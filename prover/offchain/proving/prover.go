package proving

// Persistent in-process prover — the live relayer's proving foundation. Where RunProve loads
// pk/ccs/vk on EVERY call, LoadProver loads BOTH circuits' artifacts ONCE (resident ~45 GB) and
// Prove reuses them per phase, so the 44 GB boundary pk is loaded a single time at the relayer's
// birth. The proving itself is the SAME path as RunProve's per-iteration body (identical
// BuildAssignment + groth16.Prove + Verify + goldens) — the only difference is load-once vs
// load-per-call, so the proofs are EQUIVALENT (Verify-OK + same public witness + same 292 B shape),
// not byte-identical (Groth16 proofs are randomized).

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// Prover holds the resident artifacts for the requested circuits (the live daemon loads both).
type Prover struct {
	numberOfKeys int
	ccs          map[CircuitKind]constraint.ConstraintSystem
	pk           map[CircuitKind]groth16.ProvingKey
	vk           map[CircuitKind]groth16.VerifyingKey
}

// LoadProver loads ccs/pk/vk for the requested circuits from the same dirs RunSetup wrote (reusing
// ArtifactPaths + readArtifact), resident. With no kinds it loads BOTH (the live default); the toy
// equivalence test loads only Regular (the boundary witness is full-size-only). The 44 GB boundary
// pk load (~min) happens once here, at the relayer's birth.
func LoadProver(outputDir, scratchDir string, numberOfKeys int, kinds ...CircuitKind) (*Prover, error) {
	if len(kinds) == 0 {
		kinds = []CircuitKind{Regular, Boundary}
	}
	prover := &Prover{
		numberOfKeys: numberOfKeys,
		ccs:          map[CircuitKind]constraint.ConstraintSystem{},
		pk:           map[CircuitKind]groth16.ProvingKey{},
		vk:           map[CircuitKind]groth16.VerifyingKey{},
	}
	for _, kind := range kinds {
		paths := ArtifactPaths{OutputDir: outputDir, ScratchDir: scratchDir, Kind: kind, NumberOfKeys: numberOfKeys}
		constraintSystem := groth16.NewCS(ecc.BLS12_381)
		if err := readArtifact(paths.ConstraintSystemPath(), constraintSystem.ReadFrom); err != nil {
			return nil, fmt.Errorf("load ccs (%s): %w", kind, err)
		}
		provingKey := groth16.NewProvingKey(ecc.BLS12_381)
		if err := readArtifact(paths.ProvingKeyPath(), provingKey.UnsafeReadFrom); err != nil {
			return nil, fmt.Errorf("load pk (%s): %w", kind, err)
		}
		verifyingKey := groth16.NewVerifyingKey(ecc.BLS12_381)
		if err := readArtifact(paths.VerifyingKeyPath(), verifyingKey.ReadFrom); err != nil {
			return nil, fmt.Errorf("load vk (%s): %w", kind, err)
		}
		prover.ccs[kind], prover.pk[kind], prover.vk[kind] = constraintSystem, provingKey, verifyingKey
	}
	return prover, nil
}

// PhaseProof is one live phase's output: the redeemer-shaped proof (commitment UNCOMPRESSED 96 B) +
// the public witness + the prove timing. Feeds boot/redeemer.py (proof) + the datum (publics).
type PhaseProof struct {
	A             string // G1 48 B compressed (Ar)
	B             string // G2 96 B compressed (Bs)
	C             string // G1 48 B compressed (Krs)
	Commitment    string // G1 96 B UNCOMPRESSED X‖Y (Marshal) — the redeemer form (types.ak:26-28)
	CommitmentPok string // G1 48 B compressed
	Publics       []string
	ProveSeconds  float64
	ProofBytes    int64
	VerifyOK      bool
}

// Prove builds the real-data witness for `input`, proves with the resident pk/ccs, verifies under
// the resident vk (HALT on fail), runs the goldens, and extracts the redeemer-shaped proof. The
// timer wraps groth16.Prove ONLY (the D26 prove number) — witness build + Verify sit outside, as in
// RunProve. This is the call the daemon loop invokes per phase.
func (p *Prover) Prove(kind CircuitKind, input *bootstrap.Bootstrap) (*PhaseProof, error) {
	constraintSystem, okCcs := p.ccs[kind]
	provingKey, okPk := p.pk[kind]
	verifyingKey, okVk := p.vk[kind]
	if !okCcs || !okPk || !okVk {
		return nil, fmt.Errorf("prover not loaded for circuit %q", kind)
	}

	assignment, err := BuildAssignment(kind, input, p.numberOfKeys)
	if err != nil {
		return nil, fmt.Errorf("build witness (%s): %w", kind, err)
	}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness (%s): %w", kind, err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("public (%s): %w", kind, err)
	}
	publics := publicValuesHex(publicWitness)

	proveStart := time.Now()
	proof, err := groth16.Prove(constraintSystem, provingKey, fullWitness)
	proveSeconds := time.Since(proveStart).Seconds()
	if err != nil {
		return nil, fmt.Errorf("prove (%s): %w", kind, err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		return nil, fmt.Errorf("HALT: Verify failed (%s) — the proof does not verify under the vk: %w", kind, err)
	}

	concrete, ok := proof.(*groth16bls.Proof)
	if !ok {
		return nil, fmt.Errorf("proof is not the BLS12-381 concrete type")
	}
	if len(concrete.Commitments) != 1 {
		return nil, fmt.Errorf("expected exactly 1 commitment (D19), got %d", len(concrete.Commitments))
	}
	ar := concrete.Ar.Bytes()
	bs := concrete.Bs.Bytes()
	krs := concrete.Krs.Bytes()
	pok := concrete.CommitmentPok.Bytes()
	commitment := concrete.Commitments[0].Marshal() // uncompressed 96 B

	var sizeBuffer bytes.Buffer
	proofBytes, err := proof.WriteTo(&sizeBuffer)
	if err != nil {
		return nil, fmt.Errorf("proof size: %w", err)
	}

	return &PhaseProof{
		A:             hex.EncodeToString(ar[:]),
		B:             hex.EncodeToString(bs[:]),
		C:             hex.EncodeToString(krs[:]),
		Commitment:    hex.EncodeToString(commitment),
		CommitmentPok: hex.EncodeToString(pok[:]),
		Publics:       publics,
		ProveSeconds:  proveSeconds,
		ProofBytes:    proofBytes,
		VerifyOK:      true,
	}, nil
}
