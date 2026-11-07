// Package proving is the stage-2/3 entrypoint core: circuit compile, the SINGLE-PARTY
// DEMONSTRATOR trusted setup (vk → the OUTPUT dir; pk/ccs → the SCRATCH dir, which never
// leaves the machine and is destroyed at stage end), and the measured prove harness
// (median over iterations, Verify-per-iteration, public-witness determinism + goldens).
//
// Environment-agnostic by design: every path is parametric (output dir, scratch dir,
// fixture paths), so the AWS glue — where on EBS, the rsync/scp rules (ONLY the output dir
// is ever transferred), the self-stopping shutdown, the τ-destruction checklist — lives in
// the model-C runbook, not in Go. The two thin cmds (cmd/groth16_setup, cmd/groth16_prove)
// parse flags and call this package; a provisioning change never touches the core.
//
// TRUST (finding-4, assembly-design "Trusted-setup honesty"): groth16.Setup here is a
// single-party demonstrator setup, NOT an MPC. The pk embeds toxic-waste-derived material —
// whoever holds it can forge proofs that verify under the resulting vk. The vks are sound
// only under the operator's destruction of the scratch artifacts; production requires the
// MPC ceremony the thesis names.
package proving

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	gnarkwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"eth-cardano-zk-light-client/prover/circuits/common"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/witness"
)

// CircuitKind selects the Phase-A circuit.
type CircuitKind string

const (
	Regular  CircuitKind = "regular"
	Boundary CircuitKind = "boundary"
	// RealCommitteeSize is the real sync-committee size; any other n is a TOY size (logic
	// validation only — the artifacts must never be mistaken for the demonstrator's).
	RealCommitteeSize = 512
)

// ParseCircuitKind validates a -circuit flag value.
func ParseCircuitKind(value string) (CircuitKind, error) {
	switch CircuitKind(value) {
	case Regular, Boundary:
		return CircuitKind(value), nil
	}
	return "", fmt.Errorf("unknown circuit %q (want %q or %q)", value, Regular, Boundary)
}

// NewCircuit returns the empty circuit definition for compilation.
func NewCircuit(kind CircuitKind, numberOfKeys int) (frontend.Circuit, error) {
	switch kind {
	case Regular:
		return common.NewRegularCircuit(numberOfKeys), nil
	case Boundary:
		return common.NewBoundaryCircuit(numberOfKeys), nil
	}
	return nil, fmt.Errorf("unknown circuit kind %q", kind)
}

// BuildAssignment builds the real-data witness assignment via the (already validated)
// witness builder — its internal gindex-169/87 anchors re-guard on whatever machine runs this.
func BuildAssignment(kind CircuitKind, input *bootstrap.Bootstrap, numberOfKeys int) (frontend.Circuit, error) {
	switch kind {
	case Regular:
		return witness.BuildRegular(input, numberOfKeys)
	case Boundary:
		return witness.BuildBoundary(input, numberOfKeys)
	}
	return nil, fmt.Errorf("unknown circuit kind %q", kind)
}

// ArtifactPaths derives every artifact location from the two parametric directories. The
// size n is embedded in every filename so a TOY artifact can never be mistaken for the real
// (n=512) demonstrator artifact.
type ArtifactPaths struct {
	OutputDir    string // vk, proof, public witness, logs — the ONLY dir that ever leaves the machine
	ScratchDir   string // pk, ccs — τ-bearing material; never transferred; destroyed at stage end
	Kind         CircuitKind
	NumberOfKeys int
}

func (p ArtifactPaths) name(prefix, extension string) string {
	return fmt.Sprintf("%s_%s_n%d.%s", prefix, p.Kind, p.NumberOfKeys, extension)
}
func (p ArtifactPaths) VerifyingKeyPath() string {
	return filepath.Join(p.OutputDir, p.name("vk", "vk"))
}
func (p ArtifactPaths) ProofPath() string {
	return filepath.Join(p.OutputDir, p.name("proof", "proof"))
}
func (p ArtifactPaths) PublicWitnessPath() string {
	return filepath.Join(p.OutputDir, p.name("public", "json"))
}
func (p ArtifactPaths) ProvingKeyPath() string {
	return filepath.Join(p.ScratchDir, p.name("pk", "pk"))
}
func (p ArtifactPaths) ConstraintSystemPath() string {
	return filepath.Join(p.ScratchDir, p.name("ccs", "ccs"))
}

// RefuseScratchInsideGitRepository HALTs if the scratch dir (or any parent) is a git
// repository — the structural guard that τ-bearing files can never become committable, even
// by a stray `git add -A` (the scratch dir must live outside any repo tree, e.g. /scratch).
func RefuseScratchInsideGitRepository(scratchDir string) error {
	absolute, err := filepath.Abs(scratchDir)
	if err != nil {
		return err
	}
	for dir := absolute; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return fmt.Errorf("scratch dir %s is inside the git repository rooted at %s — pk/τ material must live OUTSIDE any repo tree", scratchDir, dir)
		}
		if dir == filepath.Dir(dir) {
			return nil // reached the filesystem root
		}
	}
}

// DemonstratorBanner is printed by both cmds — the finding-4 honesty, stated where it executes.
const DemonstratorBanner = `=== SINGLE-PARTY DEMONSTRATOR SETUP (NOT an MPC) ===
The proving key embeds toxic-waste-derived material: whoever holds it can forge proofs that
verify under the resulting vk. pk/ccs -> SCRATCH (never transferred; destroyed at stage end);
vk/proofs/logs -> OUTPUT (the only dir that ever leaves the machine). The vks are sound only
under the operator's destruction of the scratch artifacts; production requires the MPC
ceremony the thesis names. See docs/assembly-design.md "Trusted-setup honesty".`

// ToySizeBanner warns whenever n != RealCommitteeSize.
const ToySizeBanner = `*** TOY SIZE — NOT the demonstrator artifacts (logic validation only) ***`

// SetupResult reports the stage-2 measurements.
type SetupResult struct {
	ConstraintCount   int
	CompileSeconds    float64
	SetupSeconds      float64
	PeakRssGib        float64
	VerifyingKeyBytes int64
	ProvingKeyBytes   int64
	ConstraintBytes   int64
}

// RunSetup compiles the circuit and runs the single-party demonstrator groth16.Setup:
// vk → output dir; pk + ccs → scratch dir (persisted so prove never recompiles or re-runs
// setup). Returns the measured compile/setup wall-clock + sizes.
func RunSetup(paths ArtifactPaths) (*SetupResult, error) {
	if err := RefuseScratchInsideGitRepository(paths.ScratchDir); err != nil {
		return nil, err
	}
	circuit, err := NewCircuit(paths.Kind, paths.NumberOfKeys)
	if err != nil {
		return nil, err
	}

	compileStart := time.Now()
	constraintSystem, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	compileSeconds := time.Since(compileStart).Seconds()

	setupStart := time.Now()
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	setupSeconds := time.Since(setupStart).Seconds()

	verifyingKeyBytes, err := writeArtifact(paths.VerifyingKeyPath(), verifyingKey.WriteTo)
	if err != nil {
		return nil, fmt.Errorf("persist vk: %w", err)
	}
	provingKeyBytes, err := writeArtifact(paths.ProvingKeyPath(), provingKey.WriteRawTo)
	if err != nil {
		return nil, fmt.Errorf("persist pk (scratch): %w", err)
	}
	constraintBytes, err := writeArtifact(paths.ConstraintSystemPath(), constraintSystem.WriteTo)
	if err != nil {
		return nil, fmt.Errorf("persist ccs (scratch): %w", err)
	}

	return &SetupResult{
		ConstraintCount:   constraintSystem.GetNbConstraints(),
		CompileSeconds:    compileSeconds,
		SetupSeconds:      setupSeconds,
		PeakRssGib:        peakRssGib(),
		VerifyingKeyBytes: verifyingKeyBytes,
		ProvingKeyBytes:   provingKeyBytes,
		ConstraintBytes:   constraintBytes,
	}, nil
}

// ProveResult reports the stage-3 measurements.
type ProveResult struct {
	Iterations          int
	ProveSecondsAll     []float64
	ProveSecondsMedian  float64
	ProveSecondsMin     float64
	ProveSecondsP95     float64
	PeakRssGib          float64
	PublicInputCount    int
	ProofBytes          int64
	PublicsStableAcross bool
	ReferencePublics    []string // iteration-0's public witness (hex) — the golden-check input
}

// RunProve loads pk/ccs/vk from disk, builds the real-data witness (rebuilt EVERY iteration —
// the public-witness determinism gate), and measures groth16.Prove over `iterations` runs.
// The timer wraps groth16.Prove ONLY (which internally includes witness solving); witness
// build, NewWitness and Verify sit outside it. EVERY iteration must groth16.Verify (Groth16
// proofs are randomized — Verify is the correctness gate, there is no golden-bytes check);
// the public witness must be identical across iterations. One proof + the public witness are
// persisted to the output dir.
func RunProve(paths ArtifactPaths, bootstrapFixturePath, updateFixturePath string, iterations int) (*ProveResult, error) {
	if iterations < 1 {
		return nil, fmt.Errorf("iterations %d < 1", iterations)
	}
	input, _, err := bootstrap.LoadFromFixtures(bootstrapFixturePath, updateFixturePath)
	if err != nil {
		return nil, fmt.Errorf("load fixtures: %w", err)
	}

	constraintSystem := groth16.NewCS(ecc.BLS12_381)
	if err := readArtifact(paths.ConstraintSystemPath(), constraintSystem.ReadFrom); err != nil {
		return nil, fmt.Errorf("load ccs (scratch): %w", err)
	}
	provingKey := groth16.NewProvingKey(ecc.BLS12_381)
	if err := readArtifact(paths.ProvingKeyPath(), provingKey.UnsafeReadFrom); err != nil {
		return nil, fmt.Errorf("load pk (scratch): %w", err)
	}
	verifyingKey := groth16.NewVerifyingKey(ecc.BLS12_381)
	if err := readArtifact(paths.VerifyingKeyPath(), verifyingKey.ReadFrom); err != nil {
		return nil, fmt.Errorf("load vk: %w", err)
	}

	result := &ProveResult{Iterations: iterations, PublicsStableAcross: true}
	var referencePublics []string
	var lastProof groth16.Proof

	for iteration := 0; iteration < iterations; iteration++ {
		assignment, err := BuildAssignment(paths.Kind, input, paths.NumberOfKeys)
		if err != nil {
			return nil, fmt.Errorf("build witness (iteration %d): %w", iteration, err)
		}
		fullWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
		if err != nil {
			return nil, fmt.Errorf("witness (iteration %d): %w", iteration, err)
		}
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return nil, fmt.Errorf("public (iteration %d): %w", iteration, err)
		}
		publics := publicValuesHex(publicWitness)
		if iteration == 0 {
			referencePublics = publics
			result.ReferencePublics = publics
			result.PublicInputCount = len(publics)
		} else if strings.Join(publics, ",") != strings.Join(referencePublics, ",") {
			result.PublicsStableAcross = false
			return nil, fmt.Errorf("HALT: public witness differs between iteration 0 and %d — the witness build is non-deterministic", iteration)
		}

		proveStart := time.Now()
		proof, err := groth16.Prove(constraintSystem, provingKey, fullWitness)
		proveSeconds := time.Since(proveStart).Seconds()
		if err != nil {
			return nil, fmt.Errorf("prove (iteration %d): %w", iteration, err)
		}
		if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
			return nil, fmt.Errorf("HALT: Verify failed on iteration %d (the proof does not verify under the vk): %w", iteration, err)
		}
		result.ProveSecondsAll = append(result.ProveSecondsAll, proveSeconds)
		lastProof = proof
	}

	result.ProveSecondsMin, result.ProveSecondsMedian, result.ProveSecondsP95 = stats(result.ProveSecondsAll)
	result.PeakRssGib = peakRssGib()

	proofBytes, err := writeArtifact(paths.ProofPath(), lastProof.WriteTo)
	if err != nil {
		return nil, fmt.Errorf("persist proof: %w", err)
	}
	result.ProofBytes = proofBytes
	if err := writePublicWitnessJson(paths.PublicWitnessPath(), referencePublics); err != nil {
		return nil, fmt.Errorf("persist public witness: %w", err)
	}
	return result, nil
}

// GoldenPublicChecks spot-checks the REAL (n=512) public witness against the bootstrap
// pipeline's goldens: publics[0] = current pubkeys commitment, publics[10] = finalized slot,
// and for the boundary publics[11] = the next commitment. Returns nil at toy sizes (the
// goldens are 512-key values; toy publics are subset values by construction).
func GoldenPublicChecks(kind CircuitKind, numberOfKeys int, publics []string) error {
	if numberOfKeys != RealCommitteeSize {
		return nil
	}
	const (
		goldenCurrentCommitment = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
		goldenNextCommitment    = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
		goldenFinalizedSlot     = "c80000" // 13107200 = 0xc80000
	)
	if publics[0] != fmt.Sprintf("%064s", goldenCurrentCommitment) {
		return fmt.Errorf("HALT: publics[0] (pubkeys commitment) = %s, want golden %s", publics[0], goldenCurrentCommitment)
	}
	if strings.TrimLeft(publics[10], "0") != goldenFinalizedSlot {
		return fmt.Errorf("HALT: publics[10] (finalized slot) = %s, want 0x%s", publics[10], goldenFinalizedSlot)
	}
	if kind == Boundary {
		if publics[11] != fmt.Sprintf("%064s", goldenNextCommitment) {
			return fmt.Errorf("HALT: publics[11] (next commitment) = %s, want golden %s", publics[11], goldenNextCommitment)
		}
	}
	return nil
}

// ── small helpers ──

func writeArtifact(path string, write func(w io.Writer) (int64, error)) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	file, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	buffered := bufio.NewWriterSize(file, 1<<20)
	written, err := write(buffered)
	if err != nil {
		return 0, err
	}
	if err := buffered.Flush(); err != nil {
		return 0, err
	}
	return written, nil
}

func readArtifact(path string, read func(r io.Reader) (int64, error)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = read(bufio.NewReaderSize(file, 1<<20))
	return err
}

func publicValuesHex(publicWitness gnarkwitness.Witness) []string {
	vector := publicWitness.Vector().(fr.Vector)
	out := make([]string, len(vector))
	for i := range vector {
		out[i] = fmt.Sprintf("%064s", vector[i].Text(16))
	}
	return out
}

func writePublicWitnessJson(path string, publics []string) error {
	var builder strings.Builder
	builder.WriteString("{\n  \"public_inputs_fr_hex\": [\n")
	for i, value := range publics {
		comma := ","
		if i == len(publics)-1 {
			comma = ""
		}
		builder.WriteString(fmt.Sprintf("    %q%s\n", value, comma))
	}
	builder.WriteString("  ]\n}\n")
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func stats(values []float64) (minimum, median, p95 float64) {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	return sorted[0], sorted[len(sorted)/2], sorted[(len(sorted)*95)/100]
}

// peakRssGib reads VmHWM (the process peak resident set) from /proc — the number that
// answers "does it fit the instance". Returns 0 if unreadable (non-Linux).
func peakRssGib() float64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kib float64
				fmt.Sscanf(fields[1], "%f", &kib)
				return kib / (1 << 20)
			}
		}
	}
	return 0
}
