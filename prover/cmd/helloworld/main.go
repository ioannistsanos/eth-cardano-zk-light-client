// Command helloworld is a Phase 2a-0 TOOLING smoke test: it confirms the
// gnark Groth16 + BLS12-381 pipeline compiles, sets up, proves, and verifies
// end-to-end on this machine. It is NOT the bridge circuit — no BLS, no
// committee keys — just the canonical cubic x^3 + x + 5 == y.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit proves knowledge of secret x such that x^3 + x + 5 == y,
// where y is a public input.
type CubicCircuit struct {
	X frontend.Variable `gnark:"x"`       // secret (default visibility)
	Y frontend.Variable `gnark:",public"` // public
}

// Define declares the single constraint x^3 + x + 5 == y.
func (c *CubicCircuit) Define(api frontend.API) error {
	xCubed := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(xCubed, c.X, 5))
	return nil
}

func must(stage string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL [%s]: %v\n", stage, err)
		os.Exit(1)
	}
}

func main() {
	const curve = ecc.BLS12_381 // fixed by architecture (Cardano verifies BLS12-381)

	// 1. Compile to R1CS over the BLS12-381 scalar field.
	var circuit CubicCircuit
	constraintSystem, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit)
	must("compile", err)
	fmt.Printf("curve            : %s\n", curve)
	fmt.Printf("R1CS constraints : %d\n", constraintSystem.GetNbConstraints())

	// 2. Groth16 trusted setup (toy, in-memory; toxic waste discarded on exit).
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	must("setup", err)

	// 3. Witness: x=3 (secret), y=35 (public), since 3^3 + 3 + 5 = 35.
	assignment := CubicCircuit{X: 3, Y: 35}
	fullWitness, err := frontend.NewWitness(&assignment, curve.ScalarField())
	must("witness", err)
	publicWitness, err := fullWitness.Public()
	must("public-witness", err)

	// 4. Prove (randomized — proofs are NOT byte-identical run-to-run; expected).
	start := time.Now()
	proof, err := groth16.Prove(constraintSystem, provingKey, fullWitness)
	must("prove", err)
	proveDuration := time.Since(start)

	// 5. Verify.
	must("verify", groth16.Verify(proof, verifyingKey, publicWitness))

	fmt.Printf("prove time       : %s (informal wall-clock, not a benchmark)\n", proveDuration.Round(time.Millisecond))
	fmt.Println("PASS: Groth16/BLS12-381 proof verified end-to-end")
}
