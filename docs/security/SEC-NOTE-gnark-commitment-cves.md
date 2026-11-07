# SEC NOTE — gnark Groth16-commitment CVEs: assessed, NOT APPLICABLE (2026-07-06)

- **CVE-2024-45039** — soundness of Groth16 proofs when commitments are used; exploitable only with
  **≥ 2 commitments** in one proof.
- **CVE-2024-45040** — zero-knowledge property of commitment-carrying Groth16 proofs.
- Both fixed in **gnark v0.11.0**.

**This project is not exposed:**
- gnark pinned at **v0.13.0** (post-fix) — `prover/go.mod:6`.
- Exactly **ONE** commitment per proof, enforced by the shape assert (halts on divergence) —
  `prover/cmd/proof_to_json/main.go:62-66`.
- The challenge-based verification path (`github.com/consensys/gnark@v0.13.0/backend/groth16/bls12-381/verify.go:90-95`,
  the `"G16-BSB22"` Fiat–Shamir challenge) is the post-fix code.

**Disposition (2026-07-06):** no change to the code or to the pinned version was needed.
Corroboration: the Least Authority gnark/Linea audit uses the label "[BSB22]" for the same reference
(Belling–Soleimanian–Bégassat, IACR ePrint 2022/1072).
