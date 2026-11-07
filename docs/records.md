# Records D1 to D31

Each record states one point at which an estimate or an assumption of the design stage was compared
with a measurement or with the behaviour of the implementation: what was estimated or assumed, what
was measured or found, how it was resolved, and where the evidence is. The labels D1 to D31 are the
ones used in comments and reports across this repository. Paths are relative to the repository root
and line numbers refer to the files as they are in this repository. Where a value has no stored log,
the program that prints it is named.

### D1 — Fourth Miller loop in the Groth16 verification
- Estimated: three Miller loops for the Groth16 check, with e(α, β) precomputed.
- Found: Plutus V3 has no builtin that serialises a Miller-loop result, so e(α, β) was recomputed on-chain with a fourth loop; the measured increment was 254,022,273 CPU steps against 254,006,273 for one loop in the cost model, a difference of 16,000 steps (0.0063 % of one loop).
- Resolution: the verifier computes four loops for the main equation and the cost analysis counts four. Evidence: `benchmarks/phase-1-cost-model/M1b-groth16-realistic.md:115`, `benchmarks/raw/phase-1-cost-model/M1b-raw.log:27`, `benchmarks/raw/phase-1-cost-model/M1b-raw.log:28`, `validator/lib/zkbridge/groth16.ak:205`.

### D2 — BLS verification without a Miller-loop multiplication
- Estimated: one `mulMlResult` in the BLS signature check.
- Found: `finalVerify` compares two Miller-loop results, so the check needs no multiplication; the form with the multiplication cost 2,286,038 CPU steps more (2,174,038 for the builtin, the rest evaluation overhead).
- Resolution: the verifier uses the form without multiplication. Evidence: `benchmarks/phase-1-cost-model/M2-report.md:151`, `benchmarks/raw/phase-1-cost-model/M2-raw.log:31`, `validator/lib/zkbridge/bls.ak:75`.

### D3 — Cost of the multi-scalar multiplication over the public inputs
- Estimated: 464,653,338 CPU steps for six inputs and 542,095,561 for seven.
- Measured: 465,400,878 and 542,959,691 (+0.16 %); the size argument of `G1_scalarMul` was counted in 64-bit words, not bytes, and each call carried about 136,000 steps of evaluation overhead.
- Resolution: the measured values replaced the estimates. Evidence: `benchmarks/phase-1-cost-model/M3-report.md:165`, `benchmarks/raw/phase-1-cost-model/M3-raw.log:20`, `benchmarks/raw/phase-1-cost-model/M3-raw.log:22`, `benchmarks/raw/phase-1-cost-model/M4-raw.log:20`.

### D4 — Additivity of the regular composite
- Assumed: the pairing, signature and multi-scalar sequences run together cost the sum of the separate measurements.
- Measured: 2,829,077,091 CPU steps for the composite against a sum of 2,828,917,091; the difference was 160,000 (0.0057 %).
- Resolution: the assumption was confirmed. Evidence: `benchmarks/phase-1-cost-model/M5-report.md:114`, `benchmarks/raw/phase-1-cost-model/M5-raw.log:18`.

### D5 — Additivity of the boundary composite
- Assumed: the boundary composite equals the regular composite plus one further term of the multi-scalar multiplication.
- Measured: 2,906,635,904 CPU steps against a sum of 2,906,475,904 (difference 160,000); boundary minus regular was 77,558,813, equal to the difference of the two multi-scalar measurements.
- Resolution: the assumption was confirmed. Evidence: `benchmarks/phase-1-cost-model/M6-report.md:106`, `benchmarks/phase-1-cost-model/M6-report.md:164`, `benchmarks/raw/phase-1-cost-model/M6-raw.log:18`.

### D6 — Datum size, first measurement
- Estimated: 1,580 to 1,600 B for the encoded datum.
- Measured: 1,656 B for the eight-field datum in its first shape (48-byte committee fields, verification keys without commitment).
- Resolution: superseded by D18 and D19; the deployed datum is 2,632 B. Evidence: `benchmarks/phase-1-cost-model/M7-report.md:98`, `benchmarks/raw/phase-1-cost-model/M7-raw.log:19`.

### D7 — Constraints per non-native G1 addition
- Estimated: 10,000 to 20,000 constraints per addition of two BLS12-381 G1 points inside the circuit.
- Measured (2026-05-31): 646.8 constraints per addition with `Add` and 1,253.6 with the complete formula `AddUnified`, from a linear fit over chains of additions.
- Resolution: the estimate was replaced; the committee region as a whole is counted in D13. Evidence: `benchmarks/raw/phase-2-circuit/g1-add-measure.log:25`, `benchmarks/phase-2-circuit/g1-add-constraint-cost.md:51`.

### D8 — Constraints per SHA-256 compression
- Estimated: about 30,000 constraints per compression block.
- Measured (2026-05-31): 27,627 per block; hashing a 64-byte Merkle node takes two blocks because of the padding, so one node costs about 55,000 constraints.
- Resolution: the per-block estimate was confirmed and the per-node count was doubled in the later records (D10, D14). Evidence: `benchmarks/raw/phase-2-circuit/sha256-measure.log:17`, `benchmarks/raw/phase-2-circuit/sha256-measure.log:22`.

### D9 — Encoding of the committee commitment
- Assumed: the committee is bound by a Poseidon2 commitment over its 512 keys (SEC-01); the encoding of the keys inside the circuit was open.
- Measured: 380,929 constraints with 4 field elements per key (packed limbs), 1,142,785 with 12 field elements per key and 2,566,466 with the 48-byte compressed form, which also needs an on-curve check per key.
- Resolution: the packed encoding was adopted. Evidence: `benchmarks/raw/phase-2-circuit/poseidon-commit.log:22`, `benchmarks/raw/phase-2-circuit/poseidon-commit.log:13`, `benchmarks/raw/phase-2-circuit/compressed-commit.log:10`.

### D10 — Merkleisation of the 512 keys in the boundary circuit
- Estimated: about 232,000 constraints for the binding of the successor committee (eight SHA-256 evaluations).
- Found: the binding hashes all 512 keys inside the circuit, 1,023 node hashes at about 53,426 constraints each, extrapolated from N = 4, 8 and 16 to 54.8 million; a direct compilation at N = 512 exceeded the memory of the development machine.
- Resolution: the cost was accepted for the boundary circuit and counted directly in D16. Evidence: `benchmarks/raw/phase-2-circuit/pubkeys-root-smallN.log:10`, `benchmarks/raw/phase-2-circuit/pubkeys-root-smallN.log:11`, `prover/circuits/common/pubkeysroot.go:24`.

### D11 — Decompression and validation of the keys
- Assumed: every key supplied to the boundary circuit needs a subgroup check, about 30 million constraints for 512 keys.
- Found: once the compressed bytes are bound to the SSZ root, the on-curve, sign and canonical-coordinate checks fix each point, so the subgroup check was not needed; the unit measured 3,309,584 constraints at N = 512.
- Resolution: the unit without subgroup check was adopted; the binding of the successor committee was estimated at about 58.9 million constraints: 54,786,825 for the merkleisation of the keys (D10), 3,309,584 for decompression and validation, 380,929 for the commitment (the construction of D9) and 374,514 to 375,704 for the container hash and the six-step branch, seven node hashes of two compression blocks each at the in-assembly rates of 26,751 to 26,836 per block (D14). The sum is an estimate; the direct count of the boundary circuit, 60,889,638 (D16), is authoritative. Evidence: `benchmarks/raw/phase-2-circuit/decompress-pubkey-direct512.log:13`, `benchmarks/raw/phase-2-circuit/pubkeys-root-smallN.log:11`, `benchmarks/raw/phase-2-circuit/poseidon-commit.log:22`, `benchmarks/raw/phase-2-circuit/op4-slotbind.log:14`, `benchmarks/phase-2-circuit/op3b-finalitybranch.md:77`, `prover/circuits/common/decompresspubkey.go:28`.

### D12 — Assembled binding of the successor committee
- Assumed: the SSZ bytes and the curve points of the committee come from one source inside the circuit.
- Found (2026-06-03): the hash layout reproduced the state root of a mainnet update of period 1600, and the assembled unit rejected witnesses with a forged path, with different keys on the two sides, or with an off-curve or wrong-sign coordinate; it measured 1,739,496 constraints at N = 8 and 2,652,648 at N = 16.
- Resolution: the unit became operation 6 of the boundary circuit. Evidence: `benchmarks/raw/phase-2-circuit/op6-assembled-smallN.log:7`, `benchmarks/raw/phase-2-circuit/op6-assembled-smallN.log:8`, `prover/circuits/common/op6anchor_test.go:84`, `prover/circuits/common/op6assemble_test.go:225`, `prover/circuits/common/op6assemble_test.go:302`.

### D13 — Committee region of the regular circuit
- Estimated: 5 to 10 million constraints for the sum of all 512 keys and 5 to 15 million for the conditional sum over the participants.
- Measured: 929,169 constraints at N = 512 for the commitment, the conditional sum and the participation count together, of which 380,929 for the commitment; the unconditional sum was removed when the commitment replaced it (SEC-01).
- Resolution: the estimates were replaced. Evidence: `benchmarks/raw/phase-2-circuit/committee-bind-direct512.log:14`, `benchmarks/raw/phase-2-circuit/poseidon-commit.log:22`.

### D14 — Finality branch
- Estimated: about 410,000 constraints for the finality Merkle proof (14 hashes at about 30,000 each).
- Measured (2026-06-03): 507,507 constraints for the seven-element branch walk alone and 749,039 for header reconstruction and branch together inside the assembled circuit, since each node hash takes two compression blocks (D8).
- Resolution: the estimate was replaced. Evidence: `benchmarks/raw/phase-2-circuit/op3b-finalitybranch.log:3`, `benchmarks/phase-2-circuit/op3b-finalitybranch.md:77`, `prover/circuits/common/op3b.go:31`.

### D15 — Regular circuit
- Estimated: 10 to 26 million constraints.
- Measured: 1,990,745 constraints at N = 512, with 11 public inputs.
- Resolution: the estimate was replaced; the measured count is lower by a factor of 5 to 13. Evidence: `benchmarks/raw/phase-2-circuit/stage2-setup-regular.log:10`, `benchmarks/phase-2-circuit/regular-assembly.md:8`.

### D16 — Boundary circuit
- Estimated: the regular circuit plus about 232,000 constraints.
- Measured (2026-06-14): 60,889,638 constraints at N = 512 (60,887,591 extrapolated from N = 8 and 16); the compilation took 21 minutes and 58.5 GiB of memory.
- Resolution: the estimate was replaced; the boundary circuit has about 30.6 times the constraints of the regular one. The composition of D11, about 58.9 million for the successor-committee binding plus 1,990,745 for the regular core (D15), gives about 60.84 million, within 0.1 % of this count; the composition is an estimate and the direct count is authoritative. Evidence: `benchmarks/raw/phase-2-circuit/stage1-boundary-direct512.log:7`, `benchmarks/raw/phase-2-circuit/stage1-boundary-direct512.log:4`, `benchmarks/raw/phase-2-circuit/stage1-boundary-direct512.log:17`.

### D17 — Time of the off-chain bootstrap verification
- Estimated: none.
- Measured (2026-06-10): a median of 161.85 ms and of 121.12 ms in two runs of 100 samples on the development machine; about 74 % of the time was key decompression, 23 % the two Poseidon2 commitments and 2 % the signature check.
- Resolution: recorded as the cost of the bootstrap check. Evidence: `benchmarks/raw/phase-2-circuit/bootstrap-verify-cost.log:8`, `benchmarks/raw/phase-2-circuit/bootstrap-verify-cost.log:27`, `benchmarks/phase-2-circuit/bootstrap-verify-cost.md:14`.

### D18 — Sizes with packed public inputs
- Estimated: a datum of 1,580 to 1,600 B and verification keys of about 672 B and 720 B.
- Measured (2026-06-11): a datum of 2,124 B with keys of about 912 B and 960 B, after the public inputs became 11 and 12 field elements and the committee fields became 32-byte commitments.
- Resolution: superseded by D19. Evidence: `validator/lib/zkbridge/types_test.ak:7`.

### D19 — Shape of the gnark proof and verification key
- Assumed: a proof of three group elements (192 B) and the standard Groth16 verification equation.
- Found: gnark adds one Pedersen commitment with a proof of knowledge; the proof has five elements (292 B), the keys hold 14 or 15 G1 points and 5 G2 points (1,152 B and 1,200 B), the datum is 2,632 B and the verification takes six Miller loops, 4,604,591,422 CPU steps in `aiken check`.
- Resolution: the on-chain verifier implements the extended check. Evidence: `validator/lib/zkbridge/groth16.ak:174`, `validator/lib/zkbridge/groth16.ak:187`, `validator/lib/zkbridge/groth16_test.ak:181`, `validator/lib/zkbridge/types_test.ak:91`.

### D20 — BLS verification in the validator
- Estimated: about 1.01 billion CPU steps for the signature check (sum of the builtin costs).
- Measured (2026-06-12): 1,191,465,914 steps in `aiken check` for a mainnet signature of period 1600, including the hashing of the signing root and the decompression of the three points; the complete regular validator evaluated at 5,944,631,108 steps.
- Resolution: the values were recorded; the on-chain figure is in D27. Evidence: `validator/lib/zkbridge/bls_test.ak:56`, `validator/validators/bridge.ak:337`, `boot/spend.py:43`.

### D21 — No period arithmetic in the validator
- Assumed: the validator would compare sync-committee periods to decide whether an update is a boundary.
- Found: the signature slot is not available to the validator and the finalized slot lags the period change, so a period test on the datum would reject valid boundaries; a boundary proof verifies only against the stored next committee, which signs only in its own period.
- Resolution: the validator checks that the slot advances and that the committees rotate, and leaves the period to the proof and the signature. Evidence: `validator/lib/zkbridge/validation.ak:80`, `validator/lib/zkbridge/validation.ak:90`, `validator/validators/bridge.ak:109`, `validator/validators/bridge.ak:113`.

### D22 — Bootstrap transaction on Preview
- Estimated: the locked deposit was not quantified; the ranges set before the run were 11 to 13 ADA for the deposit and 0.5 to 0.8 ADA for the fee.
- Measured (2026-06-13): deposit 12,447,280 lovelace, fee 317,085 lovelace, transaction 3,598 B, inline datum 2,632 B and byte-identical to the datum computed off-chain.
- Resolution: the values were recorded. Evidence: `boot/STAGE2_REHEARSAL.md:28`, `boot/STAGE2_REHEARSAL.md:30`, `benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log:8`.

### D23 — Trusted setup at N = 512
- Estimated: verification keys of 8 or 9 G1 points and 3 G2 points; no estimate of time or memory.
- Measured (2026-06-14): regular circuit 359.2 s and 4.11 GiB, proving key 1.37 GB; boundary circuit 11,843.8 s and 108.71 GiB, proving key 44.0 GB; verification keys of 14 or 15 G1 points and 5 G2 points.
- Resolution: the setup was run by a single party and serves as a demonstrator, not as a multi-party ceremony. Evidence: `benchmarks/raw/phase-2-circuit/stage2-setup-regular.log:13`, `benchmarks/raw/phase-2-circuit/stage2-setup-boundary.log:13`, `benchmarks/raw/phase-2-circuit/stage2-setup-boundary.log:16`.

### D24 — Proving at N = 512
- Estimated: 10 to 35 s per proof and 16 to 32 GB of memory.
- Measured (2026-06-15): regular circuit median 14.56 s and 5.52 GiB; boundary circuit median 428.46 s and 96.53 GiB; five runs each; both proofs 292 B.
- Resolution: the estimates were replaced. Evidence: `benchmarks/raw/phase-2-circuit/stage3-prove-regular.log:29`, `benchmarks/raw/phase-2-circuit/stage3-prove-regular.log:32`, `benchmarks/raw/phase-2-circuit/stage3-prove-boundary.log:35`, `benchmarks/raw/phase-2-circuit/stage3-prove-boundary.log:36`.

### D25 — Setup on the machine of the live runs
- Label for the time and memory of the setup repeated on the machine of the live runs. No separate record was written; the setup measurement is D23.

### D26 — Relayer timing per update
- Label for the per-update timing of the relayer. No separate record was written; the values are the fields `poll_detect_seconds`, `prove_seconds`, `submit_seconds` and `total_seconds` of `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`, summarised in `benchmarks/raw/phase-a-scenario/timing_stats.out`.

### D27 — Regular update on-chain
- Estimated: about 3.08 billion CPU steps (3.33 billion with the fourth Miller loop of D1).
- Measured (2026-06-17, Preview): 7,094,172,930 CPU steps, 611,176 memory units, transaction 6,676 B, fee 995,880 lovelace; 19.3 % above the evaluation of D20.
- Resolution: the estimate was replaced; the update uses 71 % of the limit of 10 billion steps per transaction. Evidence: `benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log:11`, `benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log:14`, `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json:19`.

### D28 — Cadence of the live system
- Label for the behaviour of the running system (interval between updates, regular updates skipped while a boundary proof is computed). No separate record was written; the values are the fields `completed_unix` and `skipped_regulars` of `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json` and the tables of `docs/live-run-log.md`.

### D29 — Guards pinned to fixtures in the live path
- Assumed: two guards that compare a value with a stored fixture could stay in the code path used on the live network.
- Found: both stopped the first live run, because live public inputs and live redeemers differ from the fixtures by construction.
- Resolution: the guards were removed from the live path and kept in the commands that work on the fixtures. Evidence: `prover/offchain/proving/proving.go:304`, `prover/cmd/groth16_prove/main.go:59`, `boot/spend.py:97`, `boot/spend.py:154`.

### D30 — Rotation of the signing committee in the relayer
- Assumed: the committee keys loaded at start-up were valid for every update of a run.
- Found: in the run on period 1788 the relayer stopped at its off-chain signature check before submitting the boundary update, after 31 regular updates. It had loaded the committee keys once, at start-up, and did not rotate them: at the period change its keys were those of the outgoing committee, and the keys of the incoming committee, which signs the boundary update, were not used, so the check failed. The boundary rule of the validator needed no change.
- Resolution: the relayer rotates its keys after a confirmed boundary update; the fix has a regression test on data of periods 1788 and 1789, and a rotation was accepted on-chain on 2026-07-01. Evidence: `prover/offchain/relayer/live.go:268`, `prover/offchain/relayer/relayer_rotation_test.go:108`, `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json:1158`.

### D31 — Boundary update on-chain
- Estimated: about 3.17 billion CPU steps (3.42 billion with the fourth Miller loop of D1).
- Measured (2026-07-01, Preview): 7,265,427,726 CPU steps, 655,584 memory units, transaction 6,676 B, fee 1,010,791 lovelace; 171,254,796 steps (2.4 %) above the regular update; the boundary proof took 432.0 s.
- Resolution: the estimate was replaced; the update uses 72.7 % of the step limit, and the equal transaction sizes of the two kinds correspond to a redeemer of 606 B for both. Evidence: `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json:1159`, `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json:1152`, `validator/lib/zkbridge/redeemer_seam_test.ak:27`.
