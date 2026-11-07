//// M9 — point-decompression cost measurement (Phase 1).
////
//// Measures the reported CPU/memory cost of one bls12_381_g1_uncompress call and of one
//// bls12_381_g2_uncompress call on the Plutus V3 CEK machine. The validator decompresses every
//// group element it reads from the datum and the redeemer (lib/zkbridge/groth16.ak,
//// lib/zkbridge/bls.ak, lib/zkbridge/points.ak), so these two builtins are part of the cost of
//// every update.
////
//// Cost model (PlutusV3 parameters 211 and 227, constant cost):
////   bls12_381_G1_uncompress = 52_948_122 CPU steps
////   bls12_381_G2_uncompress = 74_698_472 CPU steps
////
//// Each test decompresses one real point and does nothing else, so its reported cost is the
//// builtin charge plus the evaluation overhead of the test body.
//// See benchmarks/phase-1-cost-model/M9-report.md and docs/aiken-gotchas.md (G5).

use aiken/builtin

// G1 point, compressed (48 bytes): the element `alpha` of the regular verification key,
// validator/fixtures/groth16_regular_n512.json (vk.alpha).
const g1_alpha_compressed: ByteArray =
  #"aca2f634ad5259ac618d579801ebfb9955ae24051e015e1f05243ef4e521f50a69bbc0ad7abf896e9fbdd169f2984d93"

// G2 point, compressed (96 bytes): the element `beta` of the same verification key
// (vk.beta).
const g2_beta_compressed: ByteArray =
  #"a38312b234095c6b762b0d50a67398f69ffb81aed11899dd1d0b7a949b0842ab611084ca095681b60ed21b6d104dd4090870673717a3091e8829aba397ed92ea0d0c0b262a5574cfa450b1dddbf1eb8e5413c07f6949d88df8e28dee4c36ec64"

// === M9 measurement targets ===
// One uncompress call per test. `expect _ = p` references the binding so that the optimizer
// keeps the (failable) call; an unreferenced binding would be eliminated (G5).
test bench_m9_g1_uncompress() {
  let p = builtin.bls12_381_g1_uncompress(g1_alpha_compressed)
  expect _ = p
  True
}

test bench_m9_g2_uncompress() {
  let p = builtin.bls12_381_g2_uncompress(g2_beta_compressed)
  expect _ = p
  True
}
