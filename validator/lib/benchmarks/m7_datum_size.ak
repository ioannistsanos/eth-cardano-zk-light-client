//// M7 — On-chain datum CBOR SIZE measurement (Phase 1).
////
//// ⚠️ SHAPE SUPERSEDED (Phase 3, Layer 0): this file measures the PRE-Option-P /
//// pre-SEC-01 datum — 48 B committee_id (now a 32 B Poseidon commitment) and a 7/8-IC
//// vk (the Option-P keys carry 13/14 IC: 12/13 for the public layout and one for the commitment). Its 1,656 B is a faithful record of THAT shape and is
//// kept as the Phase-1 result. The canonical datum + its current size (2,632 B; D18, D19) now
//// live in lib/zkbridge/types.ak + types_test.ak.
////
//// Measures the Plutus Data CBOR byte-length of the 8-field bridge oracle datum,
//// to confirm/refute the thesis §3.1.3 estimate of ~1,580–1,600 B. This is a SIZE
//// (bytes) measurement, NOT a CPU/mem measurement — the relevant ledger
//// constraint is tx size (16,384 B; the inline datum, CIP-32, is one component).
////
//// The vk representation is the decisive variable. Plutus encodes a Data
//// ByteArray ≤64 B as one definite bytestring, but >64 B is split into 64-byte
//// chunks under an indefinite-length bytestring (5f … ff), adding per-chunk
//// header overhead. Two representations are measured:
////   (i)  OPAQUE — vk = one ByteArray (672 B regular / 720 B boundary); the
////        validator would slice_bytearray at fixed offsets to recover points.
////   (ii) STRUCTURED [LOCKED design] — vk = a record {alpha:G1, beta/gamma/delta:G2,
////        ic:[G1]} of compressed-point ByteArrays (48 B G1 / 96 B G2); the
////        validator reads each field/ic[i] directly and bls12_381_g{1,2}_uncompress-es
////        it (CIP-381 consumes points), no slice arithmetic. ~30 B larger; LOCKED.
////
//// finalized_slot is an Int (natural for the forward-only slot comparison, op 4
//// §2.1.3); its CBOR is value-dependent (3–9 B; ~5 B at realistic Electra slots).
////
//// Mock contents are SIZE-FAITHFUL stand-ins: a 48 B blob is NOT a real committee
//// key / G1 point — only the byte LENGTH drives CBOR size. The canonical
//// BLS12-381 generators (48 B G1 / 96 B G2) are reused as correctly-sized point
//// mocks.
////
//// Measured via two independent routes that must agree byte-for-byte:
////   Route 1 (authoritative): builtin.serialise_data — the on-chain Data CBOR —
////     extracted via aiken export → uplc decode → uplc eval.
////   Route 2 (independent): a from-scratch pure-Python Plutus-Data CBOR encoder
////     (no deps), cross-checked against Route 1 (md5) + a structure decode.
//// See M7-report.md, docs/records.md, docs/aiken-gotchas.md.

use aiken/builtin

// ---- Size-faithful point / field mocks (lengths are what matter) ----

// 48-byte compressed-G1 length (canonical BLS12-381 G1 generator; size-faithful
// stand-in for a committee key / vk G1 point — NOT a meaningful key value).
const g1_48: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// 96-byte compressed-G2 length (canonical BLS12-381 G2 generator; size-faithful).
const g2_96: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// 32-byte SSZ root length (finalized_header_root; mutable). Size-faithful pattern.
const root32_a: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// 32-byte genesis_validators_root (anchor). Size-faithful pattern.
const root32_b: ByteArray =
  #"4ce76c0c0a1b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"

// 4-byte fork_version (anchor); Electra fork-digest length (0x05000000 pattern).
const fork4: ByteArray = #"05000000"

// Realistic Electra-era mainnet slot (~2026); Int → CBOR minimal (5 B here).
const slot_realistic: Int = 14200000

// ---- vk representations ----

type Groth16Vk {
  alpha: ByteArray,
  // G1 48 B
  beta: ByteArray,
  // G2 96 B
  gamma: ByteArray,
  // G2 96 B
  delta: ByteArray,
  // G2 96 B
  ic: List<ByteArray>,
  // G1 48 B each (regular 7, boundary 8)
}

// vk_regular structured: 1 alpha + 7 ic = 8 G1; beta/gamma/delta = 3 G2 → 672 B raw.
fn vk_regular_struct() -> Groth16Vk {
  Groth16Vk {
    alpha: g1_48,
    beta: g2_96,
    gamma: g2_96,
    delta: g2_96,
    ic: [g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48],
  }
}

// vk_boundary structured: 1 alpha + 8 ic = 9 G1; 3 G2 → 720 B raw.
fn vk_boundary_struct() -> Groth16Vk {
  Groth16Vk {
    alpha: g1_48,
    beta: g2_96,
    gamma: g2_96,
    delta: g2_96,
    ic: [g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48],
  }
}

// vk_regular opaque: 8 G1 + 3 G2 concatenated = 672 B single blob.
fn vk_regular_opaque() -> ByteArray {
  g1_48
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g2_96)
    |> builtin.append_bytearray(g2_96)
    |> builtin.append_bytearray(g2_96)
}

// vk_boundary opaque: 9 G1 + 3 G2 concatenated = 720 B single blob.
fn vk_boundary_opaque() -> ByteArray {
  g1_48
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g1_48)
    |> builtin.append_bytearray(g2_96)
    |> builtin.append_bytearray(g2_96)
    |> builtin.append_bytearray(g2_96)
}

// ---- The 8-field datum, both representations (Constr 0, 8-element array) ----

type DatumStructured {
  finalized_header_root: ByteArray,
  finalized_slot: Int,
  current_committee_id: ByteArray,
  next_committee_id: ByteArray,
  fork_version: ByteArray,
  genesis_validators_root: ByteArray,
  vk_regular: Groth16Vk,
  vk_boundary: Groth16Vk,
}

type DatumOpaque {
  finalized_header_root: ByteArray,
  finalized_slot: Int,
  current_committee_id: ByteArray,
  next_committee_id: ByteArray,
  fork_version: ByteArray,
  genesis_validators_root: ByteArray,
  vk_regular: ByteArray,
  vk_boundary: ByteArray,
}

fn datum_structured() -> DatumStructured {
  DatumStructured {
    finalized_header_root: root32_a,
    // Bytes32, mutable
    finalized_slot: slot_realistic,
    // uint64 as Int, mutable
    current_committee_id: g1_48,
    // G1 48 B, mutable (boundary tx)
    next_committee_id: g1_48,
    // G1 48 B, mutable (boundary tx)
    fork_version: fork4,
    // Bytes4, anchor
    genesis_validators_root: root32_b,
    // Bytes32, anchor
    vk_regular: vk_regular_struct(),
    // 8 G1 + 3 G2, anchor
    vk_boundary: vk_boundary_struct(),
    // 9 G1 + 3 G2, anchor
  }
}

fn datum_opaque() -> DatumOpaque {
  DatumOpaque {
    finalized_header_root: root32_a,
    finalized_slot: slot_realistic,
    current_committee_id: g1_48,
    next_committee_id: g1_48,
    fork_version: fork4,
    genesis_validators_root: root32_b,
    vk_regular: vk_regular_opaque(),
    // 672 B opaque
    vk_boundary: vk_boundary_opaque(),
    // 720 B opaque
  }
}

// === Regression test — pins the MEASURED datum CBOR sizes (M7) ===
// STRUCTURED (locked design) = 1,656 B; OPAQUE = 1,623 B. These are the
// authoritative on-chain serialise_data byte-lengths, cross-checked byte-for-byte
// by an independent pure-Python Plutus-Data encoder (see M7-report.md / M7-raw.log).
test bench_m7_datum_size() {
  let ds: Data = datum_structured()
  let dop: Data = datum_opaque()
  expect builtin.length_of_bytearray(builtin.serialise_data(ds)) == 1656
  expect builtin.length_of_bytearray(builtin.serialise_data(dop)) == 1623
  True
}
