//// Layer-0 gate — the REFRESHED datum CBOR size, on the SEC-01/Option-P-correct
//// shapes. Authoritative successor to m7_datum_size.ak's 1,656 B (the now-stale
//// 48 B committee_id, 7/8-IC vk shape; m7 left intact as the faithful Phase-1 record).
////
//// Size history (each measured, reported as-is):
////   - m7 (pre-Option-P / pre-SEC-01)         : 1,656 B
////   - Option-P / SEC-01, VANILLA-vk view     : 2,124 B (est. ~2,150–2,250; came in ~26 B under)
////   - D19 COMMITMENT-AUGMENTED vk (current)  : 2,632 B  ← +508 B (each vk: +1 IC + 2 commitment-key
////     G2 = +240 B raw; ×2 + CBOR chunking) — the datum re-measured after the
////     Groth16VerifyingKey gained the Pedersen commitment key. The pinned value below is the
////     serialise_data length.

use aiken/builtin
use zkbridge/types.{Datum, Groth16VerifyingKey}

// ── size-faithful mocks (only byte LENGTH drives CBOR size; NOT meaningful values) ──

// 48-byte compressed-G1 length (canonical BLS12-381 G1 generator).
const g1_48: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// 96-byte compressed-G2 length (canonical BLS12-381 G2 generator).
const g2_96: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// 32-byte SSZ root length (finalized_header_root / genesis_validators_root).
const root32: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// 32-byte Poseidon commitment length (committee commitment — was 48 B G1 in m7).
const commitment32: ByteArray =
  #"4ce76c0c0a1b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"

// 4-byte fork_version (Electra-era length).
const fork4: ByteArray = #"05000000"

// Realistic Electra-era mainnet slot (~2026); Int → minimal CBOR.
const slot_realistic: Int = 14200000

// vk_regular: 1 alpha + 12 ic = 13 G1; beta/gamma/delta = 3 G2.
fn vk_regular_mock() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: g1_48,
    beta: g2_96,
    gamma: g2_96,
    delta: g2_96,
    ic: [
      g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48,
      g1_48, g1_48, g1_48,
    ],
    // 13 IC (D19: ℓ+2 — the 12 Option-P IC + the commitment IC)
    commitment_g: g2_96,
    commitment_g_sigma_neg: g2_96,
  }
}

// vk_boundary: 1 alpha + 13 ic = 14 G1; 3 G2.
fn vk_boundary_mock() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: g1_48,
    beta: g2_96,
    gamma: g2_96,
    delta: g2_96,
    ic: [
      g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48, g1_48,
      g1_48, g1_48, g1_48, g1_48,
    ],
    // 14 IC (D19: ℓ+2 for boundary)
    commitment_g: g2_96,
    commitment_g_sigma_neg: g2_96,
  }
}

fn datum_mock() -> Datum {
  Datum {
    finalized_header_root: root32,
    finalized_slot: slot_realistic,
    current_committee_commitment: commitment32,
    next_committee_commitment: commitment32,
    fork_version: fork4,
    genesis_validators_root: root32,
    verifying_key_regular: vk_regular_mock(),
    verifying_key_boundary: vk_boundary_mock(),
  }
}

// === The refreshed datum size (Option-P / SEC-01 shape) — pinned to MEASURED ===
test datum_size_option_p() {
  let datum: Data = datum_mock()
  let size = builtin.length_of_bytearray(builtin.serialise_data(datum))
  size == 2632
}
