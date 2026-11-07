//// Redeemer seam — gates 2/3: the off-chain encoder (boot/redeemer.py, PyCardano) must produce the
//// EXACT bytes Aiken's cbor.serialise does, so the live relayer's redeemer drives a successful
//// on-chain validation (the same source-of-truth discipline as genesis_datum_test.ak). The redeemer
//// value is real_n512_regular.real_redeemer() (the gate-1 real n=512 proof + real period-1600 σ).
////   gate 3 — redeemer_roundtrips: serialise → deserialise → expect Redeemer → == (the ledger's decode).
////   gate 2 — redeemer_bytepin: sha2_256 of the EXACT bytes; the pin PyCardano's gate 4 must match.

use aiken/builtin
use aiken/cbor
use zkbridge/real_n512_regular
use zkbridge/types.{Redeemer}

// gate 3 — the ledger's decode path round-trips to the same Redeemer value.
test redeemer_roundtrips() {
  let bytes = cbor.serialise(real_n512_regular.real_redeemer())
  expect Some(decoded) = cbor.deserialise(bytes)
  expect parsed: Redeemer = decoded
  parsed == real_n512_regular.real_redeemer()
}

// gate 2 — the byte-pin: sha2_256 of the EXACT redeemer bytes Aiken authors (the source of truth).
// boot/redeemer.py (PyCardano) must reproduce this pin (gate 4). The redeemer CBOR is 606 B.
test redeemer_bytepin() {
  builtin.sha2_256(cbor.serialise(real_n512_regular.real_redeemer())) == #"e9e291c5fc619e4e3520de04d8a49b2fef078c230b9d83d71d5e1c4a9082b995"
}

test redeemer_size() {
  builtin.length_of_bytearray(cbor.serialise(real_n512_regular.real_redeemer())) == 606
}
