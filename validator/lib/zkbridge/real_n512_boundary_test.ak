//// Byte pins of the boundary fixture (real_n512_boundary.ak) against the ledger: the inline datum of
//// bcae1b1233134ef1493232aedf41ad45fd7cc250e9519ecd2031dcb18e3a38e2#0 (the consumed datum), and the
//// inline datum of output #0 and the spend redeemer of
//// c8b296a91ab7cf16756f3d5c169a06985544482d817a640d36917e61b1675b55 (the produced datum and the
//// redeemer). Each pin compares sha2_256 of cbor.serialise of the fixture value with sha2_256 of the
//// on-chain bytes.

use aiken/builtin
use aiken/cbor
use zkbridge/real_n512_boundary
use zkbridge/types.{Datum, Redeemer}

// The consumed datum: 2,632 on-chain bytes.
test boundary_consumed_datum_bytepin() {
  builtin.sha2_256(cbor.serialise(real_n512_boundary.real_input_datum())) == #"6113243bb8e423e347dc9e5108ad31368289522eadd6f88b58737be78705e21d"
}

// The produced datum: 2,632 on-chain bytes.
test boundary_produced_datum_bytepin() {
  builtin.sha2_256(cbor.serialise(real_n512_boundary.real_output_datum())) == #"ce1a5a39dca6f5b698a0381ac3256bbd13888303a0eff706a25688105950f476"
}

// The redeemer: 606 on-chain bytes.
test boundary_redeemer_bytepin() {
  builtin.sha2_256(cbor.serialise(real_n512_boundary.real_redeemer())) == #"25e444da676865194ad288c6a7a9e97641ad90d49d15ae3868d3918bd001fb76"
}

test boundary_redeemer_size() {
  builtin.length_of_bytearray(cbor.serialise(real_n512_boundary.real_redeemer())) == 606
}

test boundary_datum_sizes() {
  and {
    builtin.length_of_bytearray(cbor.serialise(real_n512_boundary.real_input_datum())) == 2632,
    builtin.length_of_bytearray(cbor.serialise(real_n512_boundary.real_output_datum())) == 2632,
  }
}

// The ledger's decode path: serialise, deserialise, cast, compare.
test boundary_redeemer_roundtrips() {
  let bytes = cbor.serialise(real_n512_boundary.real_redeemer())
  expect Some(decoded) = cbor.deserialise(bytes)
  expect parsed: Redeemer = decoded
  parsed == real_n512_boundary.real_redeemer()
}

test boundary_datums_roundtrip() {
  let consumed = cbor.serialise(real_n512_boundary.real_input_datum())
  let produced = cbor.serialise(real_n512_boundary.real_output_datum())
  expect Some(decoded_consumed) = cbor.deserialise(consumed)
  expect Some(decoded_produced) = cbor.deserialise(produced)
  expect parsed_consumed: Datum = decoded_consumed
  expect parsed_produced: Datum = decoded_produced
  and {
    parsed_consumed == real_n512_boundary.real_input_datum(),
    parsed_produced == real_n512_boundary.real_output_datum(),
  }
}
