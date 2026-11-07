# Ledger and beacon evidence

This directory holds the records of the Cardano Preview ledger and of the Ethereum Beacon API
that support the on-chain results of the campaign of 1 July 2026: the ledger records of the sixty
update transactions and of the bootstrap transactions, three on-chain datums, the protocol
parameters of the epochs concerned, and the beacon block headers at the slots that the 57th and
58th updates finalize and attest. All records were retrieved on 2 November 2026 and are kept as
retrieved.

## Sources

- **Cardano Preview ledger**: the public Koios API at `https://preview.koios.rest/api/v1`.
- **Ethereum mainnet beacon chain**: the Beacon API at `https://ethereum-beacon-api.publicnode.com`.

## Koios records (`koios/`)

| File | Endpoint | Retrieved (UTC) | Content |
|---|---|---|---|
| `tx_info_scripts.json` | `POST /tx_info` with the body `tx_info_request.json` | 2 November 2026, 17:30 | The ledger records of 64 transactions, 29 members each: block height, slot, epoch, block time, fee, size, inputs, outputs, minted assets and, under `plutus_contracts`, the executed script with its hash, its redeemer and the execution units charged. |
| `tx_info_request.json` | body of the `tx_info` request | 2 November 2026, 17:30 | The 64 transaction hashes under `_tx_hashes`, with `_scripts` and `_assets` set to `true`. |
| `datum_info.json` | `POST /datum_info` with the three datum hashes below under `_datum_hashes` | 2 November 2026, 20:33 | Three datum records (`datum_hash`, `creation_tx_hash`, `bytes`, `value`), each datum being 2,632 bytes long. |
| `epoch_params_1327_1345.json` | `GET /epoch_params?_epoch_no=N`, one request for each N from 1327 to 1345 | 2 November 2026, 20:34 | One object keyed by the epoch number; each value is the parameter record of that epoch (55 members, among them the protocol version, the execution limits, the fee parameters and the cost models). |
| `epoch_params_mem_change.json` | `GET /epoch_params?_epoch_no=N` for N = 1366 and N = 1367 | 2 November 2026, 20:34 | The parameter records of epoch 1366 (key `last_16_5M`) and of epoch 1367 (key `first_changed`). |

The 64 transactions of `tx_info_scripts.json` are:

- the sixty update transactions of the campaign, in blocks 4,429,953 to 4,430,582 of epoch 1345,
  between 00:16:03 and 06:28:31 UTC on 1 July 2026, every one of which executes the script with
  hash `aa3ab8dce14478286fd5a6f628e19a2a0637034942db02dcaf7e52db`;
- the bootstrap transaction of the campaign bridge,
  `6d771d429f5aeb8d0a2382999afae3b1043fe952c9ea8f7f1d886d66d6f913ec`
  (30 June 2026, 23:50:19 UTC, block 4,429,906, epoch 1344);
- the bootstrap transaction of the rehearsal with toy keys,
  `a179dcc7e869ff74c36cfce39ee37a9917b3f72cb14b6b9f8a3b71c6f97bbf34` (13 June 2026, 09:50:31 UTC);
- the bootstrap transaction and the update transaction of the rehearsal with full-size keys,
  `27c9765bcea19cb1b7def355231aa89be87a08c06272386328fec75f32e13db2` (17 June 2026, 12:49:30 UTC)
  and `90c3b3e190a452e945ff7b10cc5435e285e38da27fd8edd7f05c6464675151e8` (17 June 2026,
  12:55:42 UTC).

The three datums of `datum_info.json` are the inline datums of the outputs at the bridge address of:

- the bootstrap transaction of the campaign bridge, datum hash
  `116b3cd4ec191573b817167b9c89dc0b6d4bb1a391fafc0e3dd9ecb8de8282b0` (`finalized_slot` 14,663,680);
- the 57th update, transaction `bcae1b12…`, datum hash
  `5e8570baad195578c3a7b104a625c2e5e16657a9c87eedbd89c0900d1225540d` (`finalized_slot` 14,671,775);
- the 58th update, the boundary update, transaction `c8b296a9…`, datum hash
  `20dc4fef392675f8bcd8d4b02b00130e4d5c6e52e04ad6be984f97255ebd2867` (`finalized_slot` 14,671,808).

The transaction records give the inline datum of an output as a JSON value with a null `bytes`
member; `datum_info.json` supplies the CBOR bytes, and the BLAKE2b-256 hash of each equals the
datum hash.

The nineteen epochs of `epoch_params_1327_1345.json` extend from the epoch of the first rehearsal
(1327, 13 June 2026) to the epoch of the campaign (1345, 1 July 2026). The following values are
identical in all nineteen records: protocol version 11.0, `max_tx_ex_steps` 10,000,000,000,
`max_tx_ex_mem` 16,500,000, `max_tx_size` 16,384, `min_fee_a` 44, `min_fee_b` 155,381, `price_mem`
0.0577, `price_step` 0.0000721, `coins_per_utxo_size` 4,310, and the `PlutusV3` cost model of 350
parameters. In `epoch_params_mem_change.json` the value of `max_tx_ex_mem` is 16,500,000 at epoch
1366 and 17,500,000 at epoch 1367, which began on 23 July 2026.

`tx_info_scripts.json` is the body of the response, byte for byte. `datum_info.json` and the two
`epoch_params` files hold the responses after parsing: the members and their values are those of
the responses, the whitespace and the notation of the numbers are those of the JSON writer.

## Beacon API responses (`beacon/`)

All seven responses were retrieved on 2 November 2026 at 20:31 UTC and are the bodies of the
responses, byte for byte.

| File | Endpoint | Content |
|---|---|---|
| `genesis.json` | `GET /eth/v1/beacon/genesis` | `genesis_time` 1606824023, `genesis_validators_root` `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`, `genesis_fork_version` `0x00000000`. |
| `header_14671775.json` | `GET /eth/v1/beacon/headers/14671775` | The header of the block at slot 14,671,775, root `0xa94abfa5472621d6189b236da49d1b069f793d2d539bb0917c733aa4cd763419`. The datum of the 57th update carries this root and this slot. |
| `header_14671776.json` | `GET /eth/v1/beacon/headers/14671776` | The reply with code 404, "NOT_FOUND: beacon block at slot 14671776". Slot 14,671,776 is the first slot of epoch 458,493. |
| `headers_slot_14671776.json` | `GET /eth/v1/beacon/headers?slot=14671776` | The same reply for the query by slot. |
| `header_14671777.json` | `GET /eth/v1/beacon/headers/14671777` | The header of the block at slot 14,671,777, root `0x6f9d01c2afbb5eb24bf4da0dc3ca8d71af16dbb5390f0f3f3723fce3bfe1dcba`. Its `parent_root` is the root of the block at slot 14,671,775. |
| `header_14671808.json` | `GET /eth/v1/beacon/headers/14671808` | The header of the block at slot 14,671,808, the first slot of epoch 458,494, root `0x735b480fd3356204d0591d927d457ceaae10db78213a5cced79fcbfecf24b115`. The datum of the 58th update carries this root and this slot. |
| `header_14671872.json` | `GET /eth/v1/beacon/headers/14671872` | The header of the block at slot 14,671,872 = 1791 × 8192, the first slot of sync-committee period 1791, root `0xfca2bad46e3e5260228fec16653435a60c133c4a2bfa02cc443c7923de25f2d2`. The redeemer of the 58th update carries this root as the attested header root. |

With the genesis time above, slot 14,671,872 began at 1,606,824,023 + 14,671,872 × 12 =
1,782,886,487, that is, on 1 July 2026 at 06:14:47 UTC.

## Transaction table (`live-run-transactions.csv`)

One row for each of the sixty update transactions of the campaign in order of submission: 59
regular updates and the boundary update, which is number 58. The table was compiled on
2 November 2026 from two sources, the ledger records of `koios/tx_info_scripts.json` and the
record of the relayer, `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`.

| Columns | Source |
|---|---|
| `index`, `kind`, `tx_hash` | relayer record: position in `phases`, `kind`, `spend.tx_hash` |
| `block_height`, `absolute_slot`, `epoch_no`, `block_time_utc` | ledger record: `block_height`, `absolute_slot`, `epoch_no`, `tx_timestamp` written in UTC |
| `onchain_steps`, `onchain_mem` | ledger record: `plutus_contracts[0].input.redeemer.unit.steps` and `.mem` |
| `fee_lovelace`, `tx_size_ledger` | ledger record: `fee`, `tx_size` |
| `relayer_steps`, `relayer_mem`, `relayer_fee`, `relayer_tx_size` | relayer record: `spend.ex_units_steps`, `spend.ex_units_mem`, `spend.fee_lovelace`, `spend.tx_size_bytes` |
| `finalized_slot`, `finalized_slot_period`, `signature_period` | relayer record: `finalized_slot`, the sync-committee period of that slot (the integer quotient of the slot by 8,192), `signature_period` |
| `relayer_completed_unix`, `relayer_confirmed_utc` | relayer record: `completed_unix`, and the same instant written in UTC |
| `poll_detect_s`, `prove_s`, `submit_s`, `total_s` | relayer record: `poll_detect_seconds`, `prove_seconds`, `submit_seconds`, `total_seconds` |

In all sixty rows the execution units and the fee of the ledger record equal those of the relayer
record. The ledger reports a size of 6,675 bytes for every update transaction and the relayer
records 6,676 bytes.
