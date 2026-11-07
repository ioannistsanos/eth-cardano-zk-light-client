# Cost-model cross-check — thesis Table 1 ↔ the deployed PlutusV3 parameters

## What this check establishes

1. **The six Table-1 cost rows (thesis §4.2.1) equal the PlutusV3 parameters deployed on
   Cardano mainnet and on the Preview testnet at protocol version 11**, read by index from the
   ledger's cost-model list: `[197]` bls12_381_G1_add = 962,335; `[208]/[209]`
   bls12_381_G1_scalarMul intercept / slope = 76,433,006 / 8,868; `[219]/[220]`
   bls12_381_G2_hashToGroup intercept / slope = 166,917,843 / 4,307; `[229]` finalVerify =
   333,849,714; `[231]` millerLoop = 254,006,273; `[233]` mulMlResult = 2,174,038. Every index
   name is cross-checked against `PlutusLedgerApi/V3/ParamName.hs`.
2. **The values are unchanged from the Chang-era file [53]** (`builtinCostModelC.json` at
   IntersectMBO/plutus commit `ca8463f4c61d12e6dd64dcf994089bd6a1130b8c`) **through cost-model
   variants D and E** at the same commit.
3. **The Preview campaign of 2026-07-01 ran under PV 11.** Koios `epoch_params` shows Preview at
   protocol 10.0 in epoch 1290 and 11.0 from epoch 1291 (epoch start 2026-05-08 00:00 UTC);
   mainnet moved 10.0 → 11.0 at epoch 644 (start 2026-07-18 21:44:51 UTC). The snapshots here
   are the latest epochs at fetch time (mainnet 657, Preview 1430), both 11.0.
4. Informationally: the CIP-133 multi-scalar-multiplication parameters are live on both networks, and the compiled
   spend validator (`validator/plutus.json`, `bridge.bridge.spend`, blueprint hash `fec7333b…`, before parameter
   application; the deployed instance is this validator applied with the state-token policy id, hash
   `aa3ab8dce14478286fd5a6f628e19a2a0637034942db02dcaf7e52db`) invokes **no MSM builtin** — its 41-builtin inventory realises the public-input MSM with `bls12_381_G1_scalarMul` + `bls12_381_G1_add`.
5. **The two point-decompression parameters** hold the same values in the pinned files C, D
   and E and on both networks: `[211]` bls12_381_G1_uncompress = 52,948,122 and `[227]`
   bls12_381_G2_uncompress = 74,698,472. They are not rows of Table 1; the validator executes
   these builtins 20 + 7 times per regular update and 21 + 7 times per boundary update
   (`benchmarks/phase-1-cost-model/M9-report.md`). With them the check covers eight builtin
   cost rows (ten parameters).

## Files

- `koios-epoch-params-mainnet.json`, `koios-epoch-params-preview.json` — raw Koios
  `epoch_params` records for the latest epoch at fetch time (`raw_record`), with the PlutusV3
  array lifted to `plutus_v3_cost_model`, plus `fetched_utc`, `tip_at_fetch`, `epoch_no`,
  `protocol_major/minor`, `max_tx_ex_steps/mem`. Fetched 2026-09-24 11:13 UTC from
  `https://api.koios.rest/api/v1/epoch_params?_epoch_no=657` and
  `https://preview.koios.rest/api/v1/epoch_params?_epoch_no=1430`.
- `crosscheck.py` — the check. Reference files (C/D/E cost models + `ParamName.hs`) are fetched
  read-only from `raw.githubusercontent.com` at the pinned commit and verified by sha256 against
  the digests observed on 2026-09-24; `--ref-dir DIR` reads local copies instead. The validator
  inventory is decoded live with `aiken uplc decode` when `aiken` is on PATH (`--no-aiken`
  falls back to the recorded 41-name inventory).

## Re-run

```
python3 benchmarks/cost-validation/crosscheck.py            # online: fetches + caches the references
python3 benchmarks/cost-validation/crosscheck.py --ref-dir DIR --no-aiken   # fully offline
```
Exit status 0 = all PASS. To refresh the snapshots, re-fetch the two Koios URLs above for the
current epoch and rewrite the JSON files with the same fields.

## Caveat on index → name lookups

The fetched `ParamName.hs` (identical at the pinned commit and on master, 2026-09-24) enumerates
358 constructors, while the deployed PV-11 list has 350 entries **and carries two parameters the
enumeration no longer lists**: live index 251 (andByteString cpu intercept, 100,181) and live
index 297 (expModInteger coefficient00, 607,153). Names read by index are therefore exact up to
index 250 — which covers all six Table-1 rows and the two decompression parameters — and
shifted by +1 (251–296) / +2 (298 onward) beyond. Consequence for the CIP-133 block: an index-based read of the
block gave `[311..316] = 232010, 32, 321837444, 25087669, 18, 617887431`; those values are confirmed on both
networks, but by name/value alignment `311`/`312` are `indexArray`'s cpu / memory constants and the
MSM block proper sits at `313..318` (G1 multiScalarMul cpu intercept 321,837,444 / slope
25,087,669 / memory 18; G2 617,887,431 / 67,302,824 / 36). The script locates the block by value.

## Run output (2026-10-04)

```
== Reference files (IntersectMBO/plutus @ ca8463f4c61d12e6dd64dcf994089bd6a1130b8c) ==
PASS  reference C         sha256 0ab2ba6ea925aa4e… (https://raw.githubusercontent.com/IntersectMBO/plutus/ca8463f4c61d12e6dd64dcf994089bd6a1130b8c/plutus-core/cost-model/data/builtinCostModelC.json)
PASS  reference D         sha256 6baad41bb1f3a9ac… (https://raw.githubusercontent.com/IntersectMBO/plutus/ca8463f4c61d12e6dd64dcf994089bd6a1130b8c/plutus-core/cost-model/data/builtinCostModelD.json)
PASS  reference E         sha256 6f19d691d36dded0… (https://raw.githubusercontent.com/IntersectMBO/plutus/ca8463f4c61d12e6dd64dcf994089bd6a1130b8c/plutus-core/cost-model/data/builtinCostModelE.json)
PASS  reference ParamName sha256 920833f454c81844… (https://raw.githubusercontent.com/IntersectMBO/plutus/ca8463f4c61d12e6dd64dcf994089bd6a1130b8c/plutus-ledger-api/src/PlutusLedgerApi/V3/ParamName.hs)
      PlutusV3 ParamName constructors parsed: 358
== Deployed cost models (Koios snapshots) ==
      mainnet epoch 657, protocol version 11.0, PlutusV3 list length 350, fetched 2026-09-24T11:13:02Z
PASS  mainnet snapshot is protocol version 11
      preview epoch 1430, protocol version 11.0, PlutusV3 list length 350, fetched 2026-09-24T11:13:02Z
PASS  preview snapshot is protocol version 11
== Table-1 parameters: index, name, pinned C/D/E, live mainnet/preview ==
PASS  [197] bls12_381_G1_add                       expected 962,335      C=962,335      D=962,335      E=962,335      mainnet=962,335      preview=962,335      name=ok
PASS  [208] bls12_381_G1_scalarMul.intercept       expected 76,433,006   C=76,433,006   D=76,433,006   E=76,433,006   mainnet=76,433,006   preview=76,433,006   name=ok
PASS  [209] bls12_381_G1_scalarMul.slope           expected 8,868        C=8,868        D=8,868        E=8,868        mainnet=8,868        preview=8,868        name=ok
PASS  [219] bls12_381_G2_hashToGroup.intercept     expected 166,917,843  C=166,917,843  D=166,917,843  E=166,917,843  mainnet=166,917,843  preview=166,917,843  name=ok
PASS  [220] bls12_381_G2_hashToGroup.slope         expected 4,307        C=4,307        D=4,307        E=4,307        mainnet=4,307        preview=4,307        name=ok
PASS  [229] bls12_381_finalVerify                  expected 333,849,714  C=333,849,714  D=333,849,714  E=333,849,714  mainnet=333,849,714  preview=333,849,714  name=ok
PASS  [231] bls12_381_millerLoop                   expected 254,006,273  C=254,006,273  D=254,006,273  E=254,006,273  mainnet=254,006,273  preview=254,006,273  name=ok
PASS  [233] bls12_381_mulMlResult                  expected 2,174,038    C=2,174,038    D=2,174,038    E=2,174,038    mainnet=2,174,038    preview=2,174,038    name=ok
== Point-decompression parameters: index, name, pinned C/D/E, live mainnet/preview ==
PASS  [211] bls12_381_G1_uncompress                expected 52,948,122   C=52,948,122   D=52,948,122   E=52,948,122   mainnet=52,948,122   preview=52,948,122   name=ok
PASS  [227] bls12_381_G2_uncompress                expected 74,698,472   C=74,698,472   D=74,698,472   E=74,698,472   mainnet=74,698,472   preview=74,698,472   name=ok
== Informational: CIP-133 MSM parameters ==
      mainnet PlutusV3[311..316] = [232010, 32, 321837444, 25087669, 18, 617887431]  (earlier-round record [232010, 32, 321837444, 25087669, 18, 617887431]: match)
      mainnet MSM block by value (G1 cpu intercept/slope, G1 mem, G2 cpu intercept/slope, G2 mem) = [321837444, 25087669, 18, 617887431, 67302824, 36] at indices 313..318
      mainnet ParamName.hs names at 313..318: ["Bls12_381_G1_multiScalarMul'memory'arguments", "Bls12_381_G2_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G2_multiScalarMul'cpu'arguments'slope", "Bls12_381_G2_multiScalarMul'memory'arguments", "InsertCoin'cpu'arguments'intercept", "InsertCoin'cpu'arguments'slope"]
      mainnet ParamName.hs names at 311..316: ["Bls12_381_G1_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G1_multiScalarMul'cpu'arguments'slope", "Bls12_381_G1_multiScalarMul'memory'arguments", "Bls12_381_G2_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G2_multiScalarMul'cpu'arguments'slope", "Bls12_381_G2_multiScalarMul'memory'arguments"]
      preview PlutusV3[311..316] = [232010, 32, 321837444, 25087669, 18, 617887431]  (earlier-round record [232010, 32, 321837444, 25087669, 18, 617887431]: match)
      preview MSM block by value (G1 cpu intercept/slope, G1 mem, G2 cpu intercept/slope, G2 mem) = [321837444, 25087669, 18, 617887431, 67302824, 36] at indices 313..318
      preview ParamName.hs names at 313..318: ["Bls12_381_G1_multiScalarMul'memory'arguments", "Bls12_381_G2_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G2_multiScalarMul'cpu'arguments'slope", "Bls12_381_G2_multiScalarMul'memory'arguments", "InsertCoin'cpu'arguments'intercept", "InsertCoin'cpu'arguments'slope"]
      preview ParamName.hs names at 311..316: ["Bls12_381_G1_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G1_multiScalarMul'cpu'arguments'slope", "Bls12_381_G1_multiScalarMul'memory'arguments", "Bls12_381_G2_multiScalarMul'cpu'arguments'intercept", "Bls12_381_G2_multiScalarMul'cpu'arguments'slope", "Bls12_381_G2_multiScalarMul'memory'arguments"]
      note: the deployed PV-11 list carries two parameters that the fetched ParamName.hs no longer
      enumerates (live indices 251 and 297), so names read by index from ParamName.hs are exact up to
      index 250 (all Table-1 and decompression rows) and shifted by +1 / +2 beyond; the MSM block is located by value.
== Compiled spend validator (blueprint, before parameter application): builtin inventory ==
      validator/plutus.json: bridge.bridge.spend hash fec7333b904ebecb…, compiledCode 2875 B (flat 2872 B), compiler v1.1.22+39d6b04
      41 distinct builtins via aiken uplc decode (live)
      addInteger appendByteString bls12_381_G1_add bls12_381_G1_scalarMul bls12_381_G1_uncompress bls12_381_G2_hashToGroup bls12_381_G2_neg bls12_381_G2_uncompress bls12_381_finalVerify bls12_381_millerLoop bls12_381_mulMlResult byteStringToInteger chooseList consByteString constrData equalsByteString equalsData equalsInteger fstPair headList iData ifThenElse indexByteString integerToByteString lessThanEqualsByteString lessThanEqualsInteger lessThanInteger listData mkCons modInteger multiplyInteger sha2_256 sliceByteString sndPair tailList unBData unConstrData unIData unListData unMapData xorByteString
PASS  inventory equals the recorded 41-builtin set of 2026-09-24
PASS  no MSM builtin invoked (bls12_381_G1_multiScalarMul / G2_multiScalarMul absent)
PASS  public-input MSM realised with bls12_381_G1_scalarMul + bls12_381_G1_add
PASS  point decompression invoked (bls12_381_G1_uncompress + bls12_381_G2_uncompress present)
== Result: ALL PASS ==
```
