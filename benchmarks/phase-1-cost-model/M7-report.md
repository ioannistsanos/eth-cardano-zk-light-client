# M7 — Datum CBOR Size (8-field bridge oracle datum)

Phase 1, measurement M7. Empirical **byte size** of the on-chain Plutus `Data`
CBOR encoding of the 8-field bridge oracle datum, to confirm/refute the thesis
§3.1.3 estimate of **~1,580–1,600 B**. This is a **size** measurement, not
CPU/mem (that's M8).

See `docs/phase1-methodology.md`, `docs/records.md`, and
`docs/aiken-gotchas.md`.

## 1. Scope

- Measures the CBOR byte-length of the datum as encoded by `serialise_data` —
  exactly the bytes that occupy the UTxO and count toward the **16,384 B tx
  size** limit. The datum is **inline** (CIP-32), so the full CBOR sits in the
  tx output.
- Field partition: **mutable** = `finalized_header_root`,
  `finalized_slot`, `current_committee_id`, `next_committee_id`; **anchor** =
  `fork_version`, `genesis_validators_root`, `vk_regular`, `vk_boundary`.
- NOT in scope: execution units / memory (M8).

## 2. Datum-representation decision (LOCKED)

The decisive variable is how `vk_regular` / `vk_boundary` are stored, because
Plutus encodes a `Data` ByteArray ≤64 B as one definite bytestring but **splits
>64 B into 64-byte chunks under an indefinite-length bytestring** (`5f … ff`),
adding per-chunk header overhead.

- **(i) OPAQUE** — vk = one ByteArray (672 B / 720 B). The validator would have
  to `slice_bytearray` at fixed offsets (which differ regular vs boundary) to
  recover each point — fragile offset arithmetic.
- **(ii) STRUCTURED — LOCKED** — vk = a record
  `{alpha: G1, beta: G2, gamma: G2, delta: G2, ic: List<G1>}` of compressed-point
  ByteArrays (48 B G1 / 96 B G2). The on-chain Groth16 verifier reads each
  field / `ic[i]` directly and `bls12_381_g{1,2}_uncompress`-es it — which is
  exactly what CIP-381 consumes (points). **No slice arithmetic.** The ~33 B
  size cost over opaque is negligible against the 16,384 B tx limit.

`finalized_slot` is an **`Int`** (natural for the forward-only slot comparison,
operation 4 §2.1.3; a ByteArray would force a conversion each check). Its CBOR is
value-dependent: 3 B (slot < 2²³) … 5 B (< 2³²) … 9 B (≥ 2⁶⁴). Measured at a
realistic Electra-era slot (14,200,000 → **5 B**). The thesis's fixed "8 B" is a
slight over-count for the slot at realistic values.

## 3. Method — two independent routes, byte-identical

Datum constructed in `validator/lib/benchmarks/m7_datum_size.ak` with
**size-faithful** mock fields (correct byte LENGTHS; a 48 B blob is **not** a
real key — only length drives CBOR). Both representations are built.

- **Route 1 (authoritative)** — Aiken `builtin.serialise_data`, i.e. the exact
  on-chain `Data` CBOR, extracted via:
  ```
  aiken export -m benchmarks/m7_datum_size -n pf_m7_struct_cbor \
    | (extract compiledCode) | aiken uplc decode --cbor --hex | aiken uplc eval
  ```
  (temporary `pub fn` entry points, removed before commit; same for `_opaque`).
- **Route 2 (independent)** — a from-scratch, dependency-free pure-Python
  Plutus-Data → CBOR encoder reproducing the same datum, implementing the Plutus
  rules: `Constr 0` → tag `121` (`d8 79`) + **indefinite** array (`9f … ff`);
  `List` → `9f … ff`; `Int` → minimal; ByteArray ≤64 definite, >64
  indefinite-chunked at 64 B. It also decodes Route 1's hex to confirm the
  structure. The full script is in `M7-raw.log`.

**Both routes produce byte-identical CBOR** (`python.hex() == aiken.hex()` for
both representations). **Determinism**: serialization is deterministic; the CBOR
hex md5 is identical ×2 (`744167cd…` structured, `ef7f4378…` opaque), and the
on-chain regression test (`bench_m7_datum_size`, asserts the 1,656 / 1,623
lengths) is byte-identical ×3 (`baca240c…`).

## 4. Per-field CBOR breakdown (STRUCTURED, locked)

| field (role) | logical | CBOR bytes | header detail |
|---|---|---|---|
| *outer* `Datum` Constr 0 | — | 4 | `d8 79 9f … ff` |
| finalized_header_root (mut) | Bytes32 | 34 | `58 20` + 32 |
| finalized_slot (mut) | Int @14.2 M | 5 | `1a` + 4 |
| current_committee_id (mut) | G1 48 B | 50 | `58 30` + 48 |
| next_committee_id (mut) | G1 48 B | 50 | `58 30` + 48 |
| fork_version (anchor) | Bytes4 | 5 | `44` + 4 |
| genesis_validators_root (anchor) | Bytes32 | 34 | `58 20` + 32 |
| **vk_regular** (anchor) | 8 G1 + 3 G2 | **712** | Constr + 4 pts + 7-ic list |
| **vk_boundary** (anchor) | 9 G1 + 3 G2 | **762** | Constr + 4 pts + 8-ic list |
| **TOTAL** | | **1,656** | |

vk internals: each **G1 (48 B) = 50** (`58 30`+48); each **G2 (96 B) = 102**
(>64 → `5f` `58 40`·64 `58 20`·32 `ff`); vk record wrapper = 4; `ic` list wrapper
= 2. ⇒ vk_regular = 4+50+3·102+(2+7·50) = **712**; vk_boundary = 4+50+3·102+(2+8·50)
= **762**.

For comparison, **OPAQUE** chunks each vk as one blob: vk_regular 672 B → **696**
(+24), vk_boundary 720 B → **745** (+25); **opaque total = 1,623 B**.

## 5. Measured total — vs thesis 1,580–1,600 B → **REFUTED**

| representation | measured | vs thesis 1,580–1,600 |
|---|---|---|
| **STRUCTURED (locked)** | **1,656 B** | **REFUTED**, +56…+76 B (+3.5–4.8 %) |
| OPAQUE (comparison) | 1,623 B | **REFUTED**, +23…+43 B (+1.4–2.7 %) |

Both representations **exceed** the thesis estimate. The thesis raw payload
(≈1,564 B = sum of logical field sizes) is correct; its claimed "**~16–36 B CBOR
overhead**" is the under-estimate. The real overhead is dominated by:

1. **vk `>64 B` 64-byte chunking** — the 672/720 B opaque blobs (or the 96 B G2
   points, structured) split into 64-byte chunks, each adding a 1–2 B header +
   the `5f`/`ff` wrappers (≈ +24–25 B per opaque vk; more, spread per-point, in
   structured).
2. **Per-field/per-point length prefixes** — every ByteArray carries a 1–2 B
   header (e.g. `58 30` for 48 B), which the structured vk pays 11/12× per vk.
3. **Indefinite-array wrappers** — Aiken's `serialise_data` uses indefinite
   `Constr`/`List` arrays (`9f … ff`, 2 B) rather than definite headers.

Partly offsetting: `finalized_slot` as an `Int` is 5 B (vs the thesis's 8 B), −3 B.

This **measured value replaces** the thesis "~1,580–1,600 B (UNKNOWN)"
placeholder: the locked (structured) datum is **1,656 B**. (No tuning — recorded
as measured. The ~4 % delta is below the >10 % threshold used for the
records; it is listed in `docs/records.md` as D6.)

## 6. Tx-size context (headroom)

The datum is one component of the tx (limit **16,384 B**):

| component | bytes |
|---|---|
| inline datum (locked, structured) | 1,656 (~10.1 % of limit) |
| redeemer: Groth16 proof 192 + BLS sig 96 + 6–7 public signals (~192–224) + CBOR | ≈ 500–560 |
| validator script | **0 in tx with reference scripts (CIP-33)** |
| tx body / witnesses / overhead | ~several hundred |

With a **reference script** (CIP-33) the compiled Groth16 verifier is not in the
spending tx, so datum + redeemer + overhead ≈ **2,200–2,500 B (~15 %)** → roughly
**13.8 KB of headroom**. The datum is **not** the binding constraint. (If the
script were inline instead of a reference input, a multi-KB verifier would tighten
this — reference scripts are recommended.)

## 7. Raw artifact

`benchmarks/raw/phase-1-cost-model/M7-raw.log` — the full datum CBOR hex (both
representations), md5 (×2), the regression-test md5 (×3), and the Route-2
encoder + cross-check output (byte-identical confirmation + per-field breakdown).
