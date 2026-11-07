# Aiken Tooling Gotchas (encountered during Phase 1)

Discovered during the M1 implementation (2026-05-27).

## G1 — `bench` is a reserved module-path keyword
Aiken does not allow modules under `lib/bench/`. Use `lib/benchmarks/`
instead. The `bench` keyword is reserved for the `aiken bench` sampler
harness.

## G2 — Non-TTY `aiken check` swallows compile errors
When stdout is piped (e.g., `aiken check > out.json`), aiken emits
JSON on success but silently exits 1 with empty output on failure.
For debugging, wrap in `script -q -c "aiken check" /dev/null` to
force a PTY and see real error diagnostics.

## G3 — JSON output contains a random `seed` field
Top-level `seed` in the JSON varies per run, even when test outputs
are deterministic. To verify byte-identical output across runs, pin
with `aiken check --seed 42` (or any fixed integer). The measured
cpu/mem values are deterministic regardless of seed.

## G4 — Actual builtin name is `bls12_381_mul_miller_loop_result`
The methodology document originally said `mul_ml_result` (a thesis
abbreviation). The real Aiken builtin identifier is
`bls12_381_mul_miller_loop_result`. Source: extracted via
`strings $(which aiken) | grep -i bls12`.

## G5 — Unused `let` bindings are dead-code-eliminated (added during M1 control fix)
A binding whose name is never referenced — e.g. `let _g1 = uncompress(...)`
or `let _ = uncompress(...)` — is dropped by Aiken's optimizer, so its
(failable) builtin call is NOT evaluated and costs nothing. To force a
builtin to run while discarding its value, bind to a *referenced* name:
`let g1 = uncompress(...)` followed by `let _ = g1`. Confirm with the
measured cost or `aiken uplc decode --cbor --hex`. This mattered for the M1
control test, whose whole job is to reproduce core's `uncompress` calls.

Aiken v1.1.22 also warns on `let _ = x` ("discarded variable") and recommends
`expect _ = x` instead — the `expect` form is the documented idiom for
side-effecting evaluation that the optimizer must not elide. Functionally
equivalent for our purposes; `expect` adds one `trace` builtin (~tiny cost).

## G6 — Aiken constant-folds `bls12_381_g2_hash_to_group(const, const)`
Aiken v1.1.22 applies constant folding to `bls12_381_g2_hash_to_group` when
both arguments (message, DST) are compile-time constants — the call is
replaced at compile time with a precomputed G2 element constant in the UPLC
AST. Consequences (measured in M2 + a one-off G6 probe, since removed after
confirming the behavior):

- **Folded G2 constant USED downstream** (e.g. fed to `miller_loop`): runtime
  cost of the hash_to_group call is ZERO; `aiken export` PANICS because G2
  element constants are not supported in the flat format ("BLS12-381 G2 points
  are not supported for flat encoding", crates/uplc/src/ast.rs:166).
- **Folded G2 constant UNUSED downstream**: both the call AND the resulting
  constant are eliminated by dead-code analysis; UPLC contains zero BLS
  builtins; runtime cost ≈ baseline.

Empirically **NOT** folded in the same probe set (UPLC export OK, builtin
present in the decoded UPLC, runtime cost matches the cost-model formula):

- `bls12_381_g1_uncompress`, `bls12_381_g2_uncompress` *(failable)*
- `bls12_381_g1_scalar_mul`, `bls12_381_g1_add` *(total, not folded)*
- `sha2_256` *(total, not folded)*

So the rule is NOT a clean "failable vs total" split — `hash_to_group` is the
only builtin in this probe set that shows fold behaviour. The likely cause is
a targeted optimizer rule for it (probably because its output is a fixed-size
G2 element easy to bake in as a constant).

**Defeat (M2 barrier candidates, both work)**:
- *Runtime parameter*: `test foo(x: ByteArray via fuzz.bytearray())` — `x` is
  a fuzz input, so any chain through `x` cannot be folded. ⚠ `aiken check`
  does NOT report `execution_units` for property tests (only `iterations` and
  `counterexample` in the JSON); use `aiken bench` to get costs, or convert
  to a unit test once the runtime value is established.
- *Failable-chain*: `sha2_256(g1_compress(g1_uncompress(c)))` — anchoring on
  `g1_uncompress` (failable) prevents the optimizer from collapsing
  `compress(uncompress(.))` back to a const. UPLC retains the full chain
  including `hash_to_group`. Adds ~56 M overhead (uncompress ≈ 53 M, compress
  + sha2(48B) ≈ 3 M); subtract via a barrier-control test for clean numbers.

## G7 — `aiken check -m <name>` is a SUBSTRING match, not exact
`-m, --match-tests` matches any test whose name *contains* the string, so
`-m bench_m1` also selects `bench_m1b_groth16_realistic` (and would catch a
future `bench_m1c`, etc.). This silently changes the set of tests in the
`aiken check` JSON as the suite grows, so a determinism md5 captured over one
test set no longer reproduces under the same `-m` command later. The per-test
cpu/mem are unaffected — only the JSON's test set changes.

Confirmed in v1.1.22 (`aiken check --help`): `-e, --exact-match` ("forces test
names to match exactly", used with `--match-tests`), and `-m` accepts multiple
strings. For a stable, growth-robust determinism hash, pin the exact test set:

    aiken check -e -m bench_m1_groth16_core -m bench_m1_control_setup --seed 42

This recovered M1's original 2-test hash and M1b's original 3-test hash exactly
(3× byte-identical, 2026-05-29). **Applies from M5 onward**: capture each
benchmark's md5 with `-e` over its exact test names, or record the suite-state
at which the hash was captured. See the M1/M1b report errata.
