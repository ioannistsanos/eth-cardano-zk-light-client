#!/usr/bin/env python3
"""Cross-check the six Table-1 PlutusV3 builtin cost parameters (thesis §4.2.1, Table 1)
and the two point-decompression parameters (bls12_381_G1_uncompress, bls12_381_G2_uncompress)
against (a) the cost models deployed on Cardano mainnet and Preview (Koios snapshots in
this directory) and (b) the pinned plutus cost-model files: builtinCostModelC.json at the
[53] commit, plus variants D and E at the same commit. Also prints, informationally, the
CIP-133 multi-scalar-multiplication parameters and confirms that the compiled spend validator
(validator/plutus.json, blueprint hash fec7333b…, before parameter application; the deployed instance is
this validator applied with the state-token policy id, hash aa3ab8dce14478286fd5a6f628e19a2a0637034942db02dcaf7e52db)
invokes no MSM builtin and does invoke the two decompression builtins.

Run:  python3 benchmarks/cost-validation/crosscheck.py [--ref-dir DIR] [--no-aiken]
      (--ref-dir: directory holding local copies of the reference files, named
       builtinCostModelC.json / builtinCostModelD.json / builtinCostModelE.json /
       ParamName.hs; without it they are fetched read-only from raw.githubusercontent.com
       at the pinned commit and cached under the system temp directory.)
Exit status 0 = every PASS line held; 1 = at least one FAIL.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PINNED_COMMIT = "ca8463f4c61d12e6dd64dcf994089bd6a1130b8c"  # [53] builtinCostModelC.json pin
RAW = "https://raw.githubusercontent.com/IntersectMBO/plutus/" + PINNED_COMMIT + "/"
REFS = {  # name -> (path in the plutus repo, sha256 observed 2026-09-24)
    "C": ("plutus-core/cost-model/data/builtinCostModelC.json",
          "0ab2ba6ea925aa4e2023cfc7eb13c812a58ada107d1a93a0cbe2b820c5b7351d"),
    "D": ("plutus-core/cost-model/data/builtinCostModelD.json",
          "6baad41bb1f3a9ac3fd7f952741e783fa5c9c6fb795f88dac9b7b24c452fd03f"),
    "E": ("plutus-core/cost-model/data/builtinCostModelE.json",
          "6f19d691d36dded04c2095e177d525d3c45584fb1f7a023f2d2183d8535b2e20"),
    "ParamName": ("plutus-ledger-api/src/PlutusLedgerApi/V3/ParamName.hs",
                  "920833f454c8184414d9e064b9721cd1f8a1bf845d7716cbf88a88e4f19fc0d8"),
}
LOCAL_NAME = {"C": "builtinCostModelC.json", "D": "builtinCostModelD.json",
              "E": "builtinCostModelE.json", "ParamName": "ParamName.hs"}

# The six Table-1 rows: (PlutusV3 index, ParamName constructor, JSON builtin key, cpu argument, expected)
TABLE1 = [
    (197, "Bls12_381_G1_add'cpu'arguments",                 "bls12_381_G1_add",        None,        962_335),
    (208, "Bls12_381_G1_scalarMul'cpu'arguments'intercept",  "bls12_381_G1_scalarMul",  "intercept", 76_433_006),
    (209, "Bls12_381_G1_scalarMul'cpu'arguments'slope",      "bls12_381_G1_scalarMul",  "slope",     8_868),
    (219, "Bls12_381_G2_hashToGroup'cpu'arguments'intercept","bls12_381_G2_hashToGroup","intercept", 166_917_843),
    (220, "Bls12_381_G2_hashToGroup'cpu'arguments'slope",    "bls12_381_G2_hashToGroup","slope",     4_307),
    (229, "Bls12_381_finalVerify'cpu'arguments",             "bls12_381_finalVerify",   None,        333_849_714),
    (231, "Bls12_381_millerLoop'cpu'arguments",              "bls12_381_millerLoop",    None,        254_006_273),
    (233, "Bls12_381_mulMlResult'cpu'arguments",             "bls12_381_mulMlResult",   None,        2_174_038),
]
# The two point-decompression builtins (not rows of Table 1; the validator decompresses every
# group element it reads — benchmarks/phase-1-cost-model/M9-report.md). Same tuple layout.
DECOMPRESSION = [
    (211, "Bls12_381_G1_uncompress'cpu'arguments",           "bls12_381_G1_uncompress", None,        52_948_122),
    (227, "Bls12_381_G2_uncompress'cpu'arguments",           "bls12_381_G2_uncompress", None,        74_698_472),
]
# Informational: the values an index-based read of PlutusV3 indices 311-316 gave (see the README).
MSM_INDICES = list(range(311, 317))
MSM_EXPECTED = [232_010, 32, 321_837_444, 25_087_669, 18, 617_887_431]
MSM_BUILTINS = ["bls12_381_G1_multiScalarMul", "bls12_381_G2_multiScalarMul"]
# Builtin inventory of the compiled spend validator (aiken uplc decode of validator/plutus.json
# bridge.bridge.spend, blueprint hash fec7333b…, before parameter application; the deployed instance,
# applied with the state-token policy id, hashes to aa3ab8dce14478286fd5a6f628e19a2a0637034942db02dcaf7e52db; 2026-09-24): 41 distinct.
INVENTORY_2026_09_24 = [
    "addInteger", "appendByteString", "bls12_381_G1_add", "bls12_381_G1_scalarMul",
    "bls12_381_G1_uncompress", "bls12_381_G2_hashToGroup", "bls12_381_G2_neg",
    "bls12_381_G2_uncompress", "bls12_381_finalVerify", "bls12_381_millerLoop",
    "bls12_381_mulMlResult", "byteStringToInteger", "chooseList", "consByteString",
    "constrData", "equalsByteString", "equalsData", "equalsInteger", "fstPair", "headList",
    "iData", "ifThenElse", "indexByteString", "integerToByteString", "lessThanEqualsByteString",
    "lessThanEqualsInteger", "lessThanInteger", "listData", "mkCons", "modInteger",
    "multiplyInteger", "sha2_256", "sliceByteString", "sndPair", "tailList", "unBData",
    "unConstrData", "unIData", "unListData", "unMapData", "xorByteString",
]

failures = 0


def report(ok, text):
    global failures
    if not ok:
        failures += 1
    print(("PASS  " if ok else "FAIL  ") + text)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_refs(ref_dir):
    out = {}
    cache = os.path.join(tempfile.gettempdir(), "zkbridge-cost-validation-" + PINNED_COMMIT[:8])
    for key, (path, digest) in REFS.items():
        if ref_dir:
            data = open(os.path.join(ref_dir, LOCAL_NAME[key]), "rb").read()
            src = os.path.join(ref_dir, LOCAL_NAME[key])
        else:
            os.makedirs(cache, exist_ok=True)
            local = os.path.join(cache, LOCAL_NAME[key])
            if not os.path.exists(local):
                with urllib.request.urlopen(RAW + path, timeout=60) as r:
                    open(local, "wb").write(r.read())
            data = open(local, "rb").read()
            src = RAW + path
        got = sha256(data)
        report(got == digest, "reference %-9s sha256 %s… (%s)" % (key, got[:16], src))
        out[key] = data
    return out


def param_names(hs_text):
    """Index -> constructor name of PlutusLedgerApi.V3.ParamName (comment lines skipped)."""
    block = re.search(r"data ParamName\s*=\s*(.*?)\n\s*deriving", hs_text, re.S).group(1)
    return re.findall(r"(?:^|[=|])\s*([A-Z][A-Za-z0-9_']*)", block)


def cpu_value(model, builtin, arg):
    cpu = model[builtin]["cpu"]["arguments"]
    return cpu if arg is None else cpu[arg]


def load_snapshot(name):
    d = json.load(open(os.path.join(HERE, name)))
    return d


def check_parameters(rows, names, models, snaps):
    """One PASS/FAIL line per parameter: index name, pinned C/D/E values, live mainnet/preview values."""
    for idx, cname, builtin, arg, expected in rows:
        name_ok = names[idx] == cname
        ref_vals = {k: cpu_value(models[k], builtin, arg) for k in ("C", "D", "E")}
        live_vals = {net: s["plutus_v3_cost_model"][idx] for net, s in snaps.items()}
        ok = name_ok and all(v == expected for v in ref_vals.values()) and all(v == expected for v in live_vals.values())
        label = builtin + ("" if arg is None else "." + arg)
        report(ok, "[%3d] %-38s expected %-12s C=%-12s D=%-12s E=%-12s mainnet=%-12s preview=%-12s name=%s"
               % (idx, label, f"{expected:,}", f"{ref_vals['C']:,}", f"{ref_vals['D']:,}", f"{ref_vals['E']:,}",
                  f"{live_vals['mainnet']:,}", f"{live_vals['preview']:,}", "ok" if name_ok else "MISMATCH:" + names[idx]))


def cbor_bytestring_payload(raw):
    """Unwrap the single CBOR byte string that wraps a Plutus flat program."""
    major, info = raw[0] >> 5, raw[0] & 0x1F
    assert major == 2, "compiledCode is not a CBOR byte string"
    if info < 24:
        n, off = info, 1
    elif info == 24:
        n, off = raw[1], 2
    elif info == 25:
        n, off = int.from_bytes(raw[1:3], "big"), 3
    elif info == 26:
        n, off = int.from_bytes(raw[1:5], "big"), 5
    else:
        raise ValueError("unsupported CBOR length encoding")
    return raw[off:off + n]


def validator_builtins(use_aiken):
    bp = json.load(open(os.path.join(REPO, "validator", "plutus.json")))
    v = next(x for x in bp["validators"] if x["title"] == "bridge.bridge.spend")
    flat = cbor_bytestring_payload(bytes.fromhex(v["compiledCode"]))
    print("      validator/plutus.json: %s hash %s, compiledCode %d B (flat %d B), compiler %s"
          % (v["title"], v["hash"][:16] + "…", len(v["compiledCode"]) // 2, len(flat),
             bp["preamble"]["compiler"]["version"]))
    if use_aiken and shutil.which("aiken"):
        with tempfile.NamedTemporaryFile(suffix=".flat", delete=False) as f:
            f.write(flat)
            path = f.name
        try:
            text = subprocess.run(["aiken", "uplc", "decode", path], capture_output=True,
                                  text=True, check=True).stdout
        finally:
            os.unlink(path)
        names = sorted(set(re.findall(r"\(builtin\s+([A-Za-z0-9_]+)", text)))
        return names, "aiken uplc decode (live)"
    return list(INVENTORY_2026_09_24), "recorded inventory of 2026-09-24 (aiken not run)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref-dir", default=None)
    ap.add_argument("--no-aiken", action="store_true")
    args = ap.parse_args()

    print("== Reference files (IntersectMBO/plutus @ %s) ==" % PINNED_COMMIT)
    refs = load_refs(args.ref_dir)
    models = {k: json.loads(refs[k]) for k in ("C", "D", "E")}
    names = param_names(refs["ParamName"].decode("utf-8"))
    print("      PlutusV3 ParamName constructors parsed: %d" % len(names))

    print("== Deployed cost models (Koios snapshots) ==")
    snaps = {"mainnet": load_snapshot("koios-epoch-params-mainnet.json"),
             "preview": load_snapshot("koios-epoch-params-preview.json")}
    for net, s in snaps.items():
        print("      %-7s epoch %d, protocol version %d.%d, PlutusV3 list length %d, fetched %s"
              % (net, s["epoch_no"], s["protocol_major"], s["protocol_minor"],
                 len(s["plutus_v3_cost_model"]), s["fetched_utc"]))
        report(s["protocol_major"] == 11, "%s snapshot is protocol version 11" % net)

    print("== Table-1 parameters: index, name, pinned C/D/E, live mainnet/preview ==")
    check_parameters(TABLE1, names, models, snaps)

    print("== Point-decompression parameters: index, name, pinned C/D/E, live mainnet/preview ==")
    check_parameters(DECOMPRESSION, names, models, snaps)

    print("== Informational: CIP-133 MSM parameters ==")
    for net, s in snaps.items():
        live = s["plutus_v3_cost_model"]
        vals = [live[i] for i in MSM_INDICES]
        print("      %-7s PlutusV3[311..316] = %s  (earlier-round record %s: %s)"
              % (net, vals, MSM_EXPECTED, "match" if vals == MSM_EXPECTED else "DIFFERENT"))
        # value-aligned location of the MSM block (G1 intercept, slope, memory; G2 intercept, slope, memory)
        e = models["E"]
        block = [e[b]["cpu"]["arguments"]["intercept"] for b in MSM_BUILTINS[:1]] + \
                [e[MSM_BUILTINS[0]]["cpu"]["arguments"]["slope"], e[MSM_BUILTINS[0]]["memory"]["arguments"],
                 e[MSM_BUILTINS[1]]["cpu"]["arguments"]["intercept"], e[MSM_BUILTINS[1]]["cpu"]["arguments"]["slope"],
                 e[MSM_BUILTINS[1]]["memory"]["arguments"]]
        start = next((i for i in range(len(live) - 5) if live[i:i + 6] == block), None)
        print("      %-7s MSM block by value (G1 cpu intercept/slope, G1 mem, G2 cpu intercept/slope, G2 mem) = %s at indices %s"
              % (net, block, "%d..%d" % (start, start + 5) if start is not None else "NOT FOUND"))
        if start is not None:
            print("      %-7s ParamName.hs names at %d..%d: %s" % (net, start, start + 5, names[start:start + 6]))
            print("      %-7s ParamName.hs names at 311..316: %s" % (net, names[311:317]))
    print("      note: the deployed PV-11 list carries two parameters that the fetched ParamName.hs no longer")
    print("      enumerates (live indices 251 and 297), so names read by index from ParamName.hs are exact up to")
    print("      index 250 (all Table-1 and decompression rows) and shifted by +1 / +2 beyond; the MSM block is located by value.")

    print("== Compiled spend validator (blueprint, before parameter application): builtin inventory ==")
    names_v, how = validator_builtins(not args.no_aiken)
    msm = [n for n in names_v if "multiScalarMul" in n]
    print("      %d distinct builtins via %s" % (len(names_v), how))
    print("      " + " ".join(names_v))
    report(len(names_v) == 41 and names_v == sorted(INVENTORY_2026_09_24),
           "inventory equals the recorded 41-builtin set of 2026-09-24")
    report(not msm, "no MSM builtin invoked (bls12_381_G1_multiScalarMul / G2_multiScalarMul absent)")
    report("bls12_381_G1_scalarMul" in names_v and "bls12_381_G1_add" in names_v,
           "public-input MSM realised with bls12_381_G1_scalarMul + bls12_381_G1_add")
    report("bls12_381_G1_uncompress" in names_v and "bls12_381_G2_uncompress" in names_v,
           "point decompression invoked (bls12_381_G1_uncompress + bls12_381_G2_uncompress present)")

    print("== Result: %s ==" % ("ALL PASS" if failures == 0 else "%d FAIL" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
