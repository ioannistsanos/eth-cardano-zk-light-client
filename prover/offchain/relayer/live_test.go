package relayer

import "testing"

// The spend.py shell-out+parse gate (validation c): the relayer parses spend.py --emit-json's
// RELAYER_JSON line into a SpendResult. The sample carries the REAL D27 numbers (the rehearsal spend
// 90c3b3e1…: 7,094,172,930 steps / 611,176 mem / 995,880 lovelace / 6,676 B), in spend.py's json.dumps
// format — so the parse is tied to a proven-on-chain output, not an invented one. (The exec.Command
// shell-out itself is exercised on the VM live run; the parse is the fragile bit, gated here.)
func TestParseSpendJSON_D27(t *testing.T) {
	output := "── spend --submit (LIVE · Preview) ──\n" +
		"  built + signed: 90c3b3e1… (6676 B, fee 995880, ExUnits 7094172930 steps / 611176 mem)\n" +
		"── SPEND CONFIRMED — regular ──\n" +
		"  datum update  : on-chain inline datum == boot/datum.py bytes (2632 B) ✓\n" +
		`RELAYER_JSON {"tx_hash": "90c3b3e190a452e945ff7b10cc5435e285e38da27fd8edd7f05c6464675151e8", "ex_units_steps": 7094172930, "ex_units_mem": 611176, "fee_lovelace": 995880, "tx_size_bytes": 6676, "datum_confirmed": true}` + "\n"

	s, err := parseSpendJSON(output)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.TxHash != "90c3b3e190a452e945ff7b10cc5435e285e38da27fd8edd7f05c6464675151e8" {
		t.Fatalf("tx hash: %s", s.TxHash)
	}
	if s.ExUnitsSteps != 7_094_172_930 {
		t.Fatalf("steps: %d", s.ExUnitsSteps)
	}
	if s.ExUnitsMem != 611_176 {
		t.Fatalf("mem: %d", s.ExUnitsMem)
	}
	if s.FeeLovelace != 995_880 {
		t.Fatalf("fee: %d", s.FeeLovelace)
	}
	if s.TxSizeBytes != 6676 {
		t.Fatalf("size: %d", s.TxSizeBytes)
	}
	t.Logf("SPEND-PARSE GATE GREEN — RELAYER_JSON → SpendResult{tx 90c3b3e1…, %d steps / %d mem, fee %d, %d B} (the D27 numbers)",
		s.ExUnitsSteps, s.ExUnitsMem, s.FeeLovelace, s.TxSizeBytes)
}

// negative: no RELAYER_JSON line → error (a failed / garbled spend.py run must NOT silently parse).
func TestParseSpendJSON_MissingLine(t *testing.T) {
	if _, err := parseSpendJSON("some spend.py output\nno relayer json here\n"); err == nil {
		t.Fatal("want error when no RELAYER_JSON line, got nil")
	}
}
