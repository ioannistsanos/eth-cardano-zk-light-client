#!/usr/bin/env python3
"""Timing statistics of the 60-update live run (period-1790 bridge, Cardano Preview).

Reads benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json and prints the statistics quoted in
benchmarks/phase-a/SUMMARY.md: the mean proving time and the per-update and submission times of the
59 regular phases, and the mean interval between consecutive updates over all 60 phases.

Run:  python3 benchmarks/phase-a/timing_stats.py [path-to-summary-json]
Standard library only.
"""
import json
import statistics
import sys
from pathlib import Path

DEFAULT_SUMMARY = Path(__file__).resolve().parents[1] / "raw" / "phase-a-scenario" / "tier3-1790-SUMMARY.json"


def main() -> None:
    summary_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SUMMARY
    phases = json.loads(summary_path.read_text())["phases"]
    regular_phases = [phase for phase in phases if phase["kind"] == "REGULAR"]
    boundary_phases = [phase for phase in phases if phase["kind"] == "BOUNDARY"]

    prove_seconds = [phase["prove_seconds"] for phase in regular_phases]
    submit_seconds = [phase["submit_seconds"] for phase in regular_phases]
    per_update_seconds = [phase["total_seconds"] - phase["poll_detect_seconds"] for phase in regular_phases]
    completed_unix = [phase["completed_unix"] for phase in phases]
    update_intervals = len(phases) - 1
    mean_interval_seconds = (completed_unix[-1] - completed_unix[0]) / update_intervals

    print(f"input: {summary_path.name}")
    print(f"phases: {len(phases)} (regular {len(regular_phases)}, boundary {len(boundary_phases)})")
    print(f"regular proving time, mean: {statistics.mean(prove_seconds):.3f} s"
          f" (min {min(prove_seconds):.3f}, max {max(prove_seconds):.3f}, sum {sum(prove_seconds):.2f})")
    for phase in boundary_phases:
        print(f"boundary proving time: {phase['prove_seconds']:.3f} s")
    print(f"regular per-update time (total_seconds - poll_detect_seconds), mean: {statistics.mean(per_update_seconds):.2f} s")
    print(f"regular per-update time (total_seconds - poll_detect_seconds), median: {statistics.median(per_update_seconds):.2f} s"
          f" (min {min(per_update_seconds):.1f}, max {max(per_update_seconds):.1f}, sum {sum(per_update_seconds):.2f})")
    print(f"regular submission time (submit_seconds), mean: {statistics.mean(submit_seconds):.2f} s"
          f" (median {statistics.median(submit_seconds):.1f}, min {min(submit_seconds):.1f},"
          f" max {max(submit_seconds):.1f}, sum {sum(submit_seconds):.2f})")
    print(f"mean interval between updates, (last - first completed_unix) / {update_intervals}:"
          f" {mean_interval_seconds:.2f} s ({completed_unix[-1]} - {completed_unix[0]} = {completed_unix[-1] - completed_unix[0]} s)")


if __name__ == "__main__":
    main()
