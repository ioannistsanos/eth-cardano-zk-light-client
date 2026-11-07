# Log of the runs on Cardano Preview

This log lists the runs of the bridge on the Cardano Preview testnet in the order in which they took
place: two rehearsals, the run on sync-committee period 1788 and the 60-update run on period 1790.
Times are in UTC. Every transaction was sent to Preview; none was sent to mainnet. The procedure the
two long runs followed is in `docs/c-runbook.md`; the records D22 to D31 referred to below are in
`docs/records.md`.

## Chronology

| Date | Event |
|---|---|
| 2026-06-13 | Rehearsal: bootstrap transaction with the verification keys of the N = 8 test circuit. Deposit, fee and sizes measured (D22). |
| 2026-06-14 | Trusted setup of both circuits at N = 512 (D23). |
| 2026-06-15 | Proving measurements at N = 512 (D24). The proving keys of this setup were destroyed afterwards. |
| 2026-06-17 | Rehearsal: bootstrap and one regular update with the N = 512 keys. Cost of the regular update measured on-chain (D27). |
| 2026-06-22 | A run across a period change was scheduled for the change to period 1787 (2026-06-26 17:01). The relayer received the plan `regular*,regular,regular`: regular updates until the period change, the boundary update, two further regular updates. |
| 2026-06-23 | Cloud region and quota were checked for a machine with 12 vCPUs and 125 GiB of memory. No resources of the earlier setup and proving runs remained. |
| 2026-06-26 to 2026-06-29 | Run on period 1788: 31 regular updates confirmed, boundary proof generated, boundary update not submitted (D29, D30). |
| 2026-07-01 | Run on period 1790: 60 updates confirmed, 57 regular, 1 boundary, 2 regular (D31). |

## 1. Rehearsal of 2026-06-13: bootstrap transaction

The bootstrap transaction was submitted with the verification keys of the N = 8 test circuit. The
shape of a verification key does not depend on N, so the sizes and the deposit are those of a
deployment. The bridge itself cannot accept an N = 512 proof and was not used further.

| Quantity | Value |
|---|---|
| Bootstrap transaction | `a179dcc7e869ff74c36cfce39ee37a9917b3f72cb14b6b9f8a3b71c6f97bbf34` |
| Bridge address | `addr_test1wpthwsstjl44spsmhqrjjv25gmeq2lj0m6w8n56phg4gm9gqk3ng7` |
| Deposit locked with the datum | 12,447,280 lovelace |
| Fee | 317,085 lovelace |
| Transaction size | 3,598 B |
| Inline datum | 2,632 B, byte-identical to the datum computed off-chain |

Source: `boot/STAGE2_REHEARSAL.md`.

## 2. Rehearsal of 2026-06-17: one regular update with the N = 512 keys

A second bridge was created with the verification keys of the setup of 2026-06-14 and received the
regular proof generated on 2026-06-15. Since the proving keys of that setup had been destroyed, this
bridge accepted that one proof and no further update.

| Quantity | Value |
|---|---|
| Bridge address | `addr_test1wzv7typ2ak2m8aew2h65gpca6aswvzm94jx73w4jv9y2djczpg542` |
| Bootstrap transaction | `27c9765bcea19cb1b7def355231aa89be87a08c06272386328fec75f32e13db2` |
| Regular update | `90c3b3e190a452e945ff7b10cc5435e285e38da27fd8edd7f05c6464675151e8` |
| CPU steps | 7,094,172,930 |
| Memory units | 611,176 |
| Fee | 995,880 lovelace |
| Transaction size | 6,676 B |

The evaluation before submission and the confirmed transaction gave the same execution units. The
evaluation with `aiken check` had given 5,944,631,108 CPU steps; the on-chain value is 19.3 % higher.
Source: `benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log`.

## 3. Run on period 1788 (2026-06-26 to 2026-06-29)

One cloud machine with 12 vCPUs and 125 GiB of memory ran the setup of both circuits, the prover and
the relayer (`docs/c-runbook.md`, step S1).

1. The setup of the boundary circuit, which takes about 3.3 hours, was interrupted when the machine, a
   preemptible instance, was reclaimed by the provider. The setup was repeated on a non-preemptible
   machine of the same size.
2. The run was moved from the change to period 1787 to the change to period 1789 (slot 14,655,488,
   2026-06-28 23:37), and a new bridge was created on period 1788 (bootstrap output `87560d56…#0`).
3. On the first updates with live data, two guards that compared live values with stored fixtures
   stopped the relayer. Both were removed from the live path (D29).
4. 31 regular updates of period 1788 were confirmed on-chain.
5. At the period change the boundary proof was generated and verified off-chain. The relayer then
   stopped at its off-chain check of the aggregate signature, before the boundary update was
   submitted, because it had not rotated its copy of the committee keys (D30). No boundary transaction
   was sent in this run.

Regular updates of this run:

| Quantity | Value |
|---|---|
| Loading of both proving keys at the start | about 16.5 min (about 42 GB) |
| Constraints | 1,990,745 |
| Witness solving | 2.7 to 2.9 s per update |
| Proving after solving | about 11.5 s per update |
| Off-chain verification of the proof | about 2.65 ms |
| On-chain | 31 updates accepted |

Boundary proof of this run (off-chain only):

| Quantity | Value |
|---|---|
| Constraints | 60,889,638 |
| Witness solving | 70.9 s |
| Proving after solving | 355.3 s |
| Off-chain verification of the proof | 3.0 ms |

The per-update records of this run were not retained. The values in the two tables above are the
ones recorded at the time of the run and have no raw file in this repository.

## 4. Run on period 1790 (2026-07-01): 60 updates

The relayer was rebuilt with the rotation of the committee keys (D30) and a new bridge was created on
period 1790.

| Quantity | Value |
|---|---|
| Bootstrap transaction | `6d771d429f5aeb8d0a2382999afae3b1043fe952c9ea8f7f1d886d66d6f913ec` (output 0 holds the bridge state) |
| Bridge address | `addr_test1wz4r4wxuu9z8s2r06kn0v28png4qvdcrf9pdkqku4al99kc8trwxs` |
| State token | policy `c52599c139b6126c5bd04c303a51a8f8d5bd1633660ddd06add30054`, name `zkbridge_state` |
| Checkpoint block root of the bootstrap | `0x5244f60b…` |

The relayer ran the plan `regular*,regular,regular` with the waiting limit for the boundary set to 8
hours (`--boundary-wait-deadline 8h`). The period change was detected about 6.3 hours after the
start; with the default limit of 6 hours the relayer would have stopped about 18 minutes before it.

| Updates | Kind | Signed by the committee of period |
|---|---|---|
| 1 to 57 | regular | 1790 |
| 58 | boundary | 1791 |
| 59 and 60 | regular | 1791 |

All 60 updates were confirmed and the relayer stopped by itself after update 60. The first update
was recorded as confirmed at 00:16:35, the boundary update at 06:25:02 and the last update at
06:29:01 (field `completed_unix`). Period 1791 began at slot 14,671,872 (06:14:47).

On-chain results:

| Quantity | Regular (59 updates, all identical) | Boundary (update 58) |
|---|---|---|
| CPU steps | 7,094,172,930 | 7,265,427,726 |
| Memory units | 611,176 | 655,584 |
| Fee | 995,880 lovelace | 1,010,791 lovelace |
| Transaction size | 6,676 B | 6,676 B |

The boundary update is transaction
`c8b296a91ab7cf16756f3d5c169a06985544482d817a640d36917e61b1675b55`. The committee that signed it
(commitment `3323b908…26e1`, period 1791) became the current committee of the datum, and the
commitment `2aed783b…16db` (period 1792) was stored as the next committee. The first regular update
is transaction `4ba8f81a370f1dd38fdacfcc07d887749486d683366227ac77d984f47a43ad42`.

Timing:

| Quantity | Value |
|---|---|
| Proving, regular (mean of 59; minimum and maximum) | 14.62 s (14.37 s and 14.91 s) |
| Proving, boundary | 432.0 s |
| Time per regular update without the wait for new finality (mean; median) | 83.3 s; 79.0 s |
| Submission and confirmation, regular (mean) | 68.6 s |
| Mean interval between consecutive updates | 379 s (22,346 s over 59 intervals) |
| Regular updates skipped | 0 |

The proving times include the witness solving. Sources:
`benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json` (one entry per update) and
`benchmarks/raw/phase-a-scenario/timing_stats.out` (the statistics, computed by
`benchmarks/phase-a/timing_stats.py`).

Values read from the relayer output at the time of the run, which was not retained as a file:

| Quantity | Regular update | Boundary update |
|---|---|---|
| Witness solving | about 2.8 s | 70.8 s |
| Proving after solving | about 11.7 s | 361.0 s |
| Off-chain verification of the proof | about 2.67 ms | 2.85 ms |
