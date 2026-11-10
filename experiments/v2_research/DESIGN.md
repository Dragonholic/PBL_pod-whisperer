# v2 experiment design (summary)

Full version with evidence (page numbers) and rationale: Notion "2차 실험 — 실험 설계".
Paper analysis (done by a notebook AI from the PDFs, must be checked against the PDFs
before quoting): Notion "2차 실험 — 논문 분석 10편".
Status: E0-1..E0-6, E2-1, E2-2 and four fixed combinations were run on the existing 120 runs
(2026-11-05). E1-1..E1-3 (new collection) were not run. Staniford 2002 was dropped as a basis
(full text not read).

## Principle
Keep the v1 structure (12 scenarios, rules R1-R5). Change one condition at a time,
compare with v1, then evaluate the best combination.

## Experiments
E0 = re-analysis of the existing 120 runs (no cluster needed)
E1 = new collection (optional), E2 = new rule

| ID | Change | Basis | Data |
|---|---|---|---|
| E0-1 | Precision at realistic attack share (10%, 1%, 0.1%) | Axelsson 2000 | existing numbers |
| E0-2 | Evaluation unit (run vs flow) and labelling policy A/B | Larroche 2026 (preprint), Axelsson | existing |
| E0-3 | Merge duplicate alerts into incidents (2 s / 120 s windows) | Valeur 2004 | existing |
| E0-4 | Separate normal data for learning vs evaluation | Sommer & Paxson 2010, Larroche | existing |
| E0-5 | R5 sensitivity: k sigma in {2,3,4,5} x learning runs in {3,5,10} | Chandola 2009 | existing |
| E0-6 | Sensitive-port list from the official Kubernetes port table | Kubernetes docs | existing |
| E2-1 | Consecutive failed-connection rule (R6), TRW-style | Jung 2004 | existing |
| E2-2 | R4 time windows 10/60/300 s, N in {5,20} | Jung 2004 (Snort/Bro baselines), Staniford (confirm) | existing |
| E1-1 | Normal-distribution shift (extra normal runs) | CAShift 2025 | new, ~30 min (estimate) |
| E1-2 | Looser NetworkPolicy environment | Inside Job 2025 | new, needs approval, ~40 min (estimate) |
| E1-3 | Long normal run, false alarms per hour | Axelsson, Sommer | new, ~1 h |

## Evaluation rules
- Report run-level (comparable with v1), flow-level, and false alarms per hour.
- Document the labelling policy and report both policies.
- Never evaluate on data used for learning.
- Review a sample of false positives by hand.
- Mark attack-share corrections as "direction only".

## Notes
- R6 adaptation: the paper handles new destination addresses (horizontal scans); we use
  (destination, port) pairs, so the paper's 4-5 attempt figure is not guaranteed.
  With the paper's parameters (theta0=0.8, theta1=0.2, alpha=0.01, beta=0.99) the
  likelihood ratio is x4 per failure and x0.25 per success: 4 consecutive failures
  flag a scanner (our calculation).
- Numbers taken from papers (Snort 60 s / 5 IPs, Valeur 2 s / 120 s, Jung parameters)
  are starting points, not answers for this environment.

## Results (2026-11-05, existing 120 runs; code: v2_experiments.py, v2_followup.py)
Tables: experiments/v2_research/results/summary.md and followup.md. 43 settings in the main run,
13 more in the follow-up (6 of them exploratory, chosen after seeing results).

- Reproduction check: the refactored detector gives exactly the v1 numbers (80/39/0/1, 80/17/0/23).
- E0-2: alert-level precision (policy B) of v1 default is 0.547 vs run-level 0.672; R4 alone 0.047,
  R5 alone 0.012, R1 alone 0.987, R3 alone 1.000. Policy A vs B changes path recall (0.893 vs 0.987), not precision.
- E0-3: merging cuts alerts by 34% (2 s) / 60% (120 s); incident precision does NOT stay (0.547 -> 0.376 at 2 s).
- E0-4/4b: normal runs not used for learning are flagged 2.2/5 (scoped) vs 0/10 when learned on.
- E0-5: R5 false-alarm rate 0.526 / 0.419 / 0.367 for 3 / 5 / 10 learning runs (k=3); evasion_2 always detected.
- E0-6: run-level identical for all port lists; path-level recall 0.912 (v1) vs 0.324 (official table only).
- E2-1: R6 flags 30/80 attack runs (abnormal_3, k8s_2, evasion_1), 0/40 normal; first contacts until flagged 4.0 (k8s_2), 8.0 (others).
- E2-2: scoped R4, N=5: W=10 s catches evasion_1 0/10, W=60 s and 300 s 10/10 with 0 normal runs flagged.
- COMBO (learn 5 / evaluate rest): K2, K3, K4 all 0.587 false-alarm run rate; R6 does not lower it (R2/R5 dominate).

## Corrections to earlier statements
- Predicted W=60 s would still miss evasion_1 (4 probes < N=5): wrong, DNS flows add distinct pairs; it is caught.
- Predicted R6 would catch abnormal_1~3, k8s_1~3, evasion_1: wrong, only the three multi-target scans.
- Expected alert merging to keep precision: not supported at a 2 s window.
