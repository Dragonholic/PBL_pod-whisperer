# v3 pre-registration (written 2026-11-10, BEFORE any v3 data was collected or evaluated)

Status: not committed until the user confirms (instruction in the v3 prompt).
Learning data for baselines: the original 10 normal runs (data/). Allowlist and
thresholds are fixed from the 2nd-round and 2.2 data only (data/, data_e1/).
Evaluation data: data_v3/ only (collected after this file was written).

## Combinations (fixed)
| id | definition |
| --- | --- |
| K2 | R1-R5, R4 scoped to the three apps (v2 baseline) |
| K5a | K2 + R2 and R5 only for sources in {frontend, backend, db} (D1 "restrict") |
| K5b | K2 + F1 allowlist (R2, R5) + F2 (R1 policy-denied only, unknown/init identity tiered) + F3 (R5 only app->app, not port 53) |
| K6 | K5b + signatures S1-S5 |
| K6-r3 | K6 without R3 |
| K7 | K6 + C1 multistep tag (tag only, no change in alerts) |

## Settings fixed in advance
- F1 allowlist (initial, from 2.2 E3-2 samples): host->falco:8765/TCP; coredns->reserved:world:53/UDP,TCP; our apps and falco->coredns:53/UDP,TCP. Match on stable identity (k8s-app / workload label or reserved identity), not pod name.
- F2: R1 only when drop_reason_desc in {POLICY_DENIED, POLICY_DENY}; unknown/init identity (reserved:unknown, reserved:init, or identity 0/5) is counted as tier "R1u" and reported separately (not in the main alert count).
- F3: R5 only for app->app paths, port 53 excluded; DNS request counts reported as a separate metric.
- S1 kubelet: src not in {host, remote-node, kube-apiserver}, dst in {host, remote-node, kube-apiserver}, dport 10250 (10255 as option, evaluated separately).
- S2 etcd: src != kube-apiserver, dport in {2379, 2380}.
- S3 API server: src in {frontend, backend, db}, dst reserved:kube-apiserver, dport in {443, 6443}.
- S4 namespace boundary: src namespace pbl-security, dst namespace set and != pbl-security, excluding (kube-dns, 53).
- S5 metadata: dst IP 169.254.169.254. All signatures: request direction only (is_reply false), verdict ignored.
- C1 window W = 60 s (R4 or R6 alert followed by S1-S5 from the same source).
- Run-level evaluation; alert precision with label policy B; 9-second windows for the long stream; 30 random learn-5 splits (seed 20261105) plus learn-all-10.
- Success criteria (D8 proposal): normal alerts per hour of K5b <= 50% of K2; recall 1.000 kept for K6; S1-S5 false alarms on normal data = 0.

## Prediction table (user's page, section 5, copied unchanged). O = fires, - = does not
| scenario | S1 | S2 | S3 | S4 | S5 | rules responsible if signatures miss |
| --- | --- | --- | --- | --- | --- | --- |
| normal | - | - | - | - | - | no alert expected |
| fp_1 | - | - | - | - | - | no alert expected (F3 effect) |
| fp_2 | - | - | - | - | - | no alert expected (F1 effect) |
| fp_3 | - | - | - | - | - | no alert expected |
| abnormal_1 | - | - | - | - | - | R1, R2 |
| abnormal_2 | - | - | - | - | - | R4, R5 |
| abnormal_3 | O | O | O (when 443 target is the API server) | - | - | R1, R3, R4, R6 |
| k8s_1 | - | - | O | - | - | R2, R3 |
| k8s_2 | O | - | - | - | - | R1, R3, R6 |
| k8s_3 | - | - | - | O | - | R1 |
| evasion_1 | O | O | O (when 443 target is the API server) | - | - | R4 (60 s), R6 |
| evasion_2 | - | - | - | - | - | R5 |
| abnormal_4 (new) | - | - | - | - | O | R1, R2 |
Expected: signatures cover 6 of the 9 attack scenarios; abnormal_1, abnormal_2, evasion_2 stay with R1/R2/R4/R5.

## Additional predictions (AI, written before evaluating the new data)
| id | prediction |
| --- | --- |
| Q1 | K5a normal alerts/hour <= 50% of K2 |
| Q2 | K5b normal alerts/hour lies between K5a and K2 (allowlist is weaker than restriction) |
| Q3 | F2 removes the R1 false alarms of the restart and replica2 runs (R1 flagged runs: 3/5 -> 0/5) |
| Q4 | evasion_2 stays detected by R5 under F3 (10/10) |
| Q5 | K6 run recall = 1.000; S1-S5 add 0 alerts on normal data, so K6 normal alerts/hour = K5b |
| Q6 | K6-r3 run recall stays 1.000 (S1-S3 and R1 cover the admin-port scenarios) |
| Q7 | K2 already detects abnormal_4 (R1 + R2) 10/10; S5 adds explanation, not recall |
| Q8 | fp_1 stays flagged in >= 8/10 runs under K5b (app->app fast repeats are not filtered) |
| Q9 | K7 changes no alert count (tags only) |
| Q10 | the signature S1/S2/S3 detect rate is 10/10 for the scenarios marked O above |
Not testable here: attacks that use a system component as the source (no scenario); reported as a limitation.
