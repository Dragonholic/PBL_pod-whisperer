# v2.2 results

## E1-1 normal-distribution shift (new normal runs, no attacks)

| combination | shift | runs | flagged (learn all 10) | flagged rate (learn 5, mean+-sd over 30 splits) | original held-out normal rate (same splits) | mean runs flagged per rule (learn 5) |
| --- | --- | --- | --- | --- | --- | --- |
| K1 v1 default: R1-R5 | later | 5 | 5/5 | 1.000+-0.000 | 1.000+-0.000 | R1:1.0, R2:1.3, R3:0.0, R4:5.0, R5:2.4 |
| K1 v1 default: R1-R5 | rounds | 5 | 5/5 | 1.000+-0.000 | 1.000+-0.000 | R2:0.4, R3:0.1, R4:5.0, R5:5.0 |
| K1 v1 default: R1-R5 | restart | 5 | 5/5 | 1.000+-0.000 | 1.000+-0.000 | R1:3.0, R2:3.0, R3:0.1, R4:5.0, R5:2.5 |
| K1 v1 default: R1-R5 | replica2 | 5 | 5/5 | 1.000+-0.000 | 1.000+-0.000 | R1:3.0, R2:3.0, R4:5.0, R5:5.0 |
| K2 R1-R5, R4 scoped | later | 5 | 3/5 | 0.693+-0.177 | 0.440+-0.320 | R1:1.0, R2:1.3, R3:0.0, R5:2.4 |
| K2 R1-R5, R4 scoped | rounds | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R2:0.4, R3:0.1, R5:5.0 |
| K2 R1-R5, R4 scoped | restart | 5 | 4/5 | 0.880+-0.098 | 0.440+-0.320 | R1:3.0, R2:3.0, R3:0.1, R5:2.5 |
| K2 R1-R5, R4 scoped | replica2 | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R1:3.0, R2:3.0, R5:5.0 |
| K3 R1,R2,R3,R5,R6 | later | 5 | 3/5 | 0.693+-0.177 | 0.440+-0.320 | R1:1.0, R2:1.3, R3:0.0, R5:2.4 |
| K3 R1,R2,R3,R5,R6 | rounds | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R2:0.4, R3:0.1, R5:5.0 |
| K3 R1,R2,R3,R5,R6 | restart | 5 | 4/5 | 0.880+-0.098 | 0.440+-0.320 | R1:3.0, R2:3.0, R3:0.1, R5:2.5 |
| K3 R1,R2,R3,R5,R6 | replica2 | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R1:3.0, R2:3.0, R5:5.0 |
| K4 R1-R6, R4 and R6 scoped | later | 5 | 3/5 | 0.693+-0.177 | 0.440+-0.320 | R1:1.0, R2:1.3, R3:0.0, R5:2.4 |
| K4 R1-R6, R4 and R6 scoped | rounds | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R2:0.4, R3:0.1, R5:5.0 |
| K4 R1-R6, R4 and R6 scoped | restart | 5 | 4/5 | 0.880+-0.098 | 0.440+-0.320 | R1:3.0, R2:3.0, R3:0.1, R5:2.5 |
| K4 R1-R6, R4 and R6 scoped | replica2 | 5 | 5/5 | 1.000+-0.000 | 0.440+-0.320 | R1:3.0, R2:3.0, R5:5.0 |

## E1-3 long normal run: false alarms per hour (9-second windows, matching the original run length)

| combination | hours | 9-second segments | alerts/hour (learn all 10) | segments flagged (learn all 10) | alerts/hour (learn 5, mean+-sd) | segments flagged rate (learn 5) | segments flagged by rule (learn all 10) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K1 v1 default: R1-R5 | 1.01 | 403 | 1505 | 402/403 | 1662+-218 | 0.998+-0.000 | R1:19, R2:36, R4:402, R5:47 |
| K2 R1-R5, R4 scoped | 1.01 | 403 | 311 | 78/403 | 468+-218 | 0.374+-0.178 | R1:19, R2:36, R5:47 |
| K3 R1,R2,R3,R5,R6 | 1.01 | 403 | 311 | 78/403 | 468+-218 | 0.374+-0.178 | R1:19, R2:36, R5:47 |
| K4 R1-R6, R4 and R6 scoped | 1.01 | 403 | 311 | 78/403 | 468+-218 | 0.374+-0.178 | R1:19, R2:36, R5:47 |

## E3-1 paired t-test over the 30 learn/evaluate splits

| pair (false-alarm run rate over 30 splits) | mean difference | paired t-test |
| --- | --- | --- |
| K1 vs K2 | +0.385 | t=21.56, df=29, p=2.1e-19 |
| K2 vs K3 | +0.000 | identical in every split (no test possible) |
| K2 vs K4 | +0.000 | identical in every split (no test possible) |
| K3 vs K4 | +0.000 | identical in every split (no test possible) |

## E3-1b shifted normal vs original held-out normal

| shift (K2 R1-R5, R4 scoped, learn 5) | flagged rate | original held-out rate | Fisher exact (pooled over splits, rough guide only) |
| --- | --- | --- | --- |
| later | 0.693 | 0.440 | p=1.5e-05 |
| rounds | 1.000 | 0.440 | p=6.9e-33 |
| restart | 0.880 | 0.440 | p=3.5e-16 |
| replica2 | 1.000 | 0.440 | p=6.9e-33 |

## E3-2 false alarms by scenario and rule (K2, learn split 1)

| normal scenario | rule | alerts (first split, K2) |
| --- | --- | --- |
| fp_1 | R2 | 20 |
| fp_1 | R5 | 95 |
| fp_2 | R1 | 1 |
| fp_2 | R2 | 13 |
| fp_2 | R5 | 2 |
| fp_3 | R5 | 1 |
| normal | R5 | 1 |

Review sample (first two alerts per scenario and rule): e3_2_review_sample.csv

## E3-2b false alarms by alert source (K2, all 30 splits)

| rule | alert source | alerts (K2, 30 splits) | share of the rule's alerts |
| --- | --- | --- | --- |
| R1 | our apps (frontend/backend/db) | 30 | 1.000 |
| R2 | our apps (frontend/backend/db) | 30 | 0.026 |
| R2 | system components (host, coredns, falco, apiserver, ...) | 1120 | 0.974 |
| R3 | system components (host, coredns, falco, apiserver, ...) | 18 | 1.000 |
| R5 | our apps (frontend/backend/db) | 927 | 0.297 |
| R5 | system components (host, coredns, falco, apiserver, ...) | 2192 | 0.703 |
