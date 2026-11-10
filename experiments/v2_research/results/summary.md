# v2 results (existing 120 runs)

## Reference (v1, recomputed)

| setting | TP | FP | FN | TN | precision | recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 default | 80 | 39 | 0 | 1 | 0.672 | 1.000 | 0.804 |
| v1 R4 scoped | 80 | 17 | 0 | 23 | 0.825 | 1.000 | 0.904 |

## E0-1 precision at a realistic attack share (direction only, unit = run)

| setting | TPR | FPR | attack share | precision |
| --- | --- | --- | --- | --- |
| default | 1.000 | 0.975 | 0.6667 | 0.6723 |
| default | 1.000 | 0.975 | 0.1000 | 0.1023 |
| default | 1.000 | 0.975 | 0.0100 | 0.0103 |
| default | 1.000 | 0.975 | 0.0010 | 0.0010 |
| R4 scoped / N=10 | 1.000 | 0.425 | 0.6667 | 0.8247 |
| R4 scoped / N=10 | 1.000 | 0.425 | 0.1000 | 0.2073 |
| R4 scoped / N=10 | 1.000 | 0.425 | 0.0100 | 0.0232 |
| R4 scoped / N=10 | 1.000 | 0.425 | 0.0010 | 0.0023 |

## E0-2 evaluation unit and label policy (A: all frontend flows in attack runs, B: only flows aimed at the scenario targets)

| rules | label policy | run precision | run recall | alert TP | alert FP | alert precision | malicious paths covered | malicious paths | path recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1-R5 (v1 default) | A | 0.672 | 1.000 | 5244 | 4245 | 0.553 | 720 | 806 | 0.893 |
| R1-R5 (v1 default) | B | 0.672 | 1.000 | 5195 | 4294 | 0.547 | 671 | 680 | 0.987 |
| R1-R5, R4 scoped | A | 0.825 | 1.000 | 5244 | 1385 | 0.791 | 720 | 806 | 0.893 |
| R1-R5, R4 scoped | B | 0.825 | 1.000 | 5195 | 1434 | 0.784 | 671 | 680 | 0.987 |
| R1 alone | A | 0.986 | 0.887 | 1748 | 23 | 0.987 | 660 | 806 | 0.819 |
| R1 alone | B | 0.986 | 0.887 | 1748 | 23 | 0.987 | 660 | 680 | 0.971 |
| R2 alone | A | 0.910 | 0.887 | 1748 | 605 | 0.743 | 660 | 806 | 0.819 |
| R2 alone | B | 0.910 | 0.887 | 1748 | 605 | 0.743 | 660 | 680 | 0.971 |
| R3 alone | A | 1.000 | 0.500 | 1548 | 0 | 1.000 | 620 | 806 | 0.769 |
| R3 alone | B | 1.000 | 0.500 | 1548 | 0 | 1.000 | 620 | 680 | 0.912 |
| R4 alone | A | 0.672 | 0.975 | 156 | 2860 | 0.052 | 146 | 806 | 0.181 |
| R4 alone | B | 0.672 | 0.975 | 141 | 2875 | 0.047 | 131 | 680 | 0.193 |
| R5 alone | A | 0.845 | 0.750 | 44 | 757 | 0.055 | 44 | 806 | 0.055 |
| R5 alone | B | 0.845 | 0.750 | 10 | 791 | 0.012 | 10 | 680 | 0.015 |

## E0-3 alert aggregation (same rule, source, destination, port merged within the window)

| rules | merge window (s) | alerts | incidents | reduction | incident precision (policy B) |
| --- | --- | --- | --- | --- | --- |
| R1-R5 (v1 default) | 0 | 9489 | 9489 | 0.0000 | 0.547 |
| R1-R5 (v1 default) | 2 | 9489 | 6219 | 0.3446 | 0.376 |
| R1-R5 (v1 default) | 120 | 9489 | 3759 | 0.6039 | 0.554 |
| R1-R5, R4 scoped | 0 | 6629 | 6629 | 0.0000 | 0.784 |
| R1-R5, R4 scoped | 2 | 6629 | 3383 | 0.4897 | 0.692 |
| R1-R5, R4 scoped | 120 | 6629 | 3113 | 0.5304 | 0.668 |

## E0-4 learning vs evaluation split (normal runs flagged, any rule)

| rules | protocol | flagged normal runs | false-alarm run rate | flagged by R2 | flagged by R5 | flagged by R4 |
| --- | --- | --- | --- | --- | --- | --- |
| R1-R5 (v1 default) | learn = evaluate (v1 way) | 39/40 | 0.975 | - | - | - |
| R1-R5 (v1 default) | learn 5 / evaluate 5 + fp (mean over 30 splits) | 34.0+-0.0/35 | 0.971+-0.000 | R2 9.3 | R5 15.0 | R4 33.0 |
| R1-R5, R4 scoped | learn = evaluate (v1 way) | 17/40 | 0.425 | - | - | - |
| R1-R5, R4 scoped | learn 5 / evaluate 5 + fp (mean over 30 splits) | 20.5+-3.4/35 | 0.587+-0.096 | R2 9.3 | R5 15.0 | R4 0.0 |

## E0-5 request-count rule (R5 only): k sigma x learning runs (20 random subsets for n<10)

| learning runs | k sigma | false-alarm set | R5 false-alarm run rate | R5 detects evasion_2 | R5 detects any attack |
| --- | --- | --- | --- | --- | --- |
| 3 | 2 | fp_1-3 + held-out normal | 0.573+-0.134 | 1.00+-0.00 | 0.844+-0.059 |
| 3 | 3 | fp_1-3 + held-out normal | 0.526+-0.159 | 1.00+-0.00 | 0.828+-0.062 |
| 3 | 4 | fp_1-3 + held-out normal | 0.491+-0.155 | 1.00+-0.00 | 0.814+-0.062 |
| 3 | 5 | fp_1-3 + held-out normal | 0.480+-0.151 | 1.00+-0.00 | 0.808+-0.066 |
| 5 | 2 | fp_1-3 + held-out normal | 0.470+-0.094 | 1.00+-0.00 | 0.801+-0.036 |
| 5 | 3 | fp_1-3 + held-out normal | 0.419+-0.110 | 1.00+-0.00 | 0.776+-0.042 |
| 5 | 4 | fp_1-3 + held-out normal | 0.406+-0.108 | 1.00+-0.00 | 0.752+-0.047 |
| 5 | 5 | fp_1-3 + held-out normal | 0.397+-0.108 | 1.00+-0.00 | 0.747+-0.050 |
| 10 | 2 | fp_1-3 only (no held-out normal) | 0.367+-0.000 | 1.00+-0.00 | 0.750+-0.000 |
| 10 | 3 | fp_1-3 only (no held-out normal) | 0.367+-0.000 | 1.00+-0.00 | 0.750+-0.000 |
| 10 | 4 | fp_1-3 only (no held-out normal) | 0.333+-0.000 | 1.00+-0.00 | 0.700+-0.000 |
| 10 | 5 | fp_1-3 only (no held-out normal) | 0.333+-0.000 | 1.00+-0.00 | 0.700+-0.000 |

## E0-6 admin-port list (R3 only)

| R3 port list | attack runs flagged (of 80) | normal runs flagged (of 40) | alert precision (B) | attack runs flagged by scenario |
| --- | --- | --- | --- | --- |
| v1 list | 40 | 0 | 1.000 | abnormal_3:10, k8s_1:10, k8s_2:10, evasion_1:10 |
| official table + NodePort range | 40 | 0 | 1.000 | abnormal_3:10, k8s_1:10, k8s_2:10, evasion_1:10 |
| official table + NodePort + 443 | 40 | 0 | 1.000 | abnormal_3:10, k8s_1:10, k8s_2:10, evasion_1:10 |
| v1 list minus non-Kubernetes ports (22, 3306, 6379) | 40 | 0 | 1.000 | abnormal_3:10, k8s_1:10, k8s_2:10, evasion_1:10 |

## E2-1 consecutive failed first contacts (R6) vs fan-out (R4), each rule alone

| rule | attack runs flagged (of 80) | normal runs flagged (of 40) | run precision | alert precision (B) | runs flagged by scenario |
| --- | --- | --- | --- | --- | --- |
| R6 alone | 30 | 0 | 1.000 | 1.000 | abnormal_3:10, k8s_2:10, evasion_1:10 |
| R6 alone, scoped | 30 | 0 | 1.000 | 1.000 | abnormal_3:10, k8s_2:10, evasion_1:10 |
| R4 alone (v1) | 78 | 38 | 0.672 | 0.047 | abnormal_1:10, abnormal_2:10, abnormal_3:10, k8s_1:10, k8s_2:10, k8s_3:10, evasion_1:10, evasion_2:8, normal:10, fp_1:10, fp_2:8, fp_3:10 |
| R4 alone, scoped | 30 | 0 | 1.000 | 0.904 | abnormal_2:10, abnormal_3:10, k8s_2:10 |

## E2-1 first contacts needed before R6 flags a source (mean over flagged runs; the paper reports about 4-5 for new addresses)

| scenario | runs flagged | mean first contacts until flagged |
| --- | --- | --- |
| abnormal_1 | 0/10 | - |
| abnormal_2 | 0/10 | - |
| abnormal_3 | 10/10 | 8.0 |
| k8s_1 | 0/10 | - |
| k8s_2 | 10/10 | 4.0 |
| k8s_3 | 0/10 | - |
| evasion_1 | 10/10 | 8.0 |
| evasion_2 | 0/10 | - |

## E2-2 fan-out rule (R4 alone): threshold N x window W x scope

| R4 scope | N | W (s) | attack runs flagged (of 80) | normal runs flagged (of 40) | evasion_1 | evasion_2 |
| --- | --- | --- | --- | --- | --- | --- |
| none | 5 | 10 | 78 | 38 | 10/10 | 8/10 |
| none | 5 | 60 | 78 | 38 | 10/10 | 8/10 |
| none | 5 | 300 | 78 | 38 | 10/10 | 8/10 |
| none | 20 | 10 | 0 | 0 | 0/10 | 0/10 |
| none | 20 | 60 | 10 | 0 | 0/10 | 0/10 |
| none | 20 | 300 | 20 | 0 | 10/10 | 0/10 |
| known apps | 5 | 10 | 30 | 0 | 0/10 | 0/10 |
| known apps | 5 | 60 | 40 | 0 | 10/10 | 0/10 |
| known apps | 5 | 300 | 40 | 0 | 10/10 | 0/10 |
| known apps | 20 | 10 | 0 | 0 | 0/10 | 0/10 |
| known apps | 20 | 60 | 10 | 0 | 0/10 | 0/10 |
| known apps | 20 | 300 | 20 | 0 | 10/10 | 0/10 |

## COMBO learn 5 / evaluate rest, mean+-sd over 30 splits

| combination (fixed in advance) | false-alarm run rate (held-out normal + fp) | run recall | alert precision (policy B) |
| --- | --- | --- | --- |
| K1 v1 default: R1-R5 | 0.971+-0.000 | 1.000+-0.000 | 0.541+-0.016 |
| K2 v1 scoped: R1-R5, R4 scoped | 0.587+-0.096 | 1.000+-0.000 | 0.769+-0.032 |
| K3 R1,R2,R3,R5,R6 (R4 replaced by R6) | 0.587+-0.096 | 1.000+-0.000 | 0.767+-0.032 |
| K4 R1-R6, R4 and R6 scoped | 0.587+-0.096 | 1.000+-0.000 | 0.770+-0.032 |

## Settings tried (report together with the results)

| experiment | settings evaluated |
| --- | --- |
| COMBO | 4 |
| E0-1 | 1 |
| E0-2 | 1 |
| E0-3 | 1 |
| E0-4 | 2 |
| E0-5 | 12 |
| E0-6 | 4 |
| E2-1 | 4 |
| E2-2 | 12 |
| ref | 2 |

Total: 43
