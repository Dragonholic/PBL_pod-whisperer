# v2 follow-up results

## E0-4b same evaluation runs, baseline learned from 10 vs 5 normal runs

| rules | rule set | fp_1-3 flagged, learn 10 | fp_1-3 flagged, learn 5 | normal flagged, learn 10 | normal flagged, learn 5 |
| --- | --- | --- | --- | --- | --- |
| R1-R5, R4 scoped | any rule | 17/30 | 18.3+-2.0/30 | 0/10 (learned on) | 2.20+-1.60/5 (held out) |
| R1-R5, R4 scoped | R2 only | 7/30 | 8.5+-2.6/30 | 0/10 (learned on) | 0.73+-1.21/5 (held out) |
| R1-R5, R4 scoped | R5 only | 11/30 | 13.0+-2.7/30 | 0/10 (learned on) | 2.00+-1.57/5 (held out) |

## E0-6b R3 alone at path level (policy B)

| R3 list | alerts (all true) | malicious paths covered | malicious paths | path recall (B) | scan port in list? |
| --- | --- | --- | --- | --- | --- |
| v1 list | 1548 | 620 | 680 | 0.912 | 22:Y 443:Y 2379:Y 3306:Y 6379:Y 6443:Y 10250:Y 10255:Y |
| official table + NodePort | 664 | 220 | 680 | 0.324 | 22:n 443:n 2379:Y 3306:n 6379:n 6443:Y 10250:Y 10255:n |
| official + 443 | 864 | 310 | 680 | 0.456 | 22:n 443:Y 2379:Y 3306:n 6379:n 6443:Y 10250:Y 10255:n |
| v1 minus non-Kubernetes (22, 3306, 6379) | 924 | 340 | 680 | 0.500 | 22:n 443:Y 2379:Y 3306:n 6379:n 6443:Y 10250:Y 10255:Y |

## EXPL exploratory rule subsets (baseline learned from all 10 normal runs, so R2/R5 are optimistic)

| rules (exploratory, chosen after seeing results) | attack runs flagged | normal runs flagged | run precision | run recall | alert precision (B) | attack scenarios not fully caught | normal flagged by scenario |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | 71/80 | 1/40 | 0.986 | 0.887 | 0.987 | evasion_2 | fp_2:1 |
| R1+R3 | 71/80 | 1/40 | 0.986 | 0.887 | 0.993 | evasion_2 | fp_2:1 |
| R1+R3+R6 | 71/80 | 1/40 | 0.986 | 0.887 | 0.993 | evasion_2 | fp_2:1 |
| R1+R5 | 80/80 | 12/40 | 0.870 | 1.000 | 0.684 | none | fp_1:10, fp_2:2 |
| R1+R3+R5+R6 | 80/80 | 12/40 | 0.870 | 1.000 | 0.804 | none | fp_1:10, fp_2:2 |
| R1+R2+R3+R5+R6 | 80/80 | 17/40 | 0.825 | 1.000 | 0.782 | none | fp_1:10, fp_2:7 |
