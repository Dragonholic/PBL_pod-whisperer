# v3 results (new data only)

- new runs per scenario: {'fp_1': 10, 'fp_2': 10, 'fp_3': 10, 'shift_replica2': 5, 'abnormal_1': 10, 'abnormal_2': 10, 'abnormal_3': 10, 'k8s_1': 10, 'k8s_2': 10, 'k8s_3': 10, 'evasion_2': 10, 'abnormal_4': 10, 'evasion_1': 10, 'shift_restart': 5}

- long stream: 1.00 h, 402 windows of 9 s

- combinations tried: 9 (K2, K5a, K5b, K6, K6-r3, K7, K2+F1, K2+F2, K2+F3); learning baselines: 1 (all 10) + 30 (learn 5)

## E5-2 new normal runs

| combination | new normal group | runs | flagged (learn all 10) | flagged rate (learn 5, mean+-sd over 30 splits) | runs flagged per rule (learn 5, mean) | R1u tier alerts (learn 10) |
| --- | --- | --- | --- | --- | --- | --- |
| K2 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:1.8, R3:0.2, R5:10.0 | 0 |
| K2 | fp_2 | 10 | 5/10 | 0.517+-0.045 | R2:5.1, R3:0.0, R5:1.0 | 0 |
| K2 | fp_3 | 10 | 1/10 | 0.223+-0.145 | R1:1.0, R2:1.4, R3:0.2, R5:1.5 | 0 |
| K2 | restart | 5 | 5/5 | 0.993+-0.036 | R1:3.0, R2:4.1, R3:0.1, R5:3.4 | 0 |
| K2 | replica2 | 5 | 5/5 | 1.000+-0.000 | R1:3.0, R2:3.3, R3:0.1, R5:5.0 | 0 |
| K5a | fp_1 | 10 | 10/10 | 1.000+-0.000 | R3:0.2, R5:10.0 | 0 |
| K5a | fp_2 | 10 | 0/10 | 0.003+-0.018 | R3:0.0 | 0 |
| K5a | fp_3 | 10 | 1/10 | 0.113+-0.072 | R1:1.0, R3:0.2 | 0 |
| K5a | restart | 5 | 4/5 | 0.807+-0.109 | R1:3.0, R3:0.1, R5:1.0 | 0 |
| K5a | replica2 | 5 | 4/5 | 0.807+-0.036 | R1:3.0, R3:0.1, R5:4.0 | 0 |
| K5b | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:0.8, R3:0.2, R5:10.0 | 0 |
| K5b | fp_2 | 10 | 0/10 | 0.037+-0.066 | R2:0.4, R3:0.0 | 0 |
| K5b | fp_3 | 10 | 1/10 | 0.143+-0.084 | R2:1.4, R3:0.2 | 0 |
| K5b | restart | 5 | 3/5 | 0.667+-0.107 | R2:3.3, R3:0.1 | 0 |
| K5b | replica2 | 5 | 4/5 | 0.860+-0.092 | R2:3.3, R3:0.1, R5:4.0 | 0 |
| K6 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:0.8, R3:0.2, R5:10.0 | 0 |
| K6 | fp_2 | 10 | 0/10 | 0.037+-0.066 | R2:0.4, R3:0.0 | 0 |
| K6 | fp_3 | 10 | 1/10 | 0.143+-0.084 | R2:1.4, R3:0.2 | 0 |
| K6 | restart | 5 | 3/5 | 0.667+-0.107 | R2:3.3, R3:0.1 | 0 |
| K6 | replica2 | 5 | 4/5 | 0.860+-0.092 | R2:3.3, R3:0.1, R5:4.0 | 0 |
| K6-r3 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:0.8, R5:10.0 | 0 |
| K6-r3 | fp_2 | 10 | 0/10 | 0.037+-0.066 | R2:0.4 | 0 |
| K6-r3 | fp_3 | 10 | 1/10 | 0.143+-0.084 | R2:1.4 | 0 |
| K6-r3 | restart | 5 | 3/5 | 0.667+-0.107 | R2:3.3 | 0 |
| K6-r3 | replica2 | 5 | 4/5 | 0.860+-0.092 | R2:3.3, R5:4.0 | 0 |
| K7 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:0.8, R3:0.2, R5:10.0 | 0 |
| K7 | fp_2 | 10 | 0/10 | 0.037+-0.066 | R2:0.4, R3:0.0 | 0 |
| K7 | fp_3 | 10 | 1/10 | 0.143+-0.084 | R2:1.4, R3:0.2 | 0 |
| K7 | restart | 5 | 3/5 | 0.667+-0.107 | R2:3.3, R3:0.1 | 0 |
| K7 | replica2 | 5 | 4/5 | 0.860+-0.092 | R2:3.3, R3:0.1, R5:4.0 | 0 |
| K2+F1 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:0.8, R3:0.2, R5:10.0 | 0 |
| K2+F1 | fp_2 | 10 | 0/10 | 0.050+-0.092 | R2:0.4, R3:0.0, R5:0.4 | 0 |
| K2+F1 | fp_3 | 10 | 1/10 | 0.163+-0.122 | R1:1.0, R2:1.4, R3:0.2, R5:0.4 | 0 |
| K2+F1 | restart | 5 | 3/5 | 0.680+-0.133 | R1:3.0, R2:3.3, R3:0.1, R5:2.3 | 0 |
| K2+F1 | replica2 | 5 | 5/5 | 1.000+-0.000 | R1:3.0, R2:3.3, R3:0.1, R5:5.0 | 0 |
| K2+F2 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:1.8, R3:0.2, R5:10.0 | 0 |
| K2+F2 | fp_2 | 10 | 5/10 | 0.517+-0.045 | R2:5.1, R3:0.0, R5:1.0 | 0 |
| K2+F2 | fp_3 | 10 | 1/10 | 0.223+-0.145 | R2:1.4, R3:0.2, R5:1.5 | 0 |
| K2+F2 | restart | 5 | 5/5 | 0.993+-0.036 | R2:4.1, R3:0.1, R5:3.4 | 0 |
| K2+F2 | replica2 | 5 | 5/5 | 1.000+-0.000 | R2:3.3, R3:0.1, R5:5.0 | 0 |
| K2+F3 | fp_1 | 10 | 10/10 | 1.000+-0.000 | R2:1.8, R3:0.2, R5:10.0 | 0 |
| K2+F3 | fp_2 | 10 | 5/10 | 0.510+-0.040 | R2:5.1, R3:0.0 | 0 |
| K2+F3 | fp_3 | 10 | 1/10 | 0.143+-0.084 | R1:1.0, R2:1.4, R3:0.2 | 0 |
| K2+F3 | restart | 5 | 4/5 | 0.813+-0.050 | R1:3.0, R2:4.1, R3:0.1 | 0 |
| K2+F3 | replica2 | 5 | 4/5 | 0.860+-0.092 | R1:3.0, R2:3.3, R3:0.1, R5:4.0 | 0 |

## E5-2 long normal stream (alerts per hour)

| combination | alerts/hour (learn 10) | windows flagged (learn 10) | alerts/hour (learn 5, mean+-sd) | windows flagged rate (learn 5) | alerts by rule (learn 10) | alerts from apps | alerts from system components | R1u tier |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K2 | 308 | 82/402 | 466+-219 | 0.395+-0.175 | R1:13, R2:231, R5:65 | 16 | 293 | 0 |
| K5a | 29 | 28/402 | 35+-35 | 0.084+-0.080 | R1:13, R5:16 | 16 | 13 | 0 |
| K5b | 13 | 12/402 | 70+-172 | 0.089+-0.108 | R2:13 | 0 | 13 | 0 |
| K6 | 13 | 12/402 | 70+-172 | 0.089+-0.108 | R2:13 | 0 | 13 | 0 |
| K6-r3 | 13 | 12/402 | 63+-162 | 0.089+-0.108 | R2:13 | 0 | 13 | 0 |
| K7 | 13 | 12/402 | 70+-172 | 0.089+-0.108 | R2:13 | 0 | 13 | 0 |
| K2+F1 | 52 | 36/402 | 161+-202 | 0.218+-0.178 | R1:13, R2:13, R5:26 | 0 | 52 | 0 |
| K2+F2 | 295 | 82/402 | 453+-219 | 0.395+-0.175 | R2:231, R5:65 | 16 | 280 | 0 |
| K2+F3 | 243 | 28/402 | 300+-172 | 0.126+-0.103 | R1:13, R2:231 | 0 | 244 | 0 |

## E5-3 / E5-4 detected runs per scenario

| combination | abnormal_1 (learn 10; mean over splits) | abnormal_2 (learn 10; mean over splits) | abnormal_3 (learn 10; mean over splits) | abnormal_4 (learn 10; mean over splits) | k8s_1 (learn 10; mean over splits) | k8s_2 (learn 10; mean over splits) | k8s_3 (learn 10; mean over splits) | evasion_1 (learn 10; mean over splits) | evasion_2 (learn 10; mean over splits) | recall old 8 scenarios | abnormal_4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K2 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K5a | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K5b | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K6 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K6-r3 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K7 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K2+F1 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K2+F2 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |
| K2+F3 | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 10/10 (1.00) | 80/80 | 10/10 |

## alert precision (label policy B, learn 10)

| combination | attack alerts labelled B | attack alerts not labelled | alerts in 40 new normal runs | alert precision |
| --- | --- | --- | --- | --- |
| K2 | 4986 | 1347 | 193 | 0.764 |
| K5a | 4986 | 83 | 46 | 0.975 |
| K5b | 4986 | 137 | 25 | 0.969 |
| K6 | 5632 | 137 | 25 | 0.972 |
| K6-r3 | 4181 | 137 | 25 | 0.963 |
| K7 | 5632 | 137 | 25 | 0.972 |
| K2+F1 | 4986 | 779 | 109 | 0.849 |
| K2+F2 | 4986 | 1313 | 182 | 0.769 |
| K2+F3 | 4986 | 639 | 98 | 0.871 |

## runs in which each rule fired (learn 10)

| combination | scenario | R1 runs | R2 runs | R3 runs | R4 runs | R5 runs | S1 runs | S2 runs | S3 runs | S4 runs | S5 runs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K2 | abnormal_1 | 10 | 10 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| K2 | abnormal_2 | 10 | 10 | 0 | 10 | 10 | 0 | 0 | 0 | 0 | 0 |
| K2 | abnormal_3 | 10 | 10 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 |
| K2 | abnormal_4 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K2 | k8s_1 | 10 | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |
| K2 | k8s_2 | 10 | 10 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 |
| K2 | k8s_3 | 10 | 10 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| K2 | evasion_1 | 10 | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |
| K2 | evasion_2 | 1 | 1 | 0 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |
| K5b | abnormal_1 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | abnormal_2 | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | abnormal_3 | 10 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | abnormal_4 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | k8s_1 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | k8s_2 | 10 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | k8s_3 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | evasion_1 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K5b | evasion_2 | 0 | 1 | 0 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |
| K6 | abnormal_1 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| K6 | abnormal_2 | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| K6 | abnormal_3 | 10 | 10 | 10 | 10 | 0 | 10 | 10 | 10 | 0 | 0 |
| K6 | abnormal_4 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 10 |
| K6 | k8s_1 | 10 | 10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 |
| K6 | k8s_2 | 10 | 10 | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 |
| K6 | k8s_3 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 10 | 0 |
| K6 | evasion_1 | 10 | 10 | 10 | 0 | 0 | 10 | 10 | 0 | 0 | 0 |
| K6 | evasion_2 | 0 | 1 | 0 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |

## E5-5 effect of F1/F2/F3 on the long stream (learn 10)

| combination | alerts/hour | change vs K2 per hour | alerts by rule | R1u tier |
| --- | --- | --- | --- | --- |
| K2 | 308 | +0 | R1:13, R2:231, R5:65 | 0 |
| K2+F1 | 52 | -256 | R1:13, R2:13, R5:26 | 0 |
| K2+F2 | 295 | -13 | R2:231, R5:65 | 0 |
| K2+F3 | 243 | -65 | R1:13, R2:231 | 0 |
| K5a | 29 | -279 | R1:13, R5:16 | 0 |
| K5b | 13 | -295 | R2:13 | 0 |

## E5-5 signatures: runs where each fires

| signature | abnormal_1 | abnormal_2 | abnormal_3 | abnormal_4 | k8s_1 | k8s_2 | k8s_3 | evasion_1 | evasion_2 | alerts in new normal runs | alerts in long stream | runs caught only by this signature (not by K5b rules) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 | 10/10 | 0/10 | 10/10 | 0/10 | 0 | 0 | 0 |
| S2 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0 | 0 | 0 |
| S3 | 0/10 | 0/10 | 10/10 | 0/10 | 10/10 | 0/10 | 0/10 | 0/10 | 0/10 | 0 | 0 | 0 |
| S4 | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 | 0 | 0 | 0 |
| S5 | 0/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 | 0 | 0 | 0 |

## paired t-tests (splits are not independent; p is a reference value)

| comparison | unit | flagged rate A | flagged rate B | paired t-test over 30 learn/evaluate splits |
| --- | --- | --- | --- | --- |
| K2 vs K5a | normal_runs | 0.684 | 0.481 | t=23.82, df=29, p=1.4e-20 |
| K2 vs K5a | long_windows | 0.395 | 0.084 | t=9.55, df=29, p=1.8e-10 |
| K2 vs K5b | normal_runs | 0.684 | 0.486 | t=31.31, df=29, p=6.6e-24 |
| K2 vs K5b | long_windows | 0.395 | 0.089 | t=12.68, df=29, p=2.3e-13 |
| K5b vs K6 | normal_runs | 0.486 | 0.486 | all differences equal (test not possible) |
| K5b vs K6 | long_windows | 0.089 | 0.089 | all differences equal (test not possible) |

## prediction table vs actual (signatures, K6, learn 10)

| scenario | S1 | S2 | S3 | S4 | S5 |
| --- | --- | --- | --- | --- | --- |
| normal | pred - / actual - (0 alerts in stream) | pred - / actual - (0 alerts in stream) | pred - / actual - (0 alerts in stream) | pred - / actual - (0 alerts in stream) | pred - / actual - (0 alerts in stream) |
| fp_1 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| fp_2 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| fp_3 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| abnormal_1 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| abnormal_2 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| abnormal_3 | pred O / actual 10/10 | pred O / actual 10/10 | pred O / actual 10/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| k8s_1 | pred - / actual 0/10 | pred - / actual 0/10 | pred O / actual 10/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| k8s_2 | pred O / actual 10/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| k8s_3 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred O / actual 10/10 | pred - / actual 0/10 |
| evasion_1 | pred O / actual 10/10 | pred O / actual 10/10 | pred O / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| evasion_2 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 |
| abnormal_4 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred - / actual 0/10 | pred O / actual 10/10 |

Mismatches: evasion_1 S3: predicted fires, actual 0/10

## additional predictions Q1-Q10 vs actual

| id | prediction | actual | result |
| --- | --- | --- | --- |
| Q1 | K5a alerts/hour <= 50% of K2 | K5a 29 vs K2 308 (9%) | correct |
| Q2 | K5a <= K5b <= K2 alerts/hour | 29 / 13 / 308 | wrong |
| Q3 | F2 removes R1 false alarms in restart and replica2 runs | K2 R1-flagged runs restart 3/5, replica2 3/5; K5b 0/5, 0/5 | correct |
| Q4 | evasion_2 stays detected by R5 under F3 (10/10) | 10/10 | correct |
| Q5 | K6 run recall = 1.000 (8 old scenarios + abnormal_4); K6 normal alerts/hour = K5b | recall 1.000; K6 13 vs K5b 13 | correct |
| Q6 | K6-r3 run recall = 1.000 | 1.000 | correct |
| Q7 | K2 detects abnormal_4 10/10; S5 10/10 | K2 10/10; S5 10/10 | correct |
| Q8 | fp_1 flagged in >= 8/10 runs under K5b | 10/10 | correct |
| Q9 | K7 changes no alert count (tags only) | K7 13 vs K6 13; multistep incidents in attack runs 124 | correct |
| Q10 | S1/S2/S3 fire 10/10 where predicted O | see signature table | wrong |

## dropped flows in the new normal runs by reason

| group | drop_reason_desc | flows |
| --- | --- | --- |
| fp_3 | UNSUPPORTED_L3_PROTOCOL | 1 |
| replica2 | UNSUPPORTED_L3_PROTOCOL | 5 |
| restart | UNSUPPORTED_L3_PROTOCOL | 5 |
