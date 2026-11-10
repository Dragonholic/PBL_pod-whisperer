# v3 - v2 + tuning (F1-F3) and signatures (S1-S5)

The user gave up designing own signatures. v3 follows the Notion page
"3차 실험 - 문제점 보완 규칙 제안" (F1-F3 tuning, S1-S5 signatures, C1 tag).

- `PREREGISTRATION.md`: combinations, settings and predictions fixed before any v3 data was collected
- `allowlist.yaml`: F1 allowlist (3 entries, from the 2.2 data)
- `signatures/signatures.yaml`: S1-S5 with source documents
- code: `../../v3_core.py` (detector layer), `../../v3_selftest.py`, `../../v3_stage0.py`, `../../v3_experiments.py`
- data collection: `../../collect_v3.sh` (writes `data_v3/`, git-ignored)
- results: `results/` (stage0_*.csv, selftest.md, e5_*.csv, pred_vs_actual_*.csv, summary.md)

Run: `python3 v3_stage0.py; python3 v3_selftest.py; python3 v3_experiments.py`
