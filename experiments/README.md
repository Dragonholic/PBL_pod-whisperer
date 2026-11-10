# Experiments

| Version | Folder | Who designed the rules | Status |
|---|---|---|---|
| v1 | `v1_ai_only/` | AI only (baseline, R1-R5) | done (git tag `v1-ai-baseline`) |
| v2 | `v2_research/` | v1 + findings from my own literature/tool research | in progress |
| v3 | `v3_signature/` | v2 + signature rules I designed myself | planned |

- Code (`detector.py`, `evaluate.py`, `collect.sh`) is shared across versions.
- Each version keeps its notes and result snapshot in its own folder.
- `config.v2.yaml` / `config.v3.yaml` write results to the matching folder:
  `python3 evaluate.py --mode report -c config.v2.yaml`
- Root `results/` and `results_scoped/` are the latest v1 outputs (copied to `v1_ai_only/`).
