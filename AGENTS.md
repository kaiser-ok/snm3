# Repository Guidelines

## Project Structure & Module Organization
Core logic lives in `nad/`, which holds operational config (`config.yaml`, `device_mapping.yaml`), ML components (`nad/ml/feature_engineer.py`, `nad/ml/isolation_forest_detector.py`, `nad/ml/anomaly_classifier.py`), helper utilities (`nad/utils/`), and trained artifacts in `nad/models/`. Top-level scripts (`train_isolation_forest.py`, `realtime_detection*.py`, `verify_anomaly.py`, `optimize_classifier_thresholds.py`) are the supported CLIs. Automation helpers such as `monitor*.sh`, `backfill_*.py`, and `batch_verify.sh` sit beside investigative Markdown notes. Keep runtime artifacts under `logs/` and `reports/`.

## Build, Test, and Development Commands
- `bash install_dependencies.sh` – guided install for numpy, scikit-learn, elasticsearch, and PyYAML.
- `python3 train_isolation_forest.py --days 7 --evaluate` – re-trains on aggregated ES data and refreshes `nad/models/*.pkl`.
- `python3 realtime_detection.py --minutes 10 --exclude-servers --continuous --interval 5` – executes realtime inference; drop `--continuous` for a single pass.
- `python3 verify_anomaly.py --config nad/config.yaml --id <alert_id>` – fetches the referenced anomaly, raw flows, and optional MySQL context.
- `python3 test_isolation_forest.py` / `python3 test_port_improvement.py` – lightweight regressions to run before code review.

## Coding Style & Naming Conventions
Target Python 3.10+, four-space indents, and descriptive docstrings. Use snake_case for files, functions, and CLI flags, PascalCase for classes (`OptimizedIsolationForest`), and ALL_CAPS for constants. Include type hints, rely on `logging` in shared modules, and reserve `print` blocks for user-facing CLIs. Preserve key ordering and comments when editing YAML.

## Testing Guidelines
Scenario-specific scripts follow the `test_*.py` pattern near the repo root (`test_isolation_forest.py`, `test_es_anomaly_data.py`, `test_port_improvement.py`). Tests may mock ES results but should print the metrics reviewers need. Run `verify_coverage.py` or `debug_coverage.py` whenever modifying feature definitions so derived stats still match `nad/config.yaml`. Feature or classifier changes need a short before/after note in `reports/` plus the exact command used to reproduce.

## Commit & Pull Request Guidelines
History uses short, imperative subjects (`Initial commit: Network Anomaly Detection System`). Keep future commits under 72 characters, optionally scoping with a colon, and include details about data ranges, scripts run, and log paths. Pull requests should link to the relevant issue, outline impacted components, list executed verification commands, and attach supporting screenshots or log excerpts (for example, snippets from `logs/realtime_detection.log`).

## Security & Configuration Tips
Do not commit real endpoints or credentials—work from `nad/config.yaml.example` and apply overrides locally. Coordinate edits to `device_mapping.yaml`; the timestamped backups in `nad/` show the desired rotation pattern. Runtime artifacts (`logs/`, `*.pid`, `reports/*.txt`) should be sanitized or git-ignored before publishing. Use the connection details in `flow.md` to test ElasticSearch/MySQL with read-only users whenever possible.
