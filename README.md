# WebSec Test

Automated web security testing CLI. Scans targets across 14 modules (auth, injection, config) plus SAST/dependency/compliance scans.

## Quick Start

1. Create and activate a Python 3.10+ virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Install Playwright browser binaries if they are not already present:

```bash
python -m playwright install
```

4. Run a web scan:

```bash
python -m websec_test.main --target http://localhost:8080/ --all
```

5. Check the result in the terminal summary and in the JSON report written to `./reports/websec_report_<timestamp>.json`.

6. Generate an interactive dashboard (3 files):

```bash
python -m websec_test.main --target http://localhost:8080/ --all --dashboard --open
```

Writes `dashboard_<ts>.html` + `.css` + `.js` to `./reports/` and opens it in your browser. Use the collapsible rows (click triangle) to see Expected, Actual, Error Details, Endpoint, and Fix for every check. Filter by status checkbox, search text, module, or severity. Click column headers to sort.

## Common Commands

```bash
python -m websec_test.main --secops /path/to/project
python -m websec_test.main --help    # full flag reference
```

Exit code 1 on failure — CI-ready.

Requires Python 3.10+, mongosh for MongoDB checks.

## Other Useful Flags

- `--secops /path/to/project` runs SAST, dependency, and compliance scans on a codebase.
- `--discover` lists discovered endpoints without running tests.
- `--check module/check_name` runs a single check.
- `--output ./reports` changes where JSON and dashboard artifacts are written.
- `--open` opens the dashboard in a browser after it is generated.

## Project Structure

```
websec_test/          # 14 modules (auth, injection, config) + engine + SAST
tests/                # 200+ pytest tests
scripts/              # SAST, dependency, compliance, pentest CLIs
references/           # OWASP, MITRE ATT&CK, disclosure templates
docs/superpowers/     # Design specs & implementation plans
graphify-out/         # Knowledge graph (open graph.html)
```
