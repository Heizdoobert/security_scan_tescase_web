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

---

## OWASP Juice Shop Test Suite

This project includes **12 test cases** mapped directly from `Pentest_TestCases_JuiceShop.xlsx` covering OWASP Juice Shop vulnerabilities. Tests run via the **PentestGPT pipeline** — an LLM-powered (qwen2.5-coder) automated security testing framework.

### Test Case Mapping (Excel → Automated Test)

| TC ID | Vulnerability | Endpoint | Attack Vector |
|-------|--------------|----------|--------------|
| TC_SEC_INJ_01 | SQLi Login Bypass | `POST /rest/user/login` | `admin@juice-sh.op' OR '1'='1 --` |
| TC_SEC_INJ_02 | GDPR Deleted Account Access | `POST /rest/user/login` | `' OR DeletedAt IS NOT NULL --` |
| TC_SEC_INJ_03 | Ephemeral Accountant (UNION SELECT) | `POST /rest/user/login` | UNION SELECT fabricating `acc0unt4nt@juice-sh.op` |
| TC_SEC_INJ_04 | SSTI Malware Execution (Pug) | `PUT /api/Users/1` | `#{global.process...exec('id')}` |
| TC_SEC_BAC_01 | Admin Registration (BAC) | `POST /api/Users` | `"role": "admin"` in registration JSON |
| TC_SEC_AUTH_01 | OAuth Password Reverse Engineering | `POST /rest/user/login` | `bjoern.kimmich@gmail.com` + Base64(reversed(email)) |
| TC_SEC_AUTH_02 | TOTP 2FA Bypass via SQLi | `GET /rest/products/search` | UNION SELECT extracting `totpSecret` |
| TC_SEC_AUTH_03 | JWT 'none' Algorithm | `GET /rest/user/whoami` | Forged JWT `alg: none`, email `jwtn3d@juice-sh.op` |
| TC_SEC_AUTH_04 | JWT RS256→HS256 Confusion | `GET /rest/user/whoami` | HS256 signed with public key, email `rsa_lord@juice-sh.op` |
| TC_SEC_SDE_01 | FTP Confidential Document | `GET /ftp/acquisition.md` | Unauthenticated access to M&A plans |
| TC_SEC_SDE_02 | GPS EXIF Password Reset | `GET /assets/public/images/uploads/favorite-hiking-place.png` | EXIF GPS → Daniel Boone National Forest → password reset |
| TC_SEC_XSS_01 | DOM XSS iframe | `GET /#/search?q=<iframe...>` | SoundCloud iframe in `q` parameter |

### Prerequisites

- **Docker** (for running OWASP Juice Shop)
- **Ollama** with `qwen2.5-coder:7b` model (or another supported model)
- Python 3.10+

### Running the Juice Shop Tests

**Step 1: Start OWASP Juice Shop**

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

**Step 2: Run the automated LLM-based test suite**

```bash
# Unit tests (no LLM needed) — validates module logic
python -m pytest tests/test_pentestgpt.py -v

# Integration tests (requires Ollama + qwen2.5-coder:7b running)
python -m pytest tests/test_pentestgpt_auto.py -v --integration
```

The pipeline works as follows:
1. Sends each test case context + Juice Shop endpoint description to PentestGPT LLM
2. LLM responds with `TYPE: HTTP` (raw HTTP request) or `TYPE: SCRIPT` (Python script)
3. Framework executes the request/script against the live Juice Shop instance
4. Result is sent back to LLM for a PASS/FAIL verdict
5. All results are logged to JSON reports in `Demo_auto/`

### Manual Testing per Excel Steps

Each Excel test case has detailed step-by-step instructions with Burp Suite. Use the `references/` directory for write-up guides:

```bash
# Example: SQLi Login Bypass (TC_SEC_INJ_01)
python -m websec_test.main --target http://localhost:3000/rest/user/login --check sqli
```

---

## PentestGPT Pipeline

Uses qwen2.5-coder:7b (via Ollama) as an automated security statement writer. Framework executes HTTP/script tests, PentestGPT verifies results.

```bash
cd Demo_auto\PentestGPT
uv run python ..\test_pentestgpt_all.py
```

The pipeline sends context to PentestGPT → receives `TYPE: HTTP` or `TYPE: SCRIPT` → routes to `do_http()` or `execute_script()` → sends result back for verdict → logs to JSON report. Results depend on model quality — qwen2.5-coder:7b handles ~1-2/8 tests correctly.

Set `TARGET_URL` (default `http://localhost:3000`) and `PENTESTGPT_MODEL` (default `ollama:qwen2.5-coder:7b`) in `Demo_auto/.env` or as env vars.

## Knowledge Graph

A persistent, queryable graph of the full codebase. Built with graphify — relationships tagged EXTRACTED, INFERRED, or AMBIGUOUS.

```bash
# Build / update
graphify . --update
# Query
graphify query "how does authentication work"
graphify explain "SessionClient"
```

Open `graphify-out/graph.html` in any browser for the interactive visualization.

## Project Structure

```
websec_test/              # 14 modules (auth, injection, config) + engine + SAST
tests/                    # 200+ pytest tests
  test_pentestgpt.py      #   PentestgptModule unit tests (no LLM)
  test_pentestgpt_auto.py #   Juice Shop LLM-powered test suite (12 cases from Excel)
Demo_auto/                # PentestGPT pipeline scripts
  PentestGPT/             #   PentestGPT framework (git submodule)
  pentestgpt_pipeline.py  #   Shared helpers: ask, HTTP, script executor
scripts/                  # SAST, dependency, compliance, pentest CLIs
references/               # OWASP, MITRE ATT&CK, disclosure templates
docs/superpowers/         # Design specs & implementation plans
graphify-out/             # Knowledge graph (open graph.html)
.superpowers/             # SDD progress & task records
Pentest_TestCases_JuiceShop.xlsx  # Master test case register (12 Juice Shop vulnerabilities)
Pentest_TestCases_WebSecTest.xlsx # WebSecTest-specific test cases
```
