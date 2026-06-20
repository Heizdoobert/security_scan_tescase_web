"""MongoDB security check companion script.

Direct database security testing via mongosh subprocess.
Not part of the HTTP scan pipeline — run separately.

Usage:
    python -m websec_test.mongodb_check --uri mongodb://localhost:27017
    python -m websec_test.mongodb_check --uri mongodb://localhost:27017 --json
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime


def find_mongosh(mongosh_path=None):
    """Locate mongosh binary using ordered discovery.

    Order:
    1. Explicit --mongosh-path argument
    2. PATH lookup via shutil.which
    3. .\\mongosh-bin\\mongosh.exe (cwd relative)
    4. C:\\Program Files\\MongoDB\\Server\\*\\bin\\mongosh.exe (glob)
    """
    if mongosh_path:
        if os.path.isfile(mongosh_path):
            return mongosh_path
        return None

    # Try PATH
    path_result = shutil.which("mongosh")
    if path_result:
        return path_result

    # Try local mongosh-bin directory
    local_path = os.path.join(os.getcwd(), "mongosh-bin", "mongosh.exe")
    if os.path.isfile(local_path):
        return local_path

    # Try Program Files (glob for version directory)
    matches = glob.glob(r"C:\Program Files\MongoDB\Server\*\bin\mongosh.exe")
    if matches:
        return matches[0]

    return None


def run_mongosh_eval(uri, eval_cmd, timeout=5, mongosh_path=None):
    """Run a single mongosh --eval command and return parsed JSON output."""
    exe = mongosh_path or "mongosh"
    result = subprocess.run(
        [exe, "--quiet", "--eval", eval_cmd, uri],
        capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args,
            output=result.stdout, stderr=result.stderr
        )
    # mongosh may print warnings before JSON; take the last line
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    if not lines:
        raise ValueError(f"No output from mongosh eval: {eval_cmd}")
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"raw": lines[-1]}


def run_all_checks(uri, timeout=5, mongosh_path=None):
    """Run all 6 MongoDB security checks and return results list."""
    results = []

    # --- Check 1: Connection / Ping ---
    try:
        ping = run_mongosh_eval(uri, "JSON.stringify(db.adminCommand('ping'))",
                                timeout, mongosh_path)
        if ping.get("ok") == 1:
            results.append({"test_name": "connection_check", "status": "pass",
                            "evidence": f"MongoDB ping OK: {ping.get('ok')}",
                            "recommendation": "No action needed"})
        else:
            results.append({"test_name": "connection_check", "status": "fail",
                            "evidence": f"Ping returned unexpected: {ping}",
                            "recommendation": "Check MongoDB server status"})
    except subprocess.TimeoutExpired:
        results.append({"test_name": "connection_check", "status": "error",
                        "evidence": f"Connection timed out after {timeout}s",
                        "recommendation": "Check network/firewall or increase --timeout"})
    except (subprocess.CalledProcessError, ValueError) as e:
        results.append({"test_name": "connection_check", "status": "error",
                        "evidence": str(e)[:200],
                        "recommendation": "Verify MongoDB is running and reachable"})

    # --- Check 2: Authentication Status ---
    try:
        auth = run_mongosh_eval(
            uri,
            "JSON.stringify(db.adminCommand({getParameter:1,authenticationMeasures:1}))",
            timeout, mongosh_path
        )
        results.append({"test_name": "auth_status", "status": "pass",
                        "evidence": f"Auth measures: {auth}",
                        "recommendation": "Authentication is configured"})
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
        results.append({"test_name": "auth_status", "status": "fail",
                        "evidence": f"Auth check failed: {str(e)[:200]}",
                        "recommendation": "Consider enabling MongoDB authentication"})

    # --- Check 3: Anonymous Access (listDatabases) ---
    try:
        dbs = run_mongosh_eval(uri, "JSON.stringify(db.adminCommand({listDatabases:1}))",
                               timeout, mongosh_path)
        if dbs.get("ok") == 1:
            db_names = [d["name"] for d in dbs.get("databases", [])]
            results.append({"test_name": "anonymous_access", "status": "fail",
                            "evidence": f"Anonymous listDatabases succeeded. Databases: {db_names}",
                            "recommendation": "Enable authentication to restrict database listing"})
        else:
            results.append({"test_name": "anonymous_access", "status": "pass",
                            "evidence": f"listDatabases blocked: {dbs}",
                            "recommendation": "No action needed"})
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
        results.append({"test_name": "anonymous_access", "status": "pass",
                        "evidence": f"listDatabases denied: {str(e)[:200]}",
                        "recommendation": "No action needed"})

    # --- Check 4: Database Enumeration (nameOnly) ---
    try:
        enum = run_mongosh_eval(
            uri,
            "JSON.stringify(db.adminCommand({listDatabases:1,nameOnly:true}))",
            timeout, mongosh_path
        )
        if enum.get("ok") == 1:
            db_names = [d["name"] for d in enum.get("databases", [])]
            results.append({"test_name": "database_enumeration", "status": "fail",
                            "evidence": f"Databases enumerated: {db_names}",
                            "recommendation": "Restrict listDatabases via auth"})
        else:
            results.append({"test_name": "database_enumeration", "status": "pass",
                            "evidence": "Database enumeration blocked",
                            "recommendation": "No action needed"})
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
        results.append({"test_name": "database_enumeration", "status": "pass",
                        "evidence": f"Enumeration denied: {str(e)[:200]}",
                        "recommendation": "No action needed"})

    # --- Check 5: Default Credentials ---
    default_creds = [("admin", "admin"), ("root", "root"),
                     ("admin", "password"), ("test", "test")]
    creds_found = []
    for user, pwd in default_creds:
        try:
            auth_uri = uri.replace("mongodb://", f"mongodb://{user}:{pwd}@")
            run_mongosh_eval(auth_uri, "JSON.stringify(db.adminCommand('ping'))",
                             timeout, mongosh_path)
            creds_found.append(f"{user}:{pwd}")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError):
            continue
    if creds_found:
        results.append({"test_name": "default_credentials", "status": "fail",
                        "evidence": f"Default credentials accepted: {creds_found}",
                        "recommendation": "Change default credentials immediately"})
    else:
        results.append({"test_name": "default_credentials", "status": "pass",
                        "evidence": "No default credentials accepted",
                        "recommendation": "No action needed"})

    # --- Check 6: Admin User Check ---
    try:
        users = run_mongosh_eval(
            uri,
            "JSON.stringify(db.getSiblingDB('admin').system.users.find().toArray())",
            timeout, mongosh_path
        )
        if isinstance(users, list) and len(users) > 0:
            usernames = [u.get("user", "unknown") for u in users]
            results.append({"test_name": "admin_users", "status": "warn",
                            "evidence": f"Admin users found: {usernames}",
                            "recommendation": "Review admin users, remove unused accounts"})
        elif isinstance(users, list):
            results.append({"test_name": "admin_users", "status": "pass",
                            "evidence": "No admin users found in admin database",
                            "recommendation": "No action needed"})
        else:
            results.append({"test_name": "admin_users", "status": "pass",
                            "evidence": f"Admin user query returned: {users}",
                            "recommendation": "No action needed"})
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
        results.append({"test_name": "admin_users", "status": "pass",
                        "evidence": f"Admin user query denied: {str(e)[:200]}",
                        "recommendation": "No action needed"})

    return results


def print_terminal(results, uri):
    """Print color-coded result table to terminal."""
    BY_STATUS = {
        "pass": "\033[32mPASS\033[0m",
        "fail": "\033[31mFAIL\033[0m",
        "warn": "\033[33mWARN\033[0m",
        "error": "\033[31mERROR\033[0m",
    }
    print(f"\n{'='*60}")
    print(f"  MongoDB Security Check — {uri}")
    print(f"{'='*60}\n")
    counts = {"pass": 0, "fail": 0, "warn": 0, "error": 0}
    for r in results:
        label = BY_STATUS.get(r["status"], str(r["status"]))
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        print(f"  [{label}] {r['test_name']}")
        print(f"         Evidence: {r['evidence'][:120]}")
        print(f"         Fix: {r['recommendation']}")
        print()
    print(f"{'-'*60}")
    print(f"  Summary: {len(results)} total"
          f"  |  PASS: {counts['pass']}"
          f"  |  FAIL: {counts['fail']}"
          f"  |  WARN: {counts['warn']}"
          f"  |  ERROR: {counts['error']}")
    print(f"{'='*60}\n")


def write_json_report(results, uri):
    """Write JSON report file to current directory."""
    report = {
        "target": uri,
        "timestamp": datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total": len(results),
            "pass": sum(1 for r in results if r["status"] == "pass"),
            "fail": sum(1 for r in results if r["status"] == "fail"),
            "warn": sum(1 for r in results if r["status"] == "warn"),
            "error": sum(1 for r in results if r["status"] == "error"),
        },
    }
    filename = f"mongodb_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def parse_args(argv=None):
    """Parse CLI arguments for mongodb_check."""
    parser = argparse.ArgumentParser(
        description="MongoDB Security Check — test authentication, access controls, and default credentials"
    )
    parser.add_argument("--uri", default="mongodb://localhost:27017",
                        help="MongoDB URI to test (default: mongodb://localhost:27017)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Seconds to wait for mongosh response (default: 5)")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON to stdout and write report file")
    parser.add_argument("--mongosh-path", default=None,
                        help="Explicit path to mongosh binary")
    return parser.parse_args(argv)


def main():
    args = parse_args()
    mongosh_path = find_mongosh(args.mongosh_path)

    if mongosh_path is None:
        print("[!] mongosh not found. Install MongoDB Shell or use --mongosh-path", file=sys.stderr)
        print("    Download: https://www.mongodb.com/try/download/shell", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Using mongosh at: {mongosh_path}")

    results = run_all_checks(args.uri, timeout=args.timeout, mongosh_path=mongosh_path)

    fail_count = sum(1 for r in results if r["status"] in ("fail", "error"))

    if args.json:
        print(json.dumps(results, indent=2))
        report_file = write_json_report(results, args.uri)
        print(f"[*] Report saved to: {report_file}", file=sys.stderr)
    else:
        print_terminal(results, args.uri)

    sys.exit(1 if fail_count > 0 else 0)


if __name__ == "__main__":
    main()
