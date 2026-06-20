"""CLI entry point for Web Security Test tool."""
import argparse
import sys
import time

from websec_test.client.session import SessionClient
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestStatus
from websec_test.results.reporter import Reporter
from websec_test.engine import Sequence, ModuleAdapter, CheckTreeBuilder, CheckSpec, Blackboard, DiscoverAction, CheckAdapter

# Module registry — maps name to a factory callable(credentials, target) returning an instance
from websec_test.modules.headers import HeadersModule, headers_check_specs
from websec_test.modules.auth import AuthModule, auth_check_specs
from websec_test.modules.csrf import CSRFModule, csrf_check_specs
from websec_test.modules.injection import InjectionModule, injection_check_specs
from websec_test.modules.authz import AuthorizationModule, authz_check_specs
from websec_test.modules.ssl_tls import SslTlsModule, ssl_tls_check_specs
from websec_test.modules.cors import CorsModule, cors_check_specs
from websec_test.modules.cookies import CookiesModule, cookies_check_specs
from websec_test.modules.disclosure import DisclosureModule, disclosure_check_specs
from websec_test.modules.methods import MethodsModule, methods_check_specs

ALL_MODULES = ["headers", "auth", "csrf", "injection", "authz",
                "ssl_tls", "cors", "cookies", "disclosure", "methods"]

CHECK_LEVEL_MODULES = {"headers", "auth", "csrf", "injection", "authz",
                       "ssl_tls", "cors", "cookies", "disclosure", "methods"}

MODULE_FACTORIES: dict[str, type] = {
    "headers": HeadersModule,
    "csrf": CSRFModule,
    "injection": InjectionModule,
    "authz": AuthorizationModule,
    "ssl_tls": SslTlsModule,
    "cors": CorsModule,
    "cookies": CookiesModule,
    "disclosure": DisclosureModule,
    "methods": MethodsModule,
}
CHECK_SPEC_REGISTRY: dict[str, list[CheckSpec]] = {
    "headers": headers_check_specs(),
    "auth": auth_check_specs(),
    "csrf": csrf_check_specs(),
    "injection": injection_check_specs(),
    "authz": authz_check_specs(),
    "ssl_tls": ssl_tls_check_specs(),
    "cors": cors_check_specs(),
    "cookies": cookies_check_specs(),
    "disclosure": disclosure_check_specs(),
    "methods": methods_check_specs(),
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Web Security Testing CLI — automated security checks for web applications"
    )
    parser.add_argument("--target", help="Target URL (e.g. http://localhost:8080/app)")
    parser.add_argument("--auth", help="Credentials in user:pass format for authenticated tests")
    parser.add_argument("--modules", nargs="+", choices=ALL_MODULES,
                        help="Specific modules to run (default: all)")
    parser.add_argument("--all", action="store_true", help="Run all test modules")
    parser.add_argument("--output", default="./reports", help="Output directory for JSON reports")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds")
    parser.add_argument("--log", nargs="?", const="log.txt", default=None,
                        help="Path to write plain-text log (default: log.txt)")
    parser.add_argument("--check-level", action="store_true",
                        help="Use per-check Behavior Tree nodes for all modules")
    parser.add_argument("--check", help="Run a single check (format: module/check_name, "
                        "e.g. headers/check_strict_transport_security)")
    parser.add_argument("--discover", action="store_true",
                        help="Run discovery only — show endpoints and checks without testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("--secops", nargs="?", const=".", default=None,
                        help="Run SAST/dependency/compliance scan on a project directory")
    args = parser.parse_args(argv)
    if args.all:
        args.modules = ALL_MODULES
    return args


def run_discover(client, target, module_map):
    """Discover-mode: run discovery only, print endpoints and checks, no test execution."""
    total_checks = 0
    total_endpoints = 0
    module_count = len(module_map)
    severity_labels = {
        2: "HIGH", 1: "MEDIUM", 0: "LOW",
    }

    print(f"\n  {'='*56}")
    print(f"  Discover mode for target: {target}")
    print(f"  {'='*56}\n")

    for name, mod in module_map.items():
        eps = mod.discover(client, target)
        if not eps:
            print(f"  Module: {name}")
            print(f"    [No endpoints discovered]\n")
            continue

        total_endpoints += len(eps)

        # Get known checks for this module
        spec_list = CHECK_SPEC_REGISTRY.get(name, [])
        total_checks += len(spec_list)

        print(f"  Module: {name}")
        print(f"    Discovered endpoints ({len(eps)}):")
        for ep in eps:
            print(f"      {ep.method or 'GET'} {ep.url}")
        if spec_list:
            print(f"    Checks ({len(spec_list)}):")
            for spec in spec_list:
                sev = severity_labels.get(spec.severity, str(spec.severity))
                print(f"      {spec.name} ({sev})")
        else:
            print(f"    Runs {name}/test() — no per-check breakdown available")
        print()

    print(f"  {'─'*56}")
    print(f"  Discover mode complete: {module_count} modules, "
          f"{total_checks} checks across {total_endpoints} endpoints")
    print(f"  {'='*56}")
    print("  Use --all or --modules <names> to run tests against these endpoints.\n")


def run(args):
    """Execute the security test suite."""
    target = args.target.rstrip("/")

    # Validate target reachability
    print(f"\n[*] Testing target: {target}")
    try:
        import requests
        resp = requests.get(target, timeout=args.timeout)
        print(f"[+] Target reachable (HTTP {resp.status_code})")
    except requests.RequestException as e:
        print(f"[!] Target unreachable: {e}")
        sys.exit(1)

    # Initialize client
    client = SessionClient(target, timeout=args.timeout)

    # Run selected modules via Behavior Tree engine
    collector = ResultCollector()
    modules_to_run = args.modules or ALL_MODULES
    start = time.time()

    # Build module registry from selected modules — use factory dict for uniformity
    def _make_module(name: str) -> object:
        if name == "auth":
            return AuthModule(credentials=args.auth, target=target)
        return MODULE_FACTORIES[name]()

    module_map = {
        name: _make_module(name)
        for name in modules_to_run
        if name in MODULE_FACTORIES
    }

    # Build and execute Behavior Tree
    blackboard = Blackboard(client=client, target=target)

    if args.discover:
        run_discover(client, target, module_map)
        sys.exit(0)

    if args.check:
        # ── Single-check mode: module/check_name ─────────────────────
        if "/" not in args.check:
            print("[!] --check must be in format: module/check_name "
                  "(e.g. headers/check_strict_transport_security)")
            sys.exit(1)
        module_name, check_name = args.check.split("/", 1)
        if module_name not in MODULE_FACTORIES:
            print(f"[!] Unknown module: {module_name}")
            sys.exit(1)
        if module_name not in CHECK_SPEC_REGISTRY:
            print(f"[!] Module '{module_name}' does not support per-check execution")
            sys.exit(1)
        specs = CHECK_SPEC_REGISTRY[module_name]
        matching = [s for s in specs if s.name == check_name]
        if not matching:
            available = ", ".join(s.name for s in specs)
            print(f"[!] Unknown check '{check_name}' in module '{module_name}'. "
                  f"Available: {available}")
            sys.exit(1)
        spec = matching[0]

        # Instantiate module
        if module_name == "auth":
            mod = AuthModule(credentials=args.auth, target=target)
        else:
            mod = MODULE_FACTORIES[module_name]()

        dis_fn = lambda c, t, _mod=mod: _mod.discover(c, t)
        tree = Sequence(module_name, children=[
            DiscoverAction(f"{module_name}_discover", dis_fn),
            CheckAdapter(spec.name, spec.fn, module_name),
        ])
        tree.tick(blackboard)
        print(f"[*] Running single check: {args.check}")

    elif args.check_level:
        children = []
        for name in module_map:
            if name in CHECK_SPEC_REGISTRY:
                children.append(CheckTreeBuilder.build_module(
                    name,
                    module_map[name].discover,
                    CHECK_SPEC_REGISTRY[name],
                ))
            else:
                children.append(ModuleAdapter(name, module_map[name]))
    else:
        children = [ModuleAdapter(name, mod) for name, mod in module_map.items()]

    if children:
        root = Sequence("scan", children=children)
        root.tick(blackboard)
    for r in blackboard.results:
        collector.add(r)

    duration = time.time() - start

    # Report
    reporter = Reporter(collector, target=target, duration=duration)
    reporter.to_terminal()

    json_path = reporter.to_json(args.output)
    print(f"\n[*] JSON report saved to: {json_path}")

    if args.log:
        log_path = reporter.to_log(args.log)
        print(f"[*] Log saved to: {log_path}")

    # Exit code: non-zero if any FAIL or ERROR
    fail_count = collector.by_status.get(TestStatus.FAIL, 0)
    error_count = collector.by_status.get(TestStatus.ERROR, 0)
    sys.exit(1 if (fail_count + error_count) > 0 else 0)


def run_secops(project_path: str):
    """Run the Senior SecOps toolkit: SAST scan + dependency assessment + compliance check."""
    from websec_test.security.scanner import SecurityScanner
    from websec_test.security.assessor import VulnerabilityAssessor
    from websec_test.security.checker import ComplianceChecker
    import os.path

    resolved = os.path.abspath(project_path)
    print(f"\n{'='*60}")
    print(f"  Senior SecOps Toolkit — {resolved}")
    print(f"{'='*60}")

    # ── Phase 1: SAST scan ──────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  Phase 1: SAST Security Scan")
    print(f"{'─'*60}")
    scanner = SecurityScanner(resolved, min_severity="high")
    findings = scanner.scan()
    if not findings:
        print("  [PASS] No high-severity findings")
    else:
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.file_path}:{f.line_number}")
            print(f"         {f.category}: {f.evidence[:100]}")
    print(f"  Summary: {len(findings)} findings"
          f"  (critical={sum(1 for x in findings if x.severity=='critical')},"
          f" high={sum(1 for x in findings if x.severity=='high')})")
    scan_code = SecurityScanner.exit_code(findings)

    # ── Phase 2: Dependency assessment ──────────────────────────────
    print(f"\n{'─'*60}")
    print("  Phase 2: Dependency Vulnerability Assessment")
    print(f"{'─'*60}")
    assessor = VulnerabilityAssessor(resolved, min_severity="high")
    dep_result = assessor.assess()
    if dep_result.count == 0:
        print("  [PASS] No vulnerabilities detected")
    else:
        for v in dep_result.vulnerabilities:
            print(f"  [{v.cve_id}] {v.package} {v.installed_version} (CVSS {v.cvss_score})")
            print(f"         {v.description}")
    print(f"  Risk score: {dep_result.risk_score:.1f}/100"
          f"  |  {dep_result.count} total"
          f"  (critical={dep_result.critical_count}, high={dep_result.high_count})")
    dep_code = VulnerabilityAssessor.exit_code(dep_result)

    # ── Phase 3: Compliance check ───────────────────────────────────
    print(f"\n{'─'*60}")
    print("  Phase 3: Compliance Framework Check")
    print(f"{'─'*60}")
    checker = ComplianceChecker(resolved)
    comp_result = checker.check()
    for fw in comp_result.frameworks:
        status = "PASS" if fw.score_pct >= 90 else ("WARN" if fw.score_pct >= 50 else "FAIL")
        print(f"  [{status}] {fw.framework.upper()}: {fw.score_pct:.0f}%"
              f" ({fw.passed_count}/{fw.total} controls passed)")
        for c in fw.controls:
            if not c.passed:
                print(f"         FAIL: {c.control_id} — {c.name}")
    print(f"  Overall: {comp_result.overall_score:.0f}%"
          f"  |  Worst: {comp_result.worst_framework}")
    comp_code = ComplianceChecker.exit_code(comp_result)

    # ── Final verdict ───────────────────────────────────────────────
    exit_codes = [scan_code, dep_code, comp_code]
    final_code = max(exit_codes)
    labels = {0: "PASS", 1: "WARN", 2: "FAIL"}
    print(f"\n{'='*60}")
    print(f"  Final verdict: {labels[final_code]}"
          f"  |  SAST: {labels[scan_code]}"
          f"  |  Deps: {labels[dep_code]}"
          f"  |  Compliance: {labels[comp_code]}")
    print(f"{'='*60}\n")
    sys.exit(final_code)


def main():
    args = parse_args()
    if args.secops is not None:
        run_secops(args.secops)
    elif args.target:
        run(args)
    else:
        print("[!] Specify --target <URL> for web testing or --secops [dir] for SAST scan")
        sys.exit(1)


if __name__ == "__main__":
    main()
