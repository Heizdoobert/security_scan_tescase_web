"""Dashboard — standalone HTML report generator for test results."""
from datetime import datetime
from pathlib import Path
from websec_test.results.models import TestStatus


class Dashboard:
    """Generates a self-contained HTML dashboard from a Reporter instance."""

    def __init__(self, reporter):
        self.reporter = reporter
        self.collector = reporter.collector

    def render(self, output_dir: str = "./reports") -> str:
        report = self.reporter._build_report()
        summary = report["summary"]
        results = report["results"]
        start_time = report["start_time"]
        end_time = report["end_time"]
        duration = report["duration_seconds"]

        pass_count = summary["pass"]
        fail_count = summary["fail"]
        warn_count = summary["warn"]
        error_count = summary["error"]
        total = summary["total"]

        pass_pct = round(pass_count / total * 100, 1) if total else 0
        fail_pct = round(fail_count / total * 100, 1) if total else 0

        status_icon = "pass" if fail_count == 0 else "fail"

        rows_html = ""
        for r in results:
            sev = r["severity"].upper()
            sev_badge = {"CRITICAL": "badge-critical", "HIGH": "badge-high",
                         "MEDIUM": "badge-medium", "LOW": "badge-info", "INFO": "badge-info"}.get(sev, "badge-info")
            status_label = r["status"].upper()
            status_class = "status-pass" if r["status"] == "pass" else \
                           "status-fail" if r["status"] == "fail" else \
                           "status-warn" if r["status"] == "warn" else "status-error"
            rows_html += f"""
            <tr>
                <td><span class="module-tag">{r["module"]}</span></td>
                <td>{r["test_name"]}</td>
                <td><span class="{status_class}">{status_label}</span></td>
                <td><span class="{sev_badge}">{sev}</span></td>
                <td class="cell-break">{r["expected"]}</td>
                <td class="cell-break">{r["actual"]}</td>
                <td class="cell-break">{r["endpoint"]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Security Test Dashboard — {report["target"]}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; padding: 24px; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; font-weight: 600; margin-bottom: 4px; }}
  .subtitle {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 24px; }}
  .subtitle span {{ margin-right: 20px; }}

  /* Summary cards */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
             gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 10px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;
                 letter-spacing: 0.5px; margin-top: 4px; }}
  .num-pass {{ color: #22c55e; }}
  .num-fail {{ color: #ef4444; }}
  .num-warn {{ color: #eab308; }}
  .num-error {{ color: #f97316; }}
  .num-total {{ color: #60a5fa; }}

  /* Overall verdict */
  .verdict {{ display: flex; align-items: center; gap: 12px;
             background: #1e293b; border-radius: 10px; padding: 16px 20px; margin-bottom: 24px; }}
  .verdict-icon {{ font-size: 2rem; }}
  .verdict-text {{ font-size: 1.1rem; font-weight: 600; }}
  .verdict-detail {{ color: #94a3b8; font-size: 0.85rem; }}

  /* Timeline */
  .timeline {{ background: #1e293b; border-radius: 10px; padding: 16px 20px; margin-bottom: 24px; }}
  .timeline-row {{ display: flex; justify-content: space-between; padding: 4px 0;
                  font-size: 0.85rem; }}
  .timeline-label {{ color: #94a3b8; }}
  .timeline-value {{ font-family: monospace; }}

  /* Table */
  .table-wrap {{ overflow-x: auto; background: #1e293b; border-radius: 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  th {{ background: #334155; color: #94a3b8; text-align: left; padding: 10px 12px;
       font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
       position: sticky; top: 0; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #334155; vertical-align: top; }}
  tr:hover td {{ background: #1e293b; }}
  tr:last-child td {{ border-bottom: none; }}

  .module-tag {{ background: #334155; color: #93c5fd; padding: 2px 8px; border-radius: 4px;
                font-size: 0.7rem; font-weight: 500; white-space: nowrap; }}
  .status-pass {{ color: #22c55e; font-weight: 600; }}
  .status-fail {{ color: #ef4444; font-weight: 600; }}
  .status-warn {{ color: #eab308; font-weight: 600; }}
  .status-error {{ color: #f97316; font-weight: 600; }}

  .badge-critical {{ color: #ef4444; font-weight: 600; }}
  .badge-high {{ color: #f97316; font-weight: 600; }}
  .badge-medium {{ color: #eab308; font-weight: 600; }}
  .badge-info {{ color: #60a5fa; }}

  .cell-break {{ word-break: break-word; max-width: 300px; }}

  .footer {{ text-align: center; color: #475569; font-size: 0.75rem; margin-top: 24px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Web Security Test Dashboard</h1>
  <div class="subtitle">
    <span>Target: {report["target"]}</span>
    <span>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
  </div>

  <!-- Summary cards -->
  <div class="summary">
    <div class="card"><div class="num num-total">{total}</div><div class="label">Total</div></div>
    <div class="card"><div class="num num-pass">{pass_count}</div><div class="label">Pass</div></div>
    <div class="card"><div class="num num-fail">{fail_count}</div><div class="label">Fail</div></div>
    <div class="card"><div class="num num-warn">{warn_count}</div><div class="label">Warn</div></div>
    <div class="card"><div class="num num-error">{error_count}</div><div class="label">Error</div></div>
  </div>

  <!-- Verdict -->
  <div class="verdict">
    <div class="verdict-icon">{'&#10003;' if status_icon == 'pass' else '&#10007;'}</div>
    <div>
      <div class="verdict-text" style="color: {'#22c55e' if status_icon == 'pass' else '#ef4444'}">
        {'ALL CHECKS PASSED' if status_icon == 'pass' else f'{fail_count} CHECK(S) FAILED'}
      </div>
      <div class="verdict-detail">{pass_pct}% pass rate &middot; {fail_pct}% failure rate</div>
    </div>
  </div>

  <!-- Timeline -->
  <div class="timeline">
    <div class="timeline-row">
      <span class="timeline-label">Start:</span>
      <span class="timeline-value">{start_time}</span>
    </div>
    <div class="timeline-row">
      <span class="timeline-label">End:</span>
      <span class="timeline-value">{end_time}</span>
    </div>
    <div class="timeline-row">
      <span class="timeline-label">Duration:</span>
      <span class="timeline-value">{duration:.2f}s</span>
    </div>
  </div>

  <!-- Results table -->
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Module</th><th>Check</th><th>Status</th><th>Severity</th>
        <th>Expected</th><th>Actual</th><th>Endpoint</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <div class="footer">Web Security Test Tool &mdash; Dashboard Report</div>
</div>
</body>
</html>"""

        path = Path(output_dir) / f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return str(path)
