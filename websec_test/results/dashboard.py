"""Dashboard — exports HTML + CSS + JS report for test results."""
from datetime import datetime
from pathlib import Path
from websec_test.results.models import TestStatus


class CSSBuilder:
    def build(self) -> str:
        return """*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
#app{max-width:1200px;margin:0 auto}
h1{font-size:1.3rem;font-weight:600;margin-bottom:4px}
h1 .tgt{color:#64748b;font-weight:400;font-size:.9rem}
.summary-bar{display:flex;gap:8px;margin:12px 0}
.stat{background:#1e293b;border-radius:8px;padding:10px 16px;font-size:.75rem;color:#94a3b8}
.stat .num{font-size:1.5rem;font-weight:700;display:block;margin-bottom:2px}
.total .num{color:#60a5fa}.passed .num{color:#22c55e}.failed .num{color:#ef4444}.warned .num{color:#eab308}.errored .num{color:#f97316}
.run-info{color:#64748b;font-size:.75rem;margin-bottom:12px;display:flex;gap:16px}
.verdict{padding:8px 14px;border-radius:6px;font-size:.85rem;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.verdict.pass{background:#052e16;color:#22c55e}.verdict.fail{background:#450a0a;color:#ef4444}.verdict.warn{background:#422006;color:#eab308}.verdict.error{background:#431407;color:#f97316}
.vbadge{font-size:1.1rem}
.filters{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.check-filters{display:flex;gap:12px;align-items:center}
.check-filters label{display:flex;align-items:center;gap:4px;font-size:.8rem;cursor:pointer;user-select:none}
.check-filters input{cursor:pointer}
.fp{color:#22c55e}.ff{color:#ef4444}.wf{color:#eab308}.ef{color:#f97316}
.other-filters{display:flex;gap:6px;flex-wrap:wrap}
.other-filters input,.other-filters select{padding:6px 10px;border-radius:5px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.78rem}
.other-filters input{width:200px}
#results-table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;font-size:.8rem}
#results-table thead{background:#1e293b}
#results-table th{background:#334155;color:#94a3b8;padding:10px 10px;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;text-align:left;white-space:nowrap;user-select:none;cursor:pointer}
#results-table th:hover{color:#e2e8f0}
.chkcol{width:28px;padding:4px!important}
.sortable .arrow{color:#64748b;margin-left:3px;font-size:.65rem}
.result-row td{padding:8px 10px;border-bottom:1px solid #334155}
.result-row.passed td{border-bottom:1px solid #1e293b}
.result-row.failed td{background:#1a0a0a}.result-row.warn td{background:#1a1500}.result-row.error td{background:#1a0d00}
.result-row.failed+.detail-row td{border-top:1px solid #334155}
.result-row:hover td{background:rgba(255,255,255,.03)!important}
.hidden{display:none!important}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600}
.badge.passed{background:#052e16;color:#22c55e}.badge.failed{background:#450a0a;color:#ef4444}.badge.warn{background:#422006;color:#eab308}.badge.error{background:#431407;color:#f97316}
.module-tag{background:#334155;color:#93c5fd;padding:2px 7px;border-radius:4px;font-size:.7rem}
.sev-critical{color:#ef4444;font-weight:600}.sev-high{color:#f97316;font-weight:600}.sev-medium{color:#eab308;font-weight:600}.sev-low,.sev-info{color:#60a5fa}
.toggle{display:inline-block;cursor:pointer;color:#64748b;font-size:.65rem;transition:transform .15s;user-select:none}
.toggle:hover{color:#e2e8f0}
.result-row.expanded .toggle{transform:rotate(90deg)}
.detail-row{display:none}
.detail-row.expanded{display:table-row}
.detail-row td{padding:0!important;background:#0f172a!important}
.detail-inner{padding:12px 14px 12px 40px;border-bottom:1px solid #334155}
.detail-table{width:100%;border-collapse:collapse;font-size:.78rem}
.detail-table td{padding:4px 8px!important;background:transparent!important;border:none!important;vertical-align:top}
.detail-table .dl{color:#64748b;width:120px;white-space:nowrap;font-weight:500}
.detail-table .dv{color:#e2e8f0;word-break:break-word}
.err-section{margin-top:8px}
.err-title{color:#ef4444;font-size:.75rem;font-weight:600;margin-bottom:4px}
.err-pre{background:#1e293b;color:#f87171;padding:8px 10px;border-radius:5px;font-family:'Cascadia Code','Fira Code',monospace;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word;border:1px solid #334155;max-height:200px;overflow-y:auto}
.rec-section{margin-top:6px;font-size:.78rem;color:#e2e8f0}
.ep-section{margin-top:4px;font-size:.78rem;color:#94a3b8}
#noMatch{text-align:center;padding:40px;color:#64748b;font-size:.9rem}
.footer{text-align:center;color:#475569;font-size:.7rem;margin-top:20px}
"""

class JSBuilder:
    def build(self) -> str:
        return """function toggleRow(id){
  var row=document.getElementById(id);
  var detail=document.querySelector('[data-parent="'+id+'"]');
  if(!detail) return;
  row.classList.toggle('expanded');
  detail.classList.toggle('expanded');
}

function applyFilters(){
  var q=document.getElementById('search').value.toLowerCase();
  var m=document.getElementById('moduleFilter').value;
  var v=document.getElementById('severityFilter').value;
  var checks={};
  document.querySelectorAll('.sf').forEach(function(cb){checks[cb.value]=cb.checked});
  var rows=document.querySelectorAll('#results-table tbody .result-row');
  var visible=0;
  rows.forEach(function(r){
    var status=r.classList.contains('pass')?'pass':r.classList.contains('fail')?'fail':r.classList.contains('warn')?'warn':r.classList.contains('error')?'error':'';
    var show=true;
    if(!checks[status]) show=false;
    if(q && !r.textContent.toLowerCase().includes(q)) show=false;
    if(m && r.querySelector('.module-tag') && r.querySelector('.module-tag').textContent!==m) show=false;
    if(v){
      var sevEl=r.querySelector('[class^="sev-"]');
      if(sevEl && sevEl.textContent.toLowerCase()!==v) show=false;
    }
    r.style.display=show?'':'none';
    var detail=document.querySelector('[data-parent="'+r.id+'"]');
    if(detail) detail.style.display=show && detail.classList.contains('expanded')?'':'none';
    if(show) visible++;
  });
  document.getElementById('noMatch').classList.toggle('hidden',visible>0);
}

// Sort by column
document.querySelectorAll('#results-table th.sortable').forEach(function(th){
  th.addEventListener('click',function(){
    var col=th.getAttribute('data-col');
    if(!col) return;
    var tbody=document.querySelector('#results-table tbody');
    var all=Array.from(tbody.querySelectorAll('tr'));
    var rows=all.filter(function(r){return r.classList.contains('result-row')});
    var dir=th._dir==='asc'?'desc':'asc';
    th._dir=dir;
    document.querySelectorAll('#results-table th .arrow').forEach(function(a){a.textContent=''});
    var arrow=document.createElement('span');
    arrow.className='arrow';
    arrow.textContent=dir==='asc'?' \\u25b2':' \\u25bc';
    th.appendChild(arrow);
    rows.sort(function(a,b){
      var getVal=function(r){
        if(col==='result') return r.querySelector('.badge')?r.querySelector('.badge').textContent.trim().toLowerCase():'';
        if(col==='testId') return (r.querySelector('.col-testId')||r.cells[2]).textContent.trim().toLowerCase();
        if(col==='module') return r.querySelector('.module-tag')?r.querySelector('.module-tag').textContent.trim().toLowerCase():'';
        if(col==='severity'){var se=r.querySelector('[class^="sev-"]');return se?se.textContent.trim().toLowerCase():'';}
        return '';
      };
      var va=getVal(a),vb=getVal(b);
      if(va<vb) return dir==='asc'?-1:1;
      if(va>vb) return dir==='asc'?1:-1;
      return 0;
    });
    rows.forEach(function(r){
      tbody.appendChild(r);
      var detail=document.querySelector('[data-parent="'+r.id+'"]');
      if(detail) tbody.appendChild(detail);
    });
  });
});
"""

def _time(s):
    return s[:19] if s and len(s) > 19 else s


def _h(val):
    """HTML-escape a value."""
    if val is None:
        return ""
    return str(val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class Dashboard:
    """Generates a standalone dashboard (3 files: HTML, CSS, JS) from a Reporter."""

    def __init__(self, reporter):
        self.reporter = reporter
        self.collector = reporter.collector

    def render(self, output_dir: str = "./reports", open_browser: bool = False, live: bool = False) -> str:
        """Generate HTML dashboard and return the path to the HTML file."""
        ts = self.reporter._start_time.strftime("%Y%m%d_%H%M%S")
        base = Path(output_dir)
        base.mkdir(parents=True, exist_ok=True)

        report = self.reporter._build_report()
        html_path = base / f"dashboard_{ts}.html"
        css_path = base / f"dashboard_{ts}.css"
        js_path = base / f"dashboard_{ts}.js"

        css_path.write_text(CSSBuilder().build(), encoding="utf-8")
        js_path.write_text(JSBuilder().build(), encoding="utf-8")
        html_path.write_text(self._html(report, f"dashboard_{ts}.css", f"dashboard_{ts}.js", live), encoding="utf-8")

        if open_browser:
            import webbrowser
            webbrowser.open(f"file://{html_path.resolve()}")

        return str(html_path)

    def _html(self, report: dict, css_file: str, js_file: str, live: bool = False) -> str:
        summary = report["summary"]
        results = report["results"]
        pass_pct = round(summary["pass"] / summary["total"] * 100, 1) if summary["total"] else 0
        verdict_cls = "fail" if summary["fail"] else ("error" if summary["error"] else ("warn" if summary["warn"] else "pass"))
        has_fail = "fail" if summary["fail"] else "pass"
        verdict_text = "ALL CHECKS PASSED" if has_fail == "pass" else f"{summary['fail']} CHECK(S) FAILED"

        table_body_html = ""
        for i, r in enumerate(results):
            table_body_html += self._row(i, r)
            table_body_html += self._detail(i, r)

        modules = sorted({r["module"] for r in results})
        mod_opts = "".join(f'<option value="{_h(m)}">{_h(m)}</option>' for m in modules)
        
        refresh_tag = '<meta http-equiv="refresh" content="2">' if live else ''
        live_badge = '<span class="tgt" style="color:#f97316;">[LIVE RUNNING...]</span>' if live else ''

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
{refresh_tag}
<title>Web Security Report — {_h(report["target"])}</title>
<link rel="stylesheet" href="{_h(css_file)}">
</head>
<body>
<div id="app">
  <h1>Security Scan Report <span class="tgt">{_h(report["target"])}</span> {live_badge}</h1>

  <div class="summary-bar">
    <div class="stat total"><span class="num">{summary["total"]}</span> Total</div>
    <div class="stat passed"><span class="num">{summary["pass"]}</span> Passed</div>
    <div class="stat failed"><span class="num">{summary["fail"]}</span> Failed</div>
    <div class="stat warned"><span class="num">{summary["warn"]}</span> Warnings</div>
    <div class="stat errored"><span class="num">{summary["error"]}</span> Errors</div>
  </div>

  <div class="run-info">
    <span>Start: {_h(_time(report["start_time"]))}</span>
    <span>End: {_h(_time(report["end_time"]))}</span>
    <span>Duration: {report["duration_seconds"]:.2f}s</span>
  </div>

  <div class="verdict {verdict_cls}">
    <span class="vbadge">{'&#10003;' if has_fail == 'pass' else '&#10007;'}</span>
    {verdict_text} &mdash; {pass_pct}% pass rate
  </div>

  <div class="filters">
    <div class="check-filters">
      <label><input type="checkbox" class="sf" value="pass" checked onchange="applyFilters()"> <span class="fp">Pass</span></label>
      <label><input type="checkbox" class="sf" value="fail" checked onchange="applyFilters()"> <span class="ff">Fail</span></label>
      <label><input type="checkbox" class="sf" value="warn" checked onchange="applyFilters()"> <span class="wf">Warnings</span></label>
      <label><input type="checkbox" class="sf" value="error" checked onchange="applyFilters()"> <span class="ef">Errors</span></label>
    </div>
    <div class="other-filters">
      <input type="text" id="search" placeholder="Search results..." oninput="applyFilters()">
      <select id="moduleFilter" onchange="applyFilters()">
        <option value="">All modules</option>
        {mod_opts}
      </select>
      <select id="severityFilter" onchange="applyFilters()">
        <option value="">All severities</option>
        <option value="critical">CRITICAL</option>
        <option value="high">HIGH</option>
        <option value="medium">MEDIUM</option>
        <option value="low">LOW</option>
        <option value="info">INFO</option>
      </select>
    </div>
  </div>

  <table id="results-table">
    <thead>
      <tr>
        <th class="chkcol"></th>
        <th class="sortable" data-col="result">Result</th>
        <th class="sortable" data-col="testId">Test</th>
        <th class="sortable" data-col="module">Module</th>
        <th class="sortable" data-col="severity">Severity</th>
      </tr>
    </thead>
    <tbody>
      {table_body_html}
    </tbody>
  </table>

  <div id="noMatch" class="hidden">No results match your filters.</div>
  <div class="footer">Web Security Test &mdash; generated {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
</div>
<script src="{_h(js_file)}"></script>
</body>
</html>"""

    def _row(self, idx, r):
        sev = r["severity"].upper()
        cls = r["status"]
        test_id = f"test_{idx}"
        expanded = "expanded" if cls == "fail" else ""
        return f'''<tr class="result-row {cls} {expanded}" id="{test_id}">
  <td class="chkcol"><span class="toggle" onclick="toggleRow('{test_id}')">&#9654;</span></td>
  <td class="col-result"><span class="badge {cls}">{cls.upper()}</span></td>
  <td class="col-testId">{_h(r["test_name"])}</td>
  <td class="col-module"><span class="module-tag">{_h(r["module"])}</span></td>
  <td class="col-severity"><span class="sev-{sev.lower()}">{sev}</span></td>
</tr>'''

    def _detail(self, idx, r):
        test_id = f"test_{idx}"
        cls = r["status"]
        expanded = "detail-row expanded" if cls == "fail" else "detail-row"
        exp = _h(r.get("expected", ""))
        act = _h(r.get("actual", ""))
        rec = _h(r.get("recommendation", ""))
        ep = _h(r.get("endpoint", ""))
        h_log = _h(r.get("http_log", ""))
        
        # Always show log section if 'act' has content
        err_title = "Error Details" if cls in ("fail", "error") else "Result Details"
        log_section = f"<div class=\"err-section\"><div class=\"err-title\">{err_title}</div><pre class=\"err-pre\">{act}</pre></div>" if act else ""
        
        http_section = f"<div class=\"err-section\"><div class=\"err-title\">HTTP Request & Response</div><pre class=\"err-pre\">{h_log}</pre></div>" if h_log else ""
        
        if cls == "pass":
            status_meaning = "&#128994; SECURE: The application passed this security check by successfully blocking the attack or correctly implementing the requirement."
            meaning_color = "#22c55e"
        elif cls == "fail":
            status_meaning = "&#128308; VULNERABLE: The application failed this security check because it allowed the attack or is missing the required security control."
            meaning_color = "#ef4444"
        elif cls == "warn":
            status_meaning = "&#128993; WARNING: The application might be vulnerable, requires manual review."
            meaning_color = "#eab308"
        else:
            status_meaning = "&#128992; ERROR: The test could not be completed successfully."
            meaning_color = "#f97316"
            
        meaning_html = f'<tr><td class="dl">Logic Explanation:</td><td class="dv" style="color: {meaning_color}; font-weight: 600;">{status_meaning}</td></tr>'

        return f'''<tr class="{expanded}" data-parent="{test_id}">
  <td colspan="5">
    <div class="detail-inner">
      <table class="detail-table">
        {meaning_html}
        <tr><td class="dl">Expected:</td><td class="dv">{exp}</td></tr>
        <tr><td class="dl">Actual:</td><td class="dv">{act}</td></tr>
        {('<tr><td class="dl">Recommendation:</td><td class="dv">' + rec + '</td></tr>') if rec else ''}
        {('<tr><td class="dl">Endpoint:</td><td class="dv">' + ep + '</td></tr>') if ep else ''}
      </table>
      {log_section}
      {http_section}
    </div>
  </td>
</tr>'''

