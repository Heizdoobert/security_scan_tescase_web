"""AI-assisted security analysis module — powered by Ollama qwen2.5-coder:7b.

Uses the local Ollama instance to perform intelligent security analysis:
  • Endpoint analysis and vulnerability hypothesis
  • Response pattern analysis
  • Configuration weakness identification
  • Security recommendation synthesis

Model parameters:
  temperature=0.6, top_p=0.95, top_k=20, min_p=0.0,
  presence_penalty=0.0, repetition_penalty=1.0
"""

from websec_test.client.ollama_client import OllamaModelConfig
from websec_test.client.session import SessionClient
from websec_test.modules._shared import Endpoint
from websec_test.results.models import TestResult, TestStatus, Severity

from websec_test.modules.ai_analysis.core.prompts import DISCOVERY_PROMPT, ANALYSIS_PROMPT
from websec_test.modules.ai_analysis.parsers.finding_parser import AiFinding, parse_severity, parse_findings
from websec_test.modules.ai_analysis.core.analyzer import AiAnalyzer

OLLAMA_CONFIG = OllamaModelConfig(
    model="qwen2.5-coder:7b",
    temperature=0.6,
    top_p=0.95,
    top_k=20,
    min_p=0.0,
    presence_penalty=0.0,
    repeat_penalty=1.0,
)

class Ai_analysisModule:
    """AI-assisted security analysis using Ollama qwen2.5-coder:7b."""

    def __init__(self):
        self._analyzer = AiAnalyzer(OLLAMA_CONFIG)
        self._discovery_findings: list[AiFinding] = []
        self._llm_raw_output: str = ""

    def discover(self, client: SessionClient, target: str) -> list[Endpoint]:
        """Query the LLM to analyze the target and discover potential issues."""
        if not self._analyzer.check_availability():
            return [Endpoint(url="/")]

        details = self._analyzer.get_target_details(client, "/")
        if not details:
            return [Endpoint(url="/")]
            
        status_code, headers, body = details
        prompt = DISCOVERY_PROMPT.format(
            target=target, status_code=status_code, headers=headers, body=body
        )

        output = self._analyzer.query(prompt)
        if not output:
            return [Endpoint(url="/")]

        self._llm_raw_output = output
        self._discovery_findings = parse_findings(output, default_endpoint="/")

        endpoints = []
        seen_urls: set[str] = set()
        for finding in self._discovery_findings:
            if finding.endpoint not in seen_urls:
                seen_urls.add(finding.endpoint)
                endpoints.append(Endpoint(url=finding.endpoint))
                
        return endpoints or [Endpoint(url="/")]

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]) -> list[TestResult]:
        """Run AI analysis on each endpoint and return results."""
        results: list[TestResult] = []

        if self._analyzer.error:
            results.append(self._create_error_result(target, self._analyzer.error))
            return results

        for finding in self._discovery_findings:
            results.append(self._create_finding_result(finding))

        for ep in endpoints:
            url = ep.url if ep.url.startswith("http") else f"{target.rstrip('/')}{ep.url}"
            details = self._analyzer.get_target_details(client, url)
            
            if not details:
                results.append(self._create_error_result(url, self._analyzer.error or "Unknown error", "check_endpoint_reachable"))
                continue

            status_code, headers, body = details
            prompt = ANALYSIS_PROMPT.format(
                url=url, method=getattr(ep, "method", "GET"),
                status_code=status_code, headers=headers, body=body
            )

            analysis = self._analyzer.query(prompt)
            if not analysis:
                results.append(self._create_error_result(url, self._analyzer.error or "Analysis failed", "check_ai_analysis"))
                continue

            if "NO_ISSUES_FOUND" in analysis:
                results.append(self._create_pass_result(url, analysis))
            else:
                ep_findings = parse_findings(analysis, default_endpoint=url)
                if ep_findings:
                    results.extend([self._create_finding_result(f, url) for f in ep_findings])
                else:
                    results.append(self._create_raw_result(url, analysis))

        results.append(self._create_summary_result(target))
        return results

    def _create_error_result(self, endpoint: str, evidence: str, test_name: str = "check_ollama_status") -> TestResult:
        return TestResult(
            module="ai_analysis", test_name=test_name,
            status=TestStatus.ERROR, severity=Severity.HIGH,
            endpoint=endpoint, evidence=evidence,
            recommendation="Fix Ollama connectivity"
        )

    def _create_finding_result(self, finding: AiFinding, url_override: str | None = None) -> TestResult:
        test_name = f"check_ai_{finding.title.lower().replace(' ', '_')[:40]}"
        return TestResult(
            module="ai_analysis", test_name=test_name,
            status=TestStatus.WARN if finding.severity in ("info", "low") else TestStatus.FAIL,
            severity=parse_severity(finding.severity),
            endpoint=url_override or finding.endpoint,
            evidence=f"[AI Analysis] {finding.evidence}",
            recommendation=finding.recommendation,
        )

    def _create_pass_result(self, endpoint: str, analysis: str) -> TestResult:
        return TestResult(
            module="ai_analysis", test_name="check_ai_analysis",
            status=TestStatus.PASS, severity=Severity.INFO,
            endpoint=endpoint, evidence=f"[AI Analysis] No security issues identified\n\nRaw analysis:\n{analysis[:500]}",
            recommendation="No action needed"
        )

    def _create_raw_result(self, endpoint: str, analysis: str) -> TestResult:
        return TestResult(
            module="ai_analysis", test_name="check_ai_analysis",
            status=TestStatus.INFO, severity=Severity.INFO,
            endpoint=endpoint, evidence=f"[AI Analysis — raw]\n{analysis[:800]}",
            recommendation="Review AI analysis output manually"
        )

    def _create_summary_result(self, target: str) -> TestResult:
        return TestResult(
            module="ai_analysis", test_name="check_ollama_status",
            status=TestStatus.PASS, severity=Severity.INFO,
            endpoint=target,
            evidence=(f"Ollama AI analysis completed successfully\n  Model: {OLLAMA_CONFIG.model}\n"
                      f"  Findings: {len(self._discovery_findings)} from discovery phase"),
            recommendation="No action needed — AI analysis module is operational"
        )

    def check_ollama_status(self, client: SessionClient, target: str, endpoint: Endpoint) -> TestResult:
        """Verify Ollama connectivity and model availability."""
        url = getattr(endpoint, "url", str(endpoint))
        if not self._analyzer.check_availability():
            return self._create_error_result(url, self._analyzer.error or "Unavailable")

        info = self._analyzer.ollama.model_info()
        model_details = ""
        if info:
            model_details = (
                f"\n  Model family: {info.get('details', {}).get('family', 'unknown')}"
                f"\n  Parameter size: {info.get('details', {}).get('parameter_size', 'unknown')}"
                f"\n  Quantization: {info.get('details', {}).get('quantization_level', 'unknown')}"
            )

        return TestResult(
            module="ai_analysis", test_name="check_ollama_status",
            status=TestStatus.PASS, severity=Severity.INFO,
            endpoint=url,
            evidence=(f"Ollama available\n  Server: {self._analyzer.ollama.base_url}\n"
                      f"  Model: {OLLAMA_CONFIG.model}{model_details}"),
            recommendation="No action needed"
        )

    def check_ai_endpoint_analysis(self, client: SessionClient, target: str, endpoint: Endpoint) -> TestResult:
        """Use AI to analyze a specific endpoint for security issues."""
        url = getattr(endpoint, "url", str(endpoint))
        full_url = url if url.startswith("http") else f"{target.rstrip('/')}{url}"

        if not self._analyzer.check_availability():
            return self._create_error_result(full_url, self._analyzer.error or "Unavailable", "check_ai_endpoint_analysis")

        details = self._analyzer.get_target_details(client, url)
        if not details:
            return self._create_error_result(full_url, self._analyzer.error or "Failed", "check_ai_endpoint_analysis")

        status_code, headers, body = details
        prompt = ANALYSIS_PROMPT.format(
            url=full_url, method=getattr(endpoint, "method", "GET"),
            status_code=status_code, headers=headers, body=body
        )

        analysis = self._analyzer.query(prompt)
        if not analysis:
            return self._create_error_result(full_url, self._analyzer.error or "Failed", "check_ai_endpoint_analysis")

        findings = parse_findings(analysis, default_endpoint=full_url)
        if not findings and "NO_ISSUES_FOUND" in analysis:
            return self._create_pass_result(full_url, analysis)

        combined_evidence = "\n\n".join(
            f"• {f.title} [{f.severity}]\n  Evidence: {f.evidence}\n  Fix: {f.recommendation}"
            for f in findings
        ) if findings else analysis[:500]

        worst_severity = Severity.INFO
        for f in findings:
            s = parse_severity(f.severity)
            if list(Severity).index(s) < list(Severity).index(worst_severity):
                worst_severity = s

        return TestResult(
            module="ai_analysis", test_name="check_ai_endpoint_analysis",
            status=TestStatus.FAIL if findings else TestStatus.INFO,
            severity=worst_severity if findings else Severity.INFO,
            endpoint=full_url,
            evidence=f"[AI Analysis — {len(findings)} finding(s)]\n{combined_evidence}",
            recommendation=findings[0].recommendation if findings else "Review AI output",
        )
