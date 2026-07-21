"""Finding parsers and models for the AI analysis module."""
import re
from dataclasses import dataclass
from websec_test.results.models import Severity

@dataclass
class AiFinding:
    """A single parsed finding from the LLM response."""
    title: str
    severity: str
    evidence: str
    endpoint: str
    recommendation: str

def parse_severity(raw: str) -> Severity:
    """Map a raw severity string to the ``Severity`` enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(raw.strip().lower(), Severity.MEDIUM)

def parse_findings(text: str, default_endpoint: str = "/") -> list[AiFinding]:
    """Parse structured findings from the LLM response text."""
    findings: list[AiFinding] = []
    blocks = re.split(r'(?=FINDING:)', text)
    for block in blocks:
        block = block.strip()
        if not block.startswith("FINDING:"):
            continue
        title_m = re.search(r'FINDING:\s*(.+?)(?:\n|$)', block)
        sev_m = re.search(r'SEVERITY:\s*(.+?)(?:\n|$)', block)
        ev_m = re.search(r'EVIDENCE:\s*(.+?)(?:\n(?=\w+:)|$)', block, re.DOTALL)
        ep_m = re.search(r'ENDPOINT:\s*(.+?)(?:\n|$)', block)
        rec_m = re.search(r'RECOMMENDATION:\s*(.+?)(?:\n(?=\w+:)|$)', block, re.DOTALL)

        findings.append(AiFinding(
            title=title_m.group(1).strip() if title_m else "Unknown finding",
            severity=sev_m.group(1).strip() if sev_m else "medium",
            evidence=ev_m.group(1).strip() if ev_m else block[:200],
            endpoint=ep_m.group(1).strip() if ep_m else default_endpoint,
            recommendation=rec_m.group(1).strip() if rec_m else "Review manually",
        ))
    return findings
