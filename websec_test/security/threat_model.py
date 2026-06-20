"""Threat modeler — STRIDE classification and DREAD scoring for DFD elements.

No external dependencies. Applies STRIDE per DFD element type, scores
threats with DREAD, and generates structured threat analysis output.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── STRIDE definitions ──

STRIDE_DESCRIPTIONS = {
    "Spoofing": "Attacker impersonates a user, system, or component.",
    "Tampering": "Unauthorized modification of data or code in transit or at rest.",
    "Repudiation": "User denies performing an action without proof to the contrary.",
    "Information Disclosure": "Exposure of sensitive data to unauthorized parties.",
    "Denial of Service": "System becomes unavailable to legitimate users.",
    "Elevation of Privilege": "Unprivileged user gains access to restricted functionality.",
}

# Per-DFD-element STRIDE applicability matrix
# (external entity, process, data store, data flow)
STRIDE_MATRIX: Dict[str, List[str]] = {
    "external-entity": ["Spoofing", "Repudiation"],
    "process": ["Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "Denial of Service",
                "Elevation of Privilege"],
    "data-store": ["Tampering", "Repudiation",
                   "Information Disclosure", "Denial of Service"],
    "data-flow": ["Tampering", "Information Disclosure", "Denial of Service"],
}

ELEMENT_DESCRIPTIONS = {
    "external-entity": "External Entity -- user, external system, or service outside your control",
    "process": "Process -- application component, service, or function",
    "data-store": "Data Store -- database, file system, or cache",
    "data-flow": "Data Flow -- direction of data movement between elements",
}


@dataclass
class ThreatFinding:
    """A single identified threat with STRIDE classification and DREAD score."""
    element_type: str
    element_name: str
    stride_category: str
    threat_description: str
    dread_score: float  # 1.0 – 10.0
    severity: str       # "critical" | "high" | "medium"
    recommendation: str


@dataclass
class ThreatModelResult:
    """Aggregated result of a threat modeling session."""
    target: str
    threats: List[ThreatFinding]

    @property
    def count(self) -> int:
        return len(self.threats)

    @property
    def critical_count(self) -> int:
        return sum(1 for t in self.threats if t.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for t in self.threats if t.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for t in self.threats if t.severity == "medium")


# ── Built-in threat patterns (STRIDE per element type) ──

THREAT_PATTERNS: Dict[str, List[Dict]] = {
    "external-entity": [
        {
            "stride": "Spoofing",
            "threat": "Attacker impersonates a legitimate user or external system",
            "recommendation": "Implement strong authentication (MFA, certificate-based identity)",
        },
        {
            "stride": "Repudiation",
            "threat": "User denies performing an action with no audit trail",
            "recommendation": "Implement audit logging with timestamps and user identity",
        },
    ],
    "process": [
        {
            "stride": "Spoofing",
            "threat": "Process identity can be forged by an attacker",
            "recommendation": "Use mTLS or API keys for service-to-service authentication",
        },
        {
            "stride": "Tampering",
            "threat": "Attacker modifies data or code within the process",
            "recommendation": "Validate all input; use integrity checks (HMAC, signatures)",
        },
        {
            "stride": "Repudiation",
            "threat": "Process actions cannot be attributed to a specific caller",
            "recommendation": "Log requests with caller identity and timestamps",
        },
        {
            "stride": "Information Disclosure",
            "threat": "Process leaks sensitive data in error messages or responses",
            "recommendation": "Use generic error messages; strip sensitive data from responses",
        },
        {
            "stride": "Denial of Service",
            "threat": "Process is overwhelmed by excessive requests",
            "recommendation": "Implement rate limiting, resource quotas, and auto-scaling",
        },
        {
            "stride": "Elevation of Privilege",
            "threat": "Caller gains unauthorized access to restricted functionality",
            "recommendation": "Enforce role-based access control on every endpoint",
        },
    ],
    "data-store": [
        {
            "stride": "Tampering",
            "threat": "Data at rest is modified by an unauthorized party",
            "recommendation": "Use encryption at rest and integrity verification",
        },
        {
            "stride": "Repudiation",
            "threat": "Data access or modification cannot be traced",
            "recommendation": "Enable audit logging for all data access and modifications",
        },
        {
            "stride": "Information Disclosure",
            "threat": "Sensitive data stored without encryption is exposed",
            "recommendation": "Encrypt sensitive data at rest (AES-256-GCM)",
        },
        {
            "stride": "Denial of Service",
            "threat": "Data store is flooded with queries or filled with junk data",
            "recommendation": "Set connection limits, query timeouts, and storage quotas",
        },
    ],
    "data-flow": [
        {
            "stride": "Tampering",
            "threat": "Data in transit is intercepted and modified",
            "recommendation": "Use TLS 1.2+ with certificate validation for all data in transit",
        },
        {
            "stride": "Information Disclosure",
            "threat": "Data in transit is intercepted and read by an attacker",
            "recommendation": "Encrypt all data flows with TLS; avoid plain-text protocols",
        },
        {
            "stride": "Denial of Service",
            "threat": "Network flow is flooded or disrupted",
            "recommendation": "Implement network-level rate limiting and DDoS protection",
        },
    ],
}

# Default DREAD scores per STRIDE category
# (damage, reproducibility, exploitability, affected_users, discoverability)
DREAD_DEFAULTS: Dict[str, Tuple[int, int, int, int, int]] = {
    "Spoofing": (8, 6, 5, 8, 5),
    "Tampering": (9, 5, 6, 9, 4),
    "Repudiation": (5, 8, 4, 7, 6),
    "Information Disclosure": (7, 7, 6, 8, 7),
    "Denial of Service": (6, 7, 5, 9, 5),
    "Elevation of Privilege": (9, 4, 5, 9, 4),
}


class ThreatModeler:
    """Analyze DFD elements for threats using STRIDE and DREAD."""

    VALID_ELEMENT_TYPES = {"external-entity", "process", "data-store", "data-flow"}

    @staticmethod
    def stride_categories(element_type: str) -> List[str]:
        """Return STRIDE categories applicable to a given DFD element type."""
        if element_type not in STRIDE_MATRIX:
            return []
        return STRIDE_MATRIX[element_type]

    @staticmethod
    def dread_score(
        damage: int,
        reproducibility: int,
        exploitability: int,
        affected_users: int,
        discoverability: int,
    ) -> float:
        """Compute DREAD score as average of five category ratings (1–10)."""
        raw = (damage + reproducibility + exploitability
               + affected_users + discoverability) / 5.0
        return round(raw, 1)

    @staticmethod
    def dread_severity(score: float) -> str:
        """Map DREAD score to severity level."""
        if score >= 7.0:
            return "critical"
        elif score >= 4.0:
            return "high"
        return "medium"

    @staticmethod
    def dread_label(score: float) -> str:
        """Return action label for a DREAD score."""
        if score >= 7.0:
            return "Named mitigation owner required. Must be addressed before release."
        elif score >= 4.0:
            return "Mitigation plan required. Track in backlog with SLA."
        return "Accept risk or add compensating control."

    @staticmethod
    def assess_element(
        element_type: str,
        element_name: str = "",
    ) -> List[ThreatFinding]:
        """Run STRIDE + DREAD analysis on a single DFD element."""
        findings: List[ThreatFinding] = []
        patterns = THREAT_PATTERNS.get(element_type, [])

        for pat in patterns:
            stride = pat["stride"]
            defaults = DREAD_DEFAULTS.get(stride, (5, 5, 5, 5, 5))
            score = ThreatModeler.dread_score(*defaults)
            severity = ThreatModeler.dread_severity(score)

            finding = ThreatFinding(
                element_type=element_type,
                element_name=element_name or element_type,
                stride_category=stride,
                threat_description=pat["threat"],
                dread_score=score,
                severity=severity,
                recommendation=pat["recommendation"],
            )
            findings.append(finding)

        return findings

    @staticmethod
    def assess_all(
        target: str,
        element_types: Optional[List[str]] = None,
    ) -> ThreatModelResult:
        """Analyze all specified DFD element types (or all if none specified)."""
        if element_types is None:
            element_types = list(ThreatModeler.VALID_ELEMENT_TYPES)

        all_threats: List[ThreatFinding] = []
        for etype in element_types:
            if etype in ThreatModeler.VALID_ELEMENT_TYPES:
                all_threats.extend(ThreatModeler.assess_element(etype))

        return ThreatModelResult(target=target, threats=all_threats)

    @staticmethod
    def exit_code(result: ThreatModelResult) -> int:
        """Determine exit code from threat model result.

        0 = no critical threats (pass)
        1 = high threats only (warn)
        2 = any critical threats (fail)
        """
        if result.critical_count > 0:
            return 2
        if result.high_count > 0:
            return 1
        return 0
