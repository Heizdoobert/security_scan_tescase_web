"""Prompts for the AI analysis module."""

SYSTEM_PROMPT = (
    "You are an expert web application security analyst. You analyze HTTP responses, "
    "headers, and application behavior to identify security vulnerabilities. "
    "Be precise and evidence-based. Format findings clearly."
)

DISCOVERY_PROMPT = """Analyze this target web application and list potential security concerns.

Target: {target}
HTTP Status: {status_code}
Response Headers:
{headers}

Response Body (first 2000 chars):
{body}

For each finding, respond in this EXACT format (one block per finding):
FINDING: <short title>
SEVERITY: <critical|high|medium|low|info>
EVIDENCE: <what confirms this>
ENDPOINT: <affected URL path>
RECOMMENDATION: <how to fix>

List ALL security-relevant observations."""

ANALYSIS_PROMPT = """Analyze this HTTP endpoint for security vulnerabilities.

URL: {url}
Method: {method}
HTTP Status: {status_code}
Response Headers:
{headers}

Response Body (first 1500 chars):
{body}

Check for:
1. Information disclosure (server versions, stack traces, debug info)
2. Missing security headers
3. Insecure configurations
4. Authentication/authorization weaknesses
5. Input handling issues

For each finding, respond in this EXACT format:
FINDING: <short title>
SEVERITY: <critical|high|medium|low|info>
EVIDENCE: <specific evidence from the response>
RECOMMENDATION: <actionable fix>

If no issues found, respond with: NO_ISSUES_FOUND"""
