"""SSL/TLS security test module.

Checks certificate validity, weak protocol support, and HSTS preload readiness
using Python stdlib ssl + socket (no extra dependencies).
"""
import re
import socket
import ssl
from collections import namedtuple
from datetime import datetime
from urllib.parse import urlparse

from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["host", "port"])


class SslTlsModule:
    """Test SSL/TLS configuration: cert validity, weak protocols, HSTS preload."""

    def discover(self, client: SessionClient, target: str):
        """Extract hostname and port from the target URL."""
        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        port = parsed.port or 443
        return [Endpoint(host=host, port=port)]

    def _check_certificate(self, host: str, port: int) -> list[TestResult]:
        """Connect with TLS and inspect the server certificate."""
        results = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        results.append(TestResult(
                            module="ssl_tls", test_name="certificate_valid",
                            status=TestStatus.FAIL, severity=Severity.HIGH,
                            endpoint=f"{host}:{port}",
                            evidence="No certificate returned",
                            recommendation="Install a valid TLS certificate",
                        ))
                        return results

                    # Check expiration
                    not_after = cert.get("notAfter", "")
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.now():
                            results.append(TestResult(
                                module="ssl_tls", test_name="certificate_valid",
                                status=TestStatus.FAIL, severity=Severity.CRITICAL,
                                endpoint=f"{host}:{port}",
                                evidence=f"Certificate expired on {not_after}",
                                recommendation="Renew the TLS certificate",
                            ))
                        else:
                            results.append(TestResult(
                                module="ssl_tls", test_name="certificate_valid",
                                status=TestStatus.PASS, severity=Severity.HIGH,
                                endpoint=f"{host}:{port}",
                                evidence=f"Certificate valid until {not_after}",
                                recommendation="No action needed",
                            ))
                    except ValueError:
                        results.append(TestResult(
                            module="ssl_tls", test_name="certificate_valid",
                            status=TestStatus.WARN, severity=Severity.MEDIUM,
                            endpoint=f"{host}:{port}",
                            evidence=f"Could not parse expiry: {not_after}",
                            recommendation="Verify certificate expiry manually",
                        ))
        except ssl.SSLCertVerificationError as e:
            results.append(TestResult(
                module="ssl_tls", test_name="certificate_valid",
                status=TestStatus.FAIL, severity=Severity.HIGH,
                endpoint=f"{host}:{port}",
                evidence=f"Certificate verification failed: {e}",
                recommendation="Install a valid TLS certificate from a trusted CA",
            ))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            results.append(TestResult(
                module="ssl_tls", test_name="certificate_valid",
                status=TestStatus.ERROR, severity=Severity.HIGH,
                endpoint=f"{host}:{port}",
                evidence=f"Connection failed: {e}",
                recommendation="Ensure the server is reachable on port {port}",
            ))
        return results

    def _check_weak_protocols(self, host: str, port: int) -> list[TestResult]:
        """Try connecting with weak TLS/SSL protocols to check if they're enabled."""
        results = []
        protocol_checks = [
            ("TLS 1.0", ssl.PROTOCOL_TLSv1),
        ]

        for name, proto in protocol_checks:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        results.append(TestResult(
                            module="ssl_tls", test_name=f"weak_protocol_{name.lower().replace(' ', '_')}",
                            status=TestStatus.FAIL, severity=Severity.HIGH,
                            endpoint=f"{host}:{port}",
                            evidence=f"{name} connection succeeded (version: {ssock.version()})",
                            recommendation=f"Disable {name} — only allow TLS 1.2+",
                        ))
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                results.append(TestResult(
                    module="ssl_tls", test_name=f"weak_protocol_{name.lower().replace(' ', '_')}",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=f"{host}:{port}",
                    evidence=f"{name} connection rejected",
                    recommendation="No action needed",
                ))

        return results

    def _check_hsts_preload(self, client: SessionClient) -> TestResult:
        """Check if HSTS header includes the preload directive."""
        resp = client.get("/")
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts and "preload" in hsts.lower():
            return TestResult(
                module="ssl_tls", test_name="hsts_preload",
                status=TestStatus.PASS, severity=Severity.MEDIUM,
                endpoint="/",
                evidence=f"HSTS with preload: {hsts[:100]}",
                recommendation="No action needed",
            )
        elif hsts:
            return TestResult(
                module="ssl_tls", test_name="hsts_preload",
                status=TestStatus.WARN, severity=Severity.MEDIUM,
                endpoint="/",
                evidence=f"HSTS present but no preload: {hsts[:100]}",
                recommendation="Add 'preload' to Strict-Transport-Security header",
            )
        else:
            return TestResult(
                module="ssl_tls", test_name="hsts_preload",
                status=TestStatus.FAIL, severity=Severity.MEDIUM,
                endpoint="/",
                evidence="No HSTS header found",
                recommendation="Add Strict-Transport-Security header with preload",
            )

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Run all SSL/TLS checks."""
        results = []
        for ep in endpoints:
            results.extend(self._check_certificate(ep.host, ep.port))
            results.extend(self._check_weak_protocols(ep.host, ep.port))
            results.append(self._check_hsts_preload(client))
        return results

