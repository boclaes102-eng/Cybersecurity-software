"""HTTP security header analysis."""
from __future__ import annotations

from typing import Callable

import requests
from requests.exceptions import RequestException

from .models import Finding

_REQUIRED_HEADERS: list[tuple[str, str, str, str]] = [
    (
        "Strict-Transport-Security", "HIGH",
        "HSTS not set — browser may downgrade to HTTP",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "Content-Security-Policy", "HIGH",
        "CSP not set — XSS attacks have no browser-level mitigation",
        "Content-Security-Policy: default-src 'self'",
    ),
    (
        "X-Frame-Options", "MEDIUM",
        "Clickjacking protection missing",
        "X-Frame-Options: DENY",
    ),
    (
        "X-Content-Type-Options", "MEDIUM",
        "MIME-type sniffing not disabled",
        "X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy", "LOW",
        "Full URL leaked in Referer header on cross-origin requests",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy", "LOW",
        "Permissions-Policy not set — camera/mic/geolocation unrestricted",
        "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
]

_INFO_LEAK_HEADERS: dict[str, str] = {
    "X-Powered-By":      "Server technology disclosed — useful for attacker fingerprinting",
    "Server":            "Web server version exposed in Server header",
    "X-AspNet-Version":  "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
}


def analyze(
    url: str,
    timeout: float,
    on_finding: Callable[[Finding], None],
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        r = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "CyberSuite/WAT HeaderAnalyzer"},
        )
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        for name, severity, detail, hint in _REQUIRED_HEADERS:
            if name.lower() not in headers_lower:
                f = Finding(
                    type="header_missing",
                    severity=severity,
                    url=url,
                    detail=f"Missing {name} — {detail}",
                    evidence={"fix": hint},
                )
            else:
                f = Finding(
                    type="header_present",
                    severity="INFO",
                    url=url,
                    detail=f"✓ {name}: {headers_lower[name.lower()]}",
                )
            findings.append(f)
            on_finding(f)

        for name, detail in _INFO_LEAK_HEADERS.items():
            if name.lower() in headers_lower:
                f = Finding(
                    type="header_weak",
                    severity="LOW",
                    url=url,
                    detail=f"Info leak — {name}: {headers_lower[name.lower()]}",
                    evidence={"header_value": headers_lower[name.lower()], "detail": detail},
                )
                findings.append(f)
                on_finding(f)

    except RequestException as exc:
        f = Finding(type="error", severity="INFO", url=url, detail=f"Request failed: {exc}")
        findings.append(f)
        on_finding(f)

    return findings
