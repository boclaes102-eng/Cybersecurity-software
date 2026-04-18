"""Directory and file brute-force scanner."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

import requests
from requests.exceptions import RequestException

from .models import Finding

_BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "logout", "api", "api/v1", "api/v2",
    "dashboard", "panel", "config", "configuration", "backup", "backups",
    "db", "database", "sql", "phpmyadmin", "adminer", "wp-admin",
    "wp-login.php", "wp-content", "wordpress", "cms", "drupal", "joomla",
    "uploads", "upload", "files", "file", "images", "img", "static", "assets",
    "css", "js", "scripts", "include", "includes", "lib", "library", "vendor",
    "src", "source", "app", "application", "web", "www", "public", "private",
    "secret", "secrets", "hidden", "test", "testing", "dev", "development",
    "staging", "prod", "production", "old", "new", "bak", "tmp", "temp",
    "cache", "logs", "log", "error", "errors", "debug", ".git", ".svn",
    ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "security.txt", "phpinfo.php", "info.php",
    "server-status", "server-info", "xmlrpc.php", "README", "readme.txt",
    "readme.md", "CHANGELOG", "LICENSE", "TODO", "install", "installer",
    "setup", "user", "users", "account", "accounts", "profile", "register",
    "signup", "signin", "auth", "oauth", "token", "reset", "forgot",
    "password", "pass", "cgi-bin", "bin", "shell", "cmd", "exec",
    "console", "terminal", "search", "query", "report", "reports",
    "download", "downloads", "export", "import", "data",
]

_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}


def scan(
    base_url: str,
    wordlist: Optional[str],
    extensions: list[str],
    threads: int,
    timeout: float,
    stop_event: threading.Event,
    on_finding: Callable[[Finding], None],
    on_progress: Callable[[str], None],
) -> list[Finding]:
    base_url = base_url.rstrip("/")
    session = requests.Session()
    session.headers["User-Agent"] = "CyberSuite/WAT DirScanner"

    if wordlist and Path(wordlist).exists():
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        paths = list(_BUILTIN_WORDLIST)

    expanded: list[str] = []
    for p in paths:
        expanded.append(p)
        for ext in extensions:
            if not p.endswith(ext):
                expanded.append(f"{p}{ext}")

    findings: list[Finding] = []
    total = len(expanded)
    checked = 0

    def check(path: str) -> Optional[Finding]:
        if stop_event.is_set():
            return None
        url = f"{base_url}/{path}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code in _INTERESTING_CODES:
                if r.status_code in (301, 302, 307):
                    severity = "INFO"
                elif r.status_code in (401, 403):
                    severity = "LOW"
                else:
                    severity = "MEDIUM"
                return Finding(
                    type="dir_found",
                    severity=severity,
                    url=url,
                    detail=f"HTTP {r.status_code}",
                    evidence={"status_code": r.status_code, "content_length": len(r.content)},
                )
        except RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, p): p for p in expanded}
        for fut in as_completed(futures):
            if stop_event.is_set():
                break
            checked += 1
            result = fut.result()
            if result:
                findings.append(result)
                on_finding(result)
            if checked % 50 == 0:
                on_progress(f"[*] Scanned {checked}/{total} paths…\n")

    return findings
