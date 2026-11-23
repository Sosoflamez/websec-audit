"""
Utilitaires communs pour le skill websec-audit.

Fournit :
- Finding / Severity : structure standard pour les résultats
- HttpClient : wrapper autour de requests avec rate-limiting et user-agent dédié
- get_browser_context : helper Playwright pour obtenir un navigateur Chromium headless
"""
from __future__ import annotations

import dataclasses
import time
import urllib.parse
from enum import Enum
from typing import Optional

import requests

USER_AGENT = "websec-audit/1.0 (+https://github.com/; non-destructive security scan)"

DEFAULT_TIMEOUT = 10
DEFAULT_DELAY_SECONDS = 0.3  # throttling entre requêtes pour rester "poli"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclasses.dataclass
class Finding:
    category: str
    title: str
    severity: Severity
    evidence: str
    recommendation: str
    url: Optional[str] = None

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "url": self.url,
        }


class HttpClient:
    """Client HTTP throttlé, utilisé par tous les modules de test."""

    def __init__(self, base_url: str, delay: float = DEFAULT_DELAY_SECONDS, timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.request_count = 0

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))

    def _throttle(self):
        if self.request_count > 0:
            time.sleep(self.delay)
        self.request_count += 1

    def get(self, path: str = "", **kwargs) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        return self.session.get(self.url(path), **kwargs)

    def post(self, path: str = "", **kwargs) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(self.url(path), **kwargs)

    def request(self, method: str, path: str = "", **kwargs) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, self.url(path), **kwargs)


def get_playwright_browser(playwright, headless: bool = True):
    """Retourne (browser, context, page) Chromium prêts à l'emploi."""
    browser = playwright.chromium.launch(headless=headless)
    context = browser.new_context(user_agent=USER_AGENT)
    page = context.new_page()
    return browser, context, page
