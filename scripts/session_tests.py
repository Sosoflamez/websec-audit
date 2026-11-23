"""
Module 4 : Tests de gestion des sessions.

Vérifie les attributs des cookies de session (HttpOnly, Secure, SameSite),
et si l'identifiant de session change après une connexion réussie (si des
identifiants de test sont fournis) pour détecter une fixation de session.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from common import Finding, HttpClient, Severity


def _cookie_findings(client: HttpClient, resp) -> List[Finding]:
    findings = []
    for cookie in client.session.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure manquant")
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly", False)  # type: ignore
        if not has_httponly:
            issues.append("HttpOnly manquant")
        samesite = cookie._rest.get("SameSite")  # type: ignore
        if not samesite:
            issues.append("SameSite manquant")
        elif samesite.lower() == "none" and not cookie.secure:
            issues.append("SameSite=None sans Secure")

        if issues and _looks_like_session_cookie(cookie.name):
            findings.append(
                Finding(
                    category="Gestion des sessions",
                    title=f"Cookie de session '{cookie.name}' mal protégé",
                    severity=Severity.MEDIUM if "HttpOnly manquant" in issues else Severity.LOW,
                    evidence=f"Attributs manquants/faibles: {', '.join(issues)}",
                    recommendation=(
                        "Définir les cookies de session avec HttpOnly, Secure (si "
                        "HTTPS) et SameSite=Lax ou Strict pour limiter le vol de "
                        "session via XSS ou les attaques CSRF."
                    ),
                    url=client.base_url,
                )
            )
    return findings


def _looks_like_session_cookie(name: str) -> bool:
    lname = name.lower()
    return any(k in lname for k in ("session", "sid", "auth", "token", "jwt", "connect.sid"))


def run(
    client: HttpClient,
    login_path: str = "/login",
    credentials: Optional[Tuple[str, str]] = None,
) -> List[Finding]:
    findings: List[Finding] = []

    resp = client.get("/")
    findings.extend(_cookie_findings(client, resp))

    if credentials:
        pre_login_cookies = {c.name: c.value for c in client.session.cookies}
        username, password = credentials
        client.post(login_path, data={"username": username, "password": password}, allow_redirects=True)
        post_login_cookies = {c.name: c.value for c in client.session.cookies}

        unchanged = [
            name
            for name in pre_login_cookies
            if _looks_like_session_cookie(name)
            and name in post_login_cookies
            and pre_login_cookies[name] == post_login_cookies[name]
        ]
        if unchanged:
            findings.append(
                Finding(
                    category="Gestion des sessions",
                    title="L'identifiant de session ne change pas après connexion",
                    severity=Severity.HIGH,
                    evidence=f"Cookies inchangés après login: {unchanged}",
                    recommendation=(
                        "Régénérer l'identifiant de session lors de l'authentification "
                        "(login) et de l'élévation de privilège, pour empêcher les "
                        "attaques de fixation de session."
                    ),
                    url=client.url(login_path),
                )
            )

    return findings
