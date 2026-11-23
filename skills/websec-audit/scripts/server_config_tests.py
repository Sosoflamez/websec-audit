"""
Module 10 : Tests de configuration serveur.

Vérifie les en-têtes de sécurité recommandés par le guide, l'imposition
HTTPS/HSTS, le listing de répertoires, et les pages d'erreur verbeuses.
"""
from __future__ import annotations

from typing import List

from common import Finding, HttpClient, Severity

SECURITY_HEADERS = {
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
    "Strict-Transport-Security": Severity.MEDIUM,
    "X-Frame-Options": Severity.LOW,
}


def run(client: HttpClient) -> List[Finding]:
    findings: List[Finding] = []

    resp = client.get("/")

    for header, severity in SECURITY_HEADERS.items():
        if header not in resp.headers:
            # HSTS n'a de sens qu'en HTTPS
            if header == "Strict-Transport-Security" and not client.base_url.startswith("https"):
                continue
            findings.append(
                Finding(
                    category="Configuration serveur",
                    title=f"En-tête de sécurité manquant : {header}",
                    severity=severity,
                    evidence=f"Absent de la réponse sur {client.url('/')}",
                    recommendation=_recommendation_for(header),
                    url=client.url("/"),
                )
            )

    # Listing de répertoire
    for path in ("/uploads/", "/static/", "/assets/", "/files/", "/backup/"):
        r = client.get(path)
        if r.status_code == 200 and ("Index of /" in r.text or "<title>Directory listing" in r.text):
            findings.append(
                Finding(
                    category="Configuration serveur",
                    title=f"Listing de répertoire activé sur {path}",
                    severity=Severity.MEDIUM,
                    evidence=r.text[:200],
                    recommendation=(
                        "Désactiver le listing de répertoire côté serveur web "
                        "(ex: `Options -Indexes` sous Apache, `autoindex off;` sous Nginx)."
                    ),
                    url=client.url(path),
                )
            )

    # Méthode TRACE (XST)
    try:
        r = client.request("TRACE", "/")
        if r.status_code not in (404, 405, 501):
            findings.append(
                Finding(
                    category="Configuration serveur",
                    title="Méthode HTTP TRACE activée",
                    severity=Severity.LOW,
                    evidence=f"TRACE / -> HTTP {r.status_code}",
                    recommendation="Désactiver la méthode TRACE sur le serveur web (risque de Cross-Site Tracing).",
                    url=client.url("/"),
                )
            )
    except Exception:
        pass

    # Page d'erreur verbeuse (404 personnalisée vs stack trace)
    r = client.get("/sectest-page-inexistante-" + "x" * 20)
    verbose_markers = ["Traceback (most recent call last)", "Fatal error:", "at System.", "Exception in thread", "Whitelabel Error Page"]
    found_marker = next((m for m in verbose_markers if m in r.text), None)
    if found_marker:
        findings.append(
            Finding(
                category="Configuration serveur",
                title="Page d'erreur révélant des détails techniques (stack trace)",
                severity=Severity.MEDIUM,
                evidence=f"Marqueur détecté: '{found_marker}' sur une page 404/erreur",
                recommendation=(
                    "Configurer des pages d'erreur génériques en production ; conserver "
                    "les traces détaillées uniquement dans les journaux internes protégés."
                ),
                url=client.url("/sectest-page-inexistante"),
            )
        )

    return findings


def _recommendation_for(header: str) -> str:
    return {
        "Content-Security-Policy": (
            "Déployer une CSP adaptée (même en mode Report-Only au départ) pour "
            "limiter l'impact d'une XSS éventuelle."
        ),
        "X-Content-Type-Options": "Ajouter 'X-Content-Type-Options: nosniff' pour empêcher le MIME-sniffing.",
        "Referrer-Policy": "Ajouter une politique Referrer-Policy adaptée (ex: strict-origin-when-cross-origin).",
        "Permissions-Policy": "Restreindre les API navigateur sensibles non utilisées par l'application.",
        "Strict-Transport-Security": "Activer HSTS après validation du déploiement HTTPS complet.",
        "X-Frame-Options": "Ajouter 'X-Frame-Options: DENY' ou une CSP frame-ancestors pour limiter le clickjacking.",
    }.get(header, "Ajouter cet en-tête de sécurité.")
