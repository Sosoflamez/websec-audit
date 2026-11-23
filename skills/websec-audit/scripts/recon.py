"""
Module 1 : Reconnaissance et identification des technologies.

Vérifications effectuées :
- En-têtes HTTP exposant serveur/framework (Server, X-Powered-By, etc.)
- Présence de robots.txt / sitemap.xml
- Fichiers .well-known
- Détection grossière de CMS/frameworks courants via empreintes de code source
  (balises meta generator, chemins statiques typiques)
"""
from __future__ import annotations

import re
from typing import List

from common import Finding, HttpClient, Severity

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "Drupal": [r"Drupal.settings", r'name="generator" content="Drupal'],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Symfony": [r"_sf2_attributes", r"symfony"],
    "Angular": [r"ng-version", r"<app-root"],
    "React": [r"data-reactroot", r"__NEXT_DATA__"],
    "Vue.js": [r"data-v-", r"__vue__"],
    "Django": [r"csrftoken", r"django"],
    "Express/Node": [r"X-Powered-By: Express"],
}

INTERESTING_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
]


def run(client: HttpClient) -> List[Finding]:
    findings: List[Finding] = []

    resp = client.get("/")
    body = resp.text if resp is not None else ""

    # En-têtes révélateurs
    exposed = {h: resp.headers[h] for h in INTERESTING_HEADERS if h in resp.headers}
    if exposed:
        findings.append(
            Finding(
                category="Reconnaissance",
                title="En-têtes HTTP révélant la pile technique",
                severity=Severity.INFO,
                evidence="; ".join(f"{k}: {v}" for k, v in exposed.items()),
                recommendation=(
                    "Supprimer ou masquer les en-têtes qui révèlent la version exacte du "
                    "serveur/framework (Server, X-Powered-By, ...) pour réduire la surface "
                    "d'information offerte à un attaquant."
                ),
                url=client.url("/"),
            )
        )

    # Détection de technologies par signature
    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                detected.append(tech)
                break
    if detected:
        findings.append(
            Finding(
                category="Reconnaissance",
                title="Technologies détectées côté client",
                severity=Severity.INFO,
                evidence=", ".join(sorted(set(detected))),
                recommendation=(
                    "Informatif : vérifier que les versions utilisées sont à jour et "
                    "surveiller les CVE connues pour ces technologies."
                ),
                url=client.url("/"),
            )
        )

    # robots.txt / sitemap.xml
    for path in ("/robots.txt", "/sitemap.xml"):
        r = client.get(path)
        if r.status_code == 200 and len(r.text.strip()) > 0:
            findings.append(
                Finding(
                    category="Reconnaissance",
                    title=f"{path} accessible",
                    severity=Severity.INFO,
                    evidence=r.text[:300],
                    recommendation=(
                        "Vérifier que ce fichier ne révèle pas de chemins sensibles "
                        "(panneaux d'admin, zones internes)."
                    ),
                    url=client.url(path),
                )
            )

    # .well-known
    r = client.get("/.well-known/security.txt")
    if r.status_code == 200:
        findings.append(
            Finding(
                category="Reconnaissance",
                title="security.txt présent",
                severity=Severity.INFO,
                evidence=r.text[:300],
                recommendation="Bonne pratique déjà en place (politique de disclosure).",
                url=client.url("/.well-known/security.txt"),
            )
        )

    return findings
