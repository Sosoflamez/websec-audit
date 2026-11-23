"""
Module 11 : Tests de fuite de données.

Vérifie l'exposition de fichiers sensibles courants (.env, .git, sauvegardes,
dumps) et recherche des motifs de secrets (clé API, mot de passe) dans le
JS/HTML exposé publiquement. Ne tente jamais d'utiliser une clé trouvée ;
se contente de signaler sa présence et son emplacement (valeur masquée dans
le rapport).
"""
from __future__ import annotations

import re
from typing import List

from common import Finding, HttpClient, Severity

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.zip",
    "/backup.sql",
    "/backup.sql.gz",
    "/dump.sql",
    "/config.php.bak",
    "/web.config.bak",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/composer.json",
    "/package.json",
    "/.well-known/security.txt",
]

SECRET_PATTERNS = {
    "API_KEY": re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    "SECRET_KEY": re.compile(r"(?i)(secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "GENERIC_TOKEN": re.compile(r"(?i)(password|passwd|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


def run(client: HttpClient, extra_js_paths: List[str] | None = None) -> List[Finding]:
    findings: List[Finding] = []

    for path in SENSITIVE_PATHS:
        r = client.get(path)
        if r.status_code == 200 and len(r.content) > 0:
            # .well-known/security.txt est volontairement public, pas un leak
            if path == "/.well-known/security.txt":
                continue
            findings.append(
                Finding(
                    category="Fuite de données",
                    title=f"Fichier potentiellement sensible accessible : {path}",
                    severity=Severity.HIGH if path.startswith(("/.env", "/.git", "/backup", "/dump")) else Severity.LOW,
                    evidence=f"GET {path} -> HTTP 200, {len(r.content)} octets",
                    recommendation=(
                        "Retirer ce fichier du répertoire servi publiquement, ou "
                        "configurer le serveur web pour bloquer l'accès aux fichiers "
                        "sensibles (.env, .git, sauvegardes). Ne jamais déployer ces "
                        "fichiers dans le webroot."
                    ),
                    url=client.url(path),
                )
            )

    # Recherche de secrets dans le HTML/JS de la page d'accueil et des
    # chemins JS supplémentaires fournis
    paths_to_scan = ["/"] + (extra_js_paths or [])
    for path in paths_to_scan:
        r = client.get(path)
        if r.status_code != 200:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(r.text):
                findings.append(
                    Finding(
                        category="Fuite de données",
                        title=f"Motif ressemblant à un secret ({name}) trouvé dans le code source",
                        severity=Severity.HIGH,
                        evidence=f"{path} : motif {name} détecté (valeur masquée: {_mask(match.group(0))})",
                        recommendation=(
                            "Si confirmé, considérer ce secret comme compromis : le "
                            "révoquer/régénérer immédiatement, puis retirer tout secret "
                            "du code côté client (JS exposé au navigateur). Utiliser un "
                            "gestionnaire de secrets côté serveur."
                        ),
                        url=client.url(path),
                    )
                )

    return findings
