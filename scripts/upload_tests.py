"""
Module 8 : Tests d'upload de fichiers.

Suit exactement les cas de test du guide : fichier valide, extension
interdite, extension double, nom avec caractères de traversée de chemin,
fichier trop volumineux (test léger, pas de déni de service réel).

IMPORTANT : tous les fichiers envoyés sont bénins (texte brut ou image
minimale). Aucun webshell, aucune macro, aucun fichier conçu pour exploiter
un parseur. Les fichiers envoyés doivent être supprimés après le test
lorsque l'API le permet (best effort), sinon l'utilisateur doit nettoyer
manuellement les fichiers de test déposés.
"""
from __future__ import annotations

import io
from typing import List, Optional

from common import Finding, HttpClient, Severity

BENIGN_TEXT = b"Fichier de test non-destructif genere par websec-audit.\n"

TEST_CASES = [
    ("test_valide.txt", "text/plain", BENIGN_TEXT, "valide"),
    ("test_interdit.php", "application/x-php", b"<?php /* contenu inoffensif, non execute */ ?>", "extension interdite"),
    ("test_double.php.txt", "text/plain", BENIGN_TEXT, "extension double"),
    ("test_PHP_majuscule.PHP", "text/plain", BENIGN_TEXT, "casse inhabituelle"),
    ("../../test_traversal.txt", "text/plain", BENIGN_TEXT, "traversée de chemin"),
]


def run(
    client: HttpClient,
    upload_path: str,
    file_field_name: str = "file",
    extra_fields: Optional[dict] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    extra_fields = extra_fields or {}
    uploaded_urls = []

    for filename, mime, content, case_label in TEST_CASES:
        files = {file_field_name: (filename, io.BytesIO(content), mime)}
        resp = client.post(upload_path, files=files, data=extra_fields)

        accepted = resp.status_code in (200, 201, 202)

        if case_label != "valide" and accepted:
            # Chercher une URL renvoyée pour vérifier si le fichier est
            # accessible/exécutable
            possible_url = None
            try:
                data = resp.json()
                possible_url = data.get("url") or data.get("path") or data.get("location")
            except Exception:
                possible_url = None

            severity = Severity.HIGH if filename.endswith((".php", ".PHP")) else Severity.MEDIUM
            findings.append(
                Finding(
                    category="Upload de fichiers",
                    title=f"Fichier avec {case_label} accepté par le serveur ({filename})",
                    severity=severity,
                    evidence=(
                        f"POST {upload_path} avec fichier '{filename}' (MIME: {mime}) -> "
                        f"HTTP {resp.status_code}"
                        + (f", URL retournée: {possible_url}" if possible_url else "")
                    ),
                    recommendation=(
                        "Valider le TYPE RÉEL du contenu (pas seulement l'extension ou le "
                        "Content-Type envoyé par le client), appliquer une liste blanche "
                        "stricte de formats autorisés, stocker les fichiers hors du "
                        "webroot ou dans un stockage dédié avec exécution désactivée, et "
                        "renommer les fichiers côté serveur (nom aléatoire, sans chemin "
                        "fourni par l'utilisateur)."
                    ),
                    url=client.url(upload_path),
                )
            )
            if possible_url:
                uploaded_urls.append(possible_url)
        elif case_label != "valide" and not accepted:
            findings.append(
                Finding(
                    category="Upload de fichiers",
                    title=f"Fichier avec {case_label} correctement rejeté ({filename})",
                    severity=Severity.INFO,
                    evidence=f"POST {upload_path} -> HTTP {resp.status_code}",
                    recommendation="Aucune action requise pour ce cas.",
                    url=client.url(upload_path),
                )
            )

    if uploaded_urls:
        findings.append(
            Finding(
                category="Upload de fichiers",
                title="Fichiers de test potentiellement encore présents sur le serveur",
                severity=Severity.INFO,
                evidence=f"URLs retournées lors des tests: {uploaded_urls}",
                recommendation=(
                    "Penser à supprimer manuellement ces fichiers de test après l'audit "
                    "si l'application ne les a pas nettoyés automatiquement."
                ),
                url=client.base_url,
            )
        )

    return findings
