"""
Module 2 : Scan de ports et services.

Scan LÉGER et volontairement limité à une liste de ports web/admin usuels,
jamais un scan complet 1-65535 (trop agressif / bruyant pour un outil
d'audit non-intrusif). Timeout court par port pour éviter de bloquer sur des
hôtes filtrants.
"""
from __future__ import annotations

import socket
from typing import List
from urllib.parse import urlparse

from common import Finding, Severity

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3000: "Dev server (Node/React)",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    8000: "HTTP alt / dev",
    8080: "HTTP alt / admin",
    8443: "HTTPS alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

RISKY_IF_PUBLIC = {21, 22, 23, 1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017}


def run(target_url: str, timeout: float = 1.5) -> List[Finding]:
    findings: List[Finding] = []
    host = urlparse(target_url).hostname
    if not host:
        return findings

    open_ports = []
    for port, name in COMMON_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append((port, name))
        except (OSError, socket.timeout):
            continue

    if not open_ports:
        return findings

    evidence = ", ".join(f"{p}/{n}" for p, n in open_ports)
    findings.append(
        Finding(
            category="Scan de ports",
            title="Ports ouverts détectés",
            severity=Severity.INFO,
            evidence=evidence,
            recommendation=(
                "Vérifier que seuls les ports strictement nécessaires (généralement "
                "80/443) sont exposés publiquement ; fermer ou restreindre les autres "
                "via pare-feu/groupe de sécurité."
            ),
            url=host,
        )
    )

    risky = [(p, n) for p, n in open_ports if p in RISKY_IF_PUBLIC]
    if risky:
        evidence = ", ".join(f"{p}/{n}" for p, n in risky)
        findings.append(
            Finding(
                category="Scan de ports",
                title="Services sensibles potentiellement exposés publiquement",
                severity=Severity.HIGH,
                evidence=evidence,
                recommendation=(
                    "Ces services (bases de données, SSH, FTP...) ne devraient "
                    "généralement pas être accessibles depuis Internet. Vérifier "
                    "l'exposition réelle et restreindre via VPN/pare-feu/bind sur "
                    "localhost si possible."
                ),
                url=host,
            )
        )

    return findings
