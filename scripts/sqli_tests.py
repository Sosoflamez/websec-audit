"""
Module 6 : Tests d'injection SQL (détection non-destructive uniquement).

Conforme au guide : on envoie uniquement des caractères de test inoffensifs
(apostrophe, guillemet, parenthèse) et on cherche des signatures d'erreur SQL
dans la réponse. AUCUNE extraction de données, AUCUNE charge de type
UNION SELECT, AUCUN test basé sur le délai (SLEEP/WAITFOR) qui pourrait
dégrader le service. Un résultat positif ici est un INDICE à confirmer
manuellement (revue de code / analyse des requêtes paramétrées), pas une
preuve définitive.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlencode

from common import Finding, HttpClient, Severity

# Caractères/charges bénins : jamais de UNION SELECT, DROP, SLEEP, etc.
BENIGN_PROBES = ["'", '"', "')", '")', "' OR '1'='1", "1' AND '1'='1"]
BASELINE_PROBE = "sectest_baseline_value"

SQL_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysqli?_",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SqlClient\.SqlException",
    r"Unclosed quotation mark after the character string",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"supplied argument is not a valid MySQL",
    r"ODBC SQL Server Driver",
    r"SQLSTATE\[\d+\]",
]

COMPILED_SIGNATURES = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_SIGNATURES]


def _contains_sql_error(text: str) -> str | None:
    for pattern in COMPILED_SIGNATURES:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def run(client: HttpClient, param_endpoints: Dict[str, List[str]]) -> List[Finding]:
    """
    param_endpoints: dict {path: [param_names]} — endpoints GET avec
    paramètres à tester (ex: {"/search": ["q"], "/products": ["category_id"]}).
    Fournis par l'utilisateur ou déduits d'un crawl léger du module recon.
    """
    findings: List[Finding] = []

    for path, params in param_endpoints.items():
        for param in params:
            baseline = client.get(path, params={param: BASELINE_PROBE})
            baseline_error = _contains_sql_error(baseline.text)

            for probe in BENIGN_PROBES:
                resp = client.get(path, params={param: probe})
                error_match = _contains_sql_error(resp.text)

                if error_match and not baseline_error:
                    findings.append(
                        Finding(
                            category="Injection SQL",
                            title=f"Message d'erreur SQL déclenché sur le paramètre '{param}'",
                            severity=Severity.HIGH,
                            evidence=(
                                f"GET {path}?{urlencode({param: probe})} -> signature "
                                f"détectée: '{error_match}'"
                            ),
                            recommendation=(
                                "Indice fort d'injection SQL potentielle. À CONFIRMER "
                                "manuellement par revue de code (la requête doit utiliser "
                                "des requêtes préparées / paramètres liés, jamais de "
                                "concaténation de chaînes). Ne pas exploiter davantage "
                                "sans environnement de test dédié. Ne jamais renvoyer les "
                                "messages d'erreur SQL bruts au client en production."
                            ),
                            url=client.url(path),
                        )
                    )
                elif resp.status_code == 500 and baseline.status_code != 500:
                    findings.append(
                        Finding(
                            category="Injection SQL",
                            title=f"Erreur serveur 500 déclenchée par un caractère spécial sur '{param}'",
                            severity=Severity.MEDIUM,
                            evidence=f"GET {path}?{urlencode({param: probe})} -> HTTP 500",
                            recommendation=(
                                "Une erreur 500 sur un simple caractère spécial peut "
                                "indiquer un défaut de validation d'entrée (pas "
                                "forcément une injection SQL). À analyser dans les "
                                "logs applicatifs et à corriger par une validation de "
                                "type/format côté serveur."
                            ),
                            url=client.url(path),
                        )
                    )

    return findings
