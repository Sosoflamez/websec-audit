"""
Module 9 : Tests des API REST.

Couvre (conformément au guide) :
- Découverte via swagger.json / openapi.json si exposé
- Vérification qu'un endpoint privé refuse l'accès sans token
- CORS trop permissif (Access-Control-Allow-Origin: * avec credentials)
- Verbes HTTP autorisés (TRACE, PUT non attendus)
- Indice de mass assignment : on vérifie si des champs sensibles
  (role, isAdmin, is_admin, balance, ownerId) sont acceptés silencieusement
  dans un payload de mise à jour (test en lecture de la réponse, jamais
  d'écriture confirmée sans vérification).
"""
from __future__ import annotations

import json
from typing import List, Optional

from common import Finding, HttpClient, Severity

SENSITIVE_FIELDS = ["role", "isAdmin", "is_admin", "admin", "balance", "ownerId", "owner_id", "permissions"]
DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "PATCH"]


def _discover_spec(client: HttpClient) -> Optional[dict]:
    for path in ("/swagger.json", "/openapi.json", "/v2/api-docs", "/api/swagger.json"):
        r = client.get(path)
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                continue
    return None


def run(client: HttpClient, private_endpoints: List[str], mass_assignment_endpoint: Optional[str] = None) -> List[Finding]:
    findings: List[Finding] = []

    spec = _discover_spec(client)
    if spec:
        paths = list(spec.get("paths", {}).keys()) if isinstance(spec, dict) else []
        findings.append(
            Finding(
                category="API REST",
                title="Documentation OpenAPI/Swagger exposée publiquement",
                severity=Severity.LOW,
                evidence=f"{len(paths)} routes documentées trouvées (ex: {paths[:5]})",
                recommendation=(
                    "Vérifier que cette documentation ne doit pas être protégée "
                    "(authentification requise) selon la politique de l'organisation, "
                    "et qu'elle ne révèle pas de routes internes non destinées au public."
                ),
                url=client.url("/"),
            )
        )

    # Accès sans authentification à des endpoints supposés privés
    for endpoint in private_endpoints:
        r_noauth = client.get(endpoint, headers={})
        if r_noauth.status_code == 200:
            findings.append(
                Finding(
                    category="API REST",
                    title=f"Endpoint privé accessible sans authentification: {endpoint}",
                    severity=Severity.HIGH,
                    evidence=f"GET {endpoint} sans token -> HTTP {r_noauth.status_code}",
                    recommendation=(
                        "Imposer un middleware d'authentification centralisé sur toutes "
                        "les routes privées. Ne jamais se fier à l'absence de lien visible "
                        "dans l'interface comme seule protection."
                    ),
                    url=client.url(endpoint),
                )
            )

        # Méthodes HTTP dangereuses
        for method in DANGEROUS_METHODS:
            try:
                r = client.request(method, endpoint)
            except Exception:
                continue
            if r.status_code not in (404, 405, 501):
                findings.append(
                    Finding(
                        category="API REST",
                        title=f"Méthode {method} inattendue acceptée sur {endpoint}",
                        severity=Severity.MEDIUM,
                        evidence=f"{method} {endpoint} -> HTTP {r.status_code}",
                        recommendation=(
                            f"Désactiver les méthodes HTTP non utilisées ({method}) sur "
                            "cette route, ou vérifier qu'elles sont correctement "
                            "authentifiées et autorisées."
                        ),
                        url=client.url(endpoint),
                    )
                )

    # CORS trop permissif
    r = client.get("/", headers={"Origin": "https://attacker-sectest.example"})
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        findings.append(
            Finding(
                category="API REST",
                title="CORS mal configuré : origine wildcard avec credentials",
                severity=Severity.HIGH,
                evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                recommendation=(
                    "Ne jamais combiner Access-Control-Allow-Origin: * avec "
                    "Access-Control-Allow-Credentials: true. Restreindre les origines "
                    "autorisées à une liste blanche explicite."
                ),
                url=client.url("/"),
            )
        )
    elif acao == "*":
        findings.append(
            Finding(
                category="API REST",
                title="CORS ouvert à toute origine (sans credentials)",
                severity=Severity.LOW,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                recommendation=(
                    "Vérifier que cela est intentionnel (API publique en lecture seule) "
                    "et ne donne pas accès à des données sensibles depuis n'importe quel "
                    "site tiers."
                ),
                url=client.url("/"),
            )
        )

    # Indice de mass assignment
    if mass_assignment_endpoint:
        payload = {field: True if "admin" in field.lower() else "sectest" for field in SENSITIVE_FIELDS}
        r = client.post(mass_assignment_endpoint, json=payload)
        if r.status_code in (200, 201):
            try:
                body = r.json()
                reflected = [f for f in SENSITIVE_FIELDS if f in json.dumps(body)]
            except ValueError:
                reflected = []
            if reflected:
                findings.append(
                    Finding(
                        category="API REST",
                        title="Possible mass assignment : champs sensibles acceptés",
                        severity=Severity.HIGH,
                        evidence=(
                            f"POST {mass_assignment_endpoint} avec champs "
                            f"{SENSITIVE_FIELDS} -> champs retrouvés dans la réponse: {reflected}"
                        ),
                        recommendation=(
                            "Utiliser des DTO/listes blanches explicites pour les champs "
                            "modifiables par chaque rôle. Ne jamais désérialiser "
                            "directement le JSON client vers le modèle de données complet. "
                            "Vérifier manuellement si la valeur a réellement été persistée."
                        ),
                        url=client.url(mass_assignment_endpoint),
                    )
                )

    return findings
