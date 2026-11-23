"""
Module 5 : Contrôle d'accès et IDOR (Insecure Direct Object Reference).

Nécessite deux comptes de test (A et B) fournis par l'utilisateur, chacun
propriétaire d'au moins une ressource identifiable. Le test est strictement
en LECTURE : on ne modifie/supprime jamais la ressource d'autrui.

Méthode (cf. guide) :
1. Se connecter avec A, relever l'identifiant d'une ressource de A.
2. Se connecter avec B, relever l'identifiant d'une ressource de B.
3. Avec la session de A, essayer de lire la ressource de B (GET uniquement).
4. Une réponse 200 contenant les données de B = IDOR confirmé.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from common import Finding, HttpClient, Severity


def _login(client: HttpClient, login_path: str, username: str, password: str) -> bool:
    r = client.post(login_path, data={"username": username, "password": password}, allow_redirects=True)
    return r.status_code < 400


def run(
    base_url: str,
    login_path: str,
    account_a: Tuple[str, str],
    account_b: Tuple[str, str],
    resource_path_template: str,
    resource_id_a: str,
    resource_id_b: str,
) -> List[Finding]:
    """
    resource_path_template: ex "/api/invoices/{id}" ou "/account/documents/{id}"
    resource_id_a / resource_id_b : identifiants de ressources appartenant
    respectivement à A et à B, fournis par l'utilisateur (données fictives).
    """
    findings: List[Finding] = []

    client_a = HttpClient(base_url)
    if not _login(client_a, login_path, *account_a):
        findings.append(
            Finding(
                category="Contrôle d'accès / IDOR",
                title="Impossible de se connecter avec le compte A fourni",
                severity=Severity.INFO,
                evidence=f"Échec de login sur {login_path}",
                recommendation="Vérifier les identifiants du compte A passés au scan.",
                url=client_a.url(login_path),
            )
        )
        return findings

    own_path = resource_path_template.format(id=resource_id_a)
    own_resp = client_a.get(own_path)

    other_path = resource_path_template.format(id=resource_id_b)
    other_resp = client_a.get(other_path)

    if other_resp.status_code == 200:
        # Vérifier que ce n'est pas juste une page générique (ex: formulaire vide)
        looks_like_data = len(other_resp.text) > 50 and other_resp.text != own_resp.text
        severity = Severity.HIGH if looks_like_data else Severity.MEDIUM
        findings.append(
            Finding(
                category="Contrôle d'accès / IDOR",
                title="Accès possible à une ressource appartenant à un autre compte",
                severity=severity,
                evidence=(
                    f"Session du compte A, requête GET {other_path} -> "
                    f"HTTP {other_resp.status_code}, {len(other_resp.text)} octets reçus"
                ),
                recommendation=(
                    "Vérifier côté serveur que l'utilisateur authentifié est bien le "
                    "propriétaire (ou autorisé) de la ressource demandée, pour CHAQUE "
                    "requête, indépendamment du contrôle d'affichage côté client. "
                    "Ne jamais faire confiance à un identifiant fourni par le client."
                ),
                url=client_a.url(other_path),
            )
        )
    elif other_resp.status_code in (403, 404):
        findings.append(
            Finding(
                category="Contrôle d'accès / IDOR",
                title="Contrôle d'accès correct sur la ressource testée",
                severity=Severity.INFO,
                evidence=f"GET {other_path} avec session A -> HTTP {other_resp.status_code}",
                recommendation="Aucune action requise pour ce cas précis ; tester d'autres endpoints similaires.",
                url=client_a.url(other_path),
            )
        )

    return findings
