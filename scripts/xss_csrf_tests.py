"""
Module 7 : Tests XSS et CSRF.

XSS : on insère un MARQUEUR inoffensif (jamais de <script> qui s'exécute
réellement, sauf si l'utilisateur active explicitement --confirm-xss-poc sur
un environnement qu'il a désigné comme un labo isolé) et on vérifie s'il
revient non échappé dans la réponse HTML.

CSRF : on vérifie la présence d'un token CSRF sur les formulaires qui
déclenchent une action d'état (POST), et les attributs SameSite des cookies
de session (complète session_tests.py).
"""
from __future__ import annotations

import random
import re
import string
from typing import List

from common import Finding, HttpClient, Severity

# Marqueur inoffensif : ne contient aucun script exécutable.
def _make_marker() -> str:
    suffix = "".join(random.choices(string.digits, k=4))
    return f"XSSTEST{suffix}<>\"'&"


DANGEROUS_SCRIPT_PAYLOAD = "<script>/*XSS_POC_NOOP*/</script>"


def _find_forms(html: str) -> List[dict]:
    forms = []
    for match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        action_match = re.search(r'action="([^"]*)"', form_html, re.IGNORECASE)
        method_match = re.search(r'method="([^"]*)"', form_html, re.IGNORECASE)
        has_csrf = bool(
            re.search(r'name="[^"]*(csrf|_token|authenticity_token)[^"]*"', form_html, re.IGNORECASE)
        )
        input_names = re.findall(r'<input[^>]+name="([^"]+)"', form_html, re.IGNORECASE)
        forms.append(
            {
                "action": action_match.group(1) if action_match else "",
                "method": (method_match.group(1) if method_match else "get").lower(),
                "has_csrf": has_csrf,
                "input_names": input_names,
            }
        )
    return forms


def run(
    client: HttpClient,
    pages_with_inputs: List[str],
    allow_script_poc: bool = False,
) -> List[Finding]:
    findings: List[Finding] = []

    for page_path in pages_with_inputs:
        resp = client.get(page_path)
        if resp.status_code != 200:
            continue

        forms = _find_forms(resp.text)
        for form in forms:
            if form["method"] == "post" and not form["has_csrf"]:
                findings.append(
                    Finding(
                        category="CSRF",
                        title=f"Formulaire POST sans token CSRF visible sur {page_path}",
                        severity=Severity.MEDIUM,
                        evidence=f"Action: {form['action']}, champs: {form['input_names']}",
                        recommendation=(
                            "Ajouter un token CSRF imprévisible, lié à la session et "
                            "vérifié côté serveur, sur toute action qui modifie l'état "
                            "(changement de mot de passe, d'email, paiement, etc.). "
                            "SameSite=Lax/Strict est un complément utile mais pas un "
                            "substitut complet au token."
                        ),
                        url=client.url(page_path),
                    )
                )

            # Test XSS réfléchi : on injecte le marqueur dans chaque champ texte
            # via une requête séparée (GET si le form est en GET, sinon on
            # teste les query params de la page elle-même si pertinents).
            if form["method"] == "get" and form["input_names"]:
                marker = _make_marker()
                data = {name: marker for name in form["input_names"]}
                test_resp = client.get(form["action"] or page_path, params=data)
                if marker in test_resp.text:
                    findings.append(
                        Finding(
                            category="XSS",
                            title=f"Marqueur non échappé reflété sur {form['action'] or page_path}",
                            severity=Severity.HIGH,
                            evidence=(
                                f"Marqueur injecté: {marker!r} retrouvé tel quel dans la "
                                "réponse HTML (non encodé)."
                            ),
                            recommendation=(
                                "Encoder toute donnée utilisateur selon le contexte de "
                                "sortie (HTML, attribut, URL, JS) avant insertion dans la "
                                "page. Préférer textContent/insertion via API DOM sûres "
                                "plutôt que innerHTML. Déployer une Content-Security-Policy "
                                "en défense en profondeur."
                            ),
                            url=client.url(form["action"] or page_path),
                        )
                    )

        if allow_script_poc:
            # Uniquement si explicitement activé par l'utilisateur pour un
            # environnement qu'il a désigné comme labo isolé. Payload
            # volontairement inoffensif (commentaire, pas d'exécution réelle
            # de code tiers, pas d'exfiltration).
            marker = DANGEROUS_SCRIPT_PAYLOAD
            test_resp = client.get(page_path, params={"sectest_xss_poc": marker})
            if marker in test_resp.text:
                findings.append(
                    Finding(
                        category="XSS",
                        title=f"Balise <script> reflétée telle quelle sur {page_path}",
                        severity=Severity.HIGH,
                        evidence="Payload de preuve de concept retrouvé sans échappement dans le HTML.",
                        recommendation=(
                            "Confirmation forte d'une XSS réfléchie exploitable. Corriger "
                            "immédiatement l'échappement de sortie pour ce paramètre."
                        ),
                        url=client.url(page_path),
                    )
                )

    return findings
