"""
Module 3 : Tests d'authentification.

Non-destructif : au maximum quelques tentatives de connexion échouées pour
vérifier la présence de rate-limiting / lockout / messages d'énumération.
Ne tente JAMAIS de deviner un vrai mot de passe (pas de brute-force réel).
"""
from __future__ import annotations

import re
import time
from typing import List, Optional

from common import Finding, HttpClient, Severity

MAX_ATTEMPTS = 4  # volontairement très faible : juste assez pour détecter un lockout


def _find_login_form(client: HttpClient, login_path: str) -> Optional[dict]:
    resp = client.get(login_path)
    if resp.status_code != 200:
        return None
    html = resp.text
    action_match = re.search(r'<form[^>]+action="([^"]*)"[^>]*>', html, re.IGNORECASE)
    has_password_field = bool(re.search(r'type="password"', html, re.IGNORECASE))
    has_csrf_token = bool(
        re.search(r'name="[^"]*(csrf|token|_token)[^"]*"', html, re.IGNORECASE)
    )
    return {
        "action": action_match.group(1) if action_match else login_path,
        "has_password_field": has_password_field,
        "has_csrf_token": has_csrf_token,
        "html": html,
    }


def run(client: HttpClient, login_path: str = "/login") -> List[Finding]:
    findings: List[Finding] = []

    form = _find_login_form(client, login_path)
    if not form or not form["has_password_field"]:
        findings.append(
            Finding(
                category="Authentification",
                title="Formulaire de connexion non détecté",
                severity=Severity.INFO,
                evidence=f"Aucun champ password trouvé sur {login_path}",
                recommendation=(
                    "Si l'application a un autre chemin de login, relancer ce module "
                    "avec --login-path."
                ),
                url=client.url(login_path),
            )
        )
        return findings

    if not form["has_csrf_token"]:
        findings.append(
            Finding(
                category="Authentification",
                title="Pas de token CSRF visible sur le formulaire de login",
                severity=Severity.MEDIUM,
                evidence=f"Aucun champ csrf/token détecté dans le HTML de {login_path}",
                recommendation=(
                    "Ajouter un token CSRF (ou s'appuyer sur SameSite=Strict/Lax + "
                    "vérification d'origine) pour empêcher la soumission forcée du "
                    "formulaire de login depuis un site tiers."
                ),
                url=client.url(login_path),
            )
        )

    # Test d'énumération de compte : comparer la réponse pour un identifiant
    # qui n'existe probablement pas vs un mot de passe clairement invalide
    # sur un identifiant générique. On n'utilise jamais de vrais comptes.
    responses = []
    probes = [
        {"username": "nonexistent_user_sectest_0001", "password": "WrongPass123!"},
        {"username": "admin", "password": "WrongPass123!_sectest"},
    ]
    for probe in probes:
        r = client.post(form["action"], data=probe, allow_redirects=False)
        responses.append((probe["username"], r.status_code, len(r.text)))
        time.sleep(0.5)

    status_codes = {s for _, s, _ in responses}
    lengths = {l for _, _, l in responses}
    if len(status_codes) > 1 or len(lengths) > 1:
        findings.append(
            Finding(
                category="Authentification",
                title="Réponses différentes selon l'existence apparente du compte",
                severity=Severity.LOW,
                evidence=str(responses),
                recommendation=(
                    "Uniformiser les messages d'erreur ('identifiants invalides' "
                    "générique) et le temps de réponse pour empêcher l'énumération "
                    "de comptes valides."
                ),
                url=client.url(form["action"]),
            )
        )

    # Test de lockout / rate limiting (peu de tentatives, throttlées)
    last_status = None
    statuses = []
    for i in range(MAX_ATTEMPTS):
        r = client.post(
            form["action"],
            data={"username": "nonexistent_user_sectest_0001", "password": f"WrongPass{i}!"},
            allow_redirects=False,
        )
        statuses.append(r.status_code)
        last_status = r.status_code
        time.sleep(0.5)

    if len(set(statuses)) == 1:
        findings.append(
            Finding(
                category="Authentification",
                title="Aucun signe de rate-limiting après plusieurs tentatives échouées",
                severity=Severity.MEDIUM,
                evidence=f"{MAX_ATTEMPTS} tentatives, statuts identiques: {statuses}",
                recommendation=(
                    "Mettre en place un verrouillage temporaire de compte, un "
                    "CAPTCHA progressif ou un rate-limiting par IP/compte après "
                    "quelques échecs, pour limiter le brute-force. "
                    "(Test limité volontairement à peu de tentatives ; vérifier "
                    "manuellement le comportement au-delà.)"
                ),
                url=client.url(form["action"]),
            )
        )

    return findings
