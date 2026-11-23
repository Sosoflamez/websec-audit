#!/usr/bin/env python3
"""
Orchestrateur principal du skill websec-audit.

Usage minimal :
    python run_scan.py --target https://staging.monapp.exemple --i-have-authorization

Usage complet :
    python run_scan.py \
      --target https://staging.monapp.exemple \
      --i-have-authorization \
      --login-path /login \
      --account-a user1:pass1 \
      --account-b user2:pass2 \
      --resource-template "/api/invoices/{id}" \
      --resource-id-a 100 --resource-id-b 101 \
      --search-endpoint "/search:q" \
      --upload-path /api/upload \
      --private-endpoint /api/admin/users \
      --out reports/

IMPORTANT : ce script ne doit être lancé que sur des cibles pour lesquelles
vous avez une autorisation explicite. Voir SKILL.md pour le cadre légal.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import HttpClient, Finding
import recon
import port_scan
import auth_tests
import session_tests
import access_control_idor
import sqli_tests
import xss_csrf_tests
import upload_tests
import api_tests
import server_config_tests
import data_leak_tests
import business_logic_tests
import report


def parse_args():
    p = argparse.ArgumentParser(description="Audit de sécurité web non-destructif (websec-audit)")
    p.add_argument("--target", required=True, help="URL de base de la cible (ex: https://app.exemple.test)")
    p.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirmation OBLIGATOIRE : vous êtes propriétaire ou autorisé par écrit à tester cette cible.",
    )
    p.add_argument("--login-path", default="/login", help="Chemin du formulaire de connexion")
    p.add_argument("--account-a", help="identifiant:motdepasse du compte de test A (pour IDOR/sessions)")
    p.add_argument("--account-b", help="identifiant:motdepasse du compte de test B (pour IDOR)")
    p.add_argument("--resource-template", help="Template d'URL de ressource, ex '/api/invoices/{id}'")
    p.add_argument("--resource-id-a", help="Identifiant d'une ressource appartenant au compte A")
    p.add_argument("--resource-id-b", help="Identifiant d'une ressource appartenant au compte B")
    p.add_argument(
        "--search-endpoint",
        action="append",
        default=[],
        help="Endpoint:param à tester pour SQLi, ex '/search:q'. Répétable.",
    )
    p.add_argument("--xss-page", action="append", default=["/"], help="Page contenant des formulaires à tester pour XSS/CSRF. Répétable.")
    p.add_argument("--upload-path", help="Chemin de l'endpoint d'upload de fichiers à tester")
    p.add_argument("--private-endpoint", action="append", default=[], help="Endpoint supposé privé à tester. Répétable.")
    p.add_argument("--mass-assignment-endpoint", help="Endpoint POST/PUT à tester pour le mass assignment")
    p.add_argument(
        "--confirm-xss-poc",
        action="store_true",
        help="Active un test XSS avec payload <script> inoffensif. Uniquement sur un labo isolé que vous désignez vous-même.",
    )
    p.add_argument("--out", default="reports", help="Dossier de sortie du rapport")
    p.add_argument(
        "--skip",
        action="append",
        default=[],
        choices=[
            "recon", "ports", "auth", "sessions", "idor", "sqli",
            "xss_csrf", "upload", "api", "server_config", "data_leak", "business_logic",
        ],
        help="Module(s) à ignorer. Répétable.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    if not args.i_have_authorization:
        print(
            "ERREUR : vous devez passer --i-have-authorization pour confirmer que vous "
            "êtes autorisé à tester cette cible. Voir SKILL.md pour le cadre légal.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[websec-audit] Cible : {args.target}")
    print(
        "[websec-audit] Rappel : scan non-destructif, mais générant du trafic qui peut "
        "déclencher des systèmes de détection côté cible (WAF/SOC). Préférez un "
        "environnement de dev/staging."
    )

    client = HttpClient(args.target)
    all_findings: list[Finding] = []
    modules_run = []

    def run_module(name, fn):
        if name in args.skip:
            print(f"[websec-audit] Module '{name}' ignoré (--skip).")
            return
        print(f"[websec-audit] Exécution du module : {name}")
        try:
            findings = fn()
            all_findings.extend(findings)
            modules_run.append(name)
            print(f"  -> {len(findings)} constat(s)")
        except Exception as e:
            print(f"  -> ERREUR dans le module {name}: {e}", file=sys.stderr)

    run_module("recon", lambda: recon.run(client))
    run_module("ports", lambda: port_scan.run(args.target))
    run_module("auth", lambda: auth_tests.run(client, login_path=args.login_path))

    creds_a = tuple(args.account_a.split(":", 1)) if args.account_a else None
    run_module("sessions", lambda: session_tests.run(client, login_path=args.login_path, credentials=creds_a))

    if args.account_a and args.account_b and args.resource_template and args.resource_id_a and args.resource_id_b:
        creds_b = tuple(args.account_b.split(":", 1))
        run_module(
            "idor",
            lambda: access_control_idor.run(
                args.target,
                args.login_path,
                creds_a,
                creds_b,
                args.resource_template,
                args.resource_id_a,
                args.resource_id_b,
            ),
        )
    else:
        print("[websec-audit] Module 'idor' ignoré (comptes/ressources de test non fournis).")

    if args.search_endpoint:
        param_endpoints = {}
        for entry in args.search_endpoint:
            path, _, param = entry.partition(":")
            param_endpoints.setdefault(path, []).append(param or "q")
        run_module("sqli", lambda: sqli_tests.run(client, param_endpoints))
    else:
        print("[websec-audit] Module 'sqli' ignoré (--search-endpoint non fourni).")

    run_module("xss_csrf", lambda: xss_csrf_tests.run(client, args.xss_page, allow_script_poc=args.confirm_xss_poc))

    if args.upload_path:
        run_module("upload", lambda: upload_tests.run(client, args.upload_path))
    else:
        print("[websec-audit] Module 'upload' ignoré (--upload-path non fourni).")

    run_module(
        "api",
        lambda: api_tests.run(client, args.private_endpoint, mass_assignment_endpoint=args.mass_assignment_endpoint),
    )
    run_module("server_config", lambda: server_config_tests.run(client))
    run_module("data_leak", lambda: data_leak_tests.run(client))
    run_module("business_logic", lambda: business_logic_tests.generate_checklist())

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = out_dir / f"audit_{timestamp}.md"
    report_path.write_text(report.generate_markdown(args.target, all_findings, modules_run), encoding="utf-8")

    print(f"\n[websec-audit] Rapport généré : {report_path}")
    print(f"[websec-audit] Total constats : {len(all_findings)}")


if __name__ == "__main__":
    main()
