"""
Génération du rapport Markdown final, suivant la structure recommandée :
résumé exécutif, méthodologie, constats (fiche de vulnérabilité par finding),
priorisation, checklist de clôture.
"""
from __future__ import annotations

import datetime
from typing import List

from common import Finding, Severity

SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
SEVERITY_LABEL_FR = {
    Severity.HIGH: "Élevée",
    Severity.MEDIUM: "Moyenne",
    Severity.LOW: "Faible",
    Severity.INFO: "Information",
}


def generate_markdown(target: str, findings: List[Finding], modules_run: List[str]) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])

    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    lines = []
    lines.append(f"# Rapport d'audit de sécurité web")
    lines.append("")
    lines.append(f"- **Cible** : {target}")
    lines.append(f"- **Date** : {now}")
    lines.append(f"- **Modules exécutés** : {', '.join(modules_run)}")
    lines.append(
        "- **Avertissement** : rapport généré par un outil automatisé "
        "(websec-audit). Chaque constat doit être vérifié manuellement avant "
        "toute action corrective ou communication externe. Des faux positifs "
        "sont possibles."
    )
    lines.append("")

    lines.append("## Résumé exécutif")
    lines.append("")
    lines.append(
        f"{counts[Severity.HIGH]} constat(s) de sévérité élevée, "
        f"{counts[Severity.MEDIUM]} moyenne, {counts[Severity.LOW]} faible, "
        f"{counts[Severity.INFO]} information(s)."
    )
    lines.append("")
    lines.append("| Sévérité | Nombre |")
    lines.append("|---|---|")
    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {SEVERITY_LABEL_FR[sev]} | {counts[sev]} |")
    lines.append("")

    lines.append("## Constats détaillés")
    lines.append("")
    for i, f in enumerate(sorted_findings, start=1):
        lines.append(f"### WEB-{i:03d} — {f.title}")
        lines.append("")
        lines.append(f"- **Catégorie** : {f.category}")
        lines.append(f"- **Sévérité** : {SEVERITY_LABEL_FR[f.severity]}")
        if f.url:
            lines.append(f"- **Actif / URL** : `{f.url}`")
        lines.append(f"- **Résultat observé (preuve)** : {f.evidence}")
        lines.append(f"- **Recommandation / correction** : {f.recommendation}")
        lines.append(f"- **Contre-test** : à réaliser après correction en reproduisant la même étape.")
        lines.append("")

    lines.append("## Checklist de clôture")
    lines.append("")
    checklist_items = [
        "Tous les actifs testés appartenaient au périmètre autorisé.",
        "Les limites de charge et les règles d'arrêt ont été respectées.",
        "Les données de test ont été restaurées ou supprimées de façon sûre "
        "(notamment les fichiers déposés par le module upload).",
        "Les secrets, cookies et données personnelles ont été expurgés des preuves "
        "avant diffusion de ce rapport.",
        "Chaque constat a une correction, un responsable et une date cible assignés "
        "(à compléter manuellement).",
        "Un contre-test indépendant est prévu après correction.",
    ]
    for item in checklist_items:
        lines.append(f"- [ ] {item}")
    lines.append("")

    lines.append("## Références")
    lines.append("")
    lines.append("- OWASP Top 10 : https://owasp.org/www-project-top-ten/")
    lines.append("- OWASP Web Security Testing Guide (WSTG) : https://owasp.org/www-project-web-security-testing-guide/")
    lines.append("- OWASP API Security Top 10 : https://owasp.org/www-project-api-security/")
    lines.append("")

    return "\n".join(lines)
