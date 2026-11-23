# websec-audit

Skill Claude Code / agent IA pour réaliser un **audit de sécurité web
non-destructif**, couvrant les 12 familles de tests classiques (OWASP-aligned) :

1. Reconnaissance et identification des technologies
2. Scan de ports et services
3. Tests d'authentification
4. Tests de gestion des sessions
5. Tests de contrôle d'accès et IDOR
6. Tests d'injection SQL
7. Tests XSS et CSRF
8. Tests d'upload de fichiers
9. Tests des API REST
10. Tests de configuration serveur
11. Tests de fuite de données
12. Tests de logique métier

## ⚠️ Avant de commencer

**N'utilisez ce skill que sur des applications que vous possédez, ou pour
lesquelles vous avez une autorisation écrite explicite.** Scanner une
application tierce sans autorisation est illégal dans la quasi-totalité des
juridictions. Voir [SKILL.md](./SKILL.md) pour le détail du cadre légal et de
la méthodologie.

Ce projet s'inspire de la méthodologie OWASP (Top 10, WSTG, ASVS, API
Security Top 10) et privilégie systématiquement la détection non-destructive :
aucune extraction réelle de données, aucune action destructive, aucun
brute-force de comptes réels.

## Installation rapide (avec la commande `/soso-secure`)

```bash
git clone https://github.com/Sosoflamez/websec-audit.git
cd websec-audit
./install.sh              # installation globale (~/.claude/)
# ou : ./install.sh --project   # installation dans le projet courant

pip install -r ~/.claude/skills/websec-audit/requirements.txt
playwright install chromium
```

`install.sh` copie le skill dans `~/.claude/skills/websec-audit/` et la
commande dans `~/.claude/commands/soso-secure.md`. Ensuite, dans Claude
Code :

```
/soso-secure https://staging.monapp.test je suis autorisé, c'est mon app
```

La commande lit `SKILL.md`, confirme l'autorisation si besoin, **lance le
scan en arrière-plan** (vous pouvez continuer à travailler pendant ce temps)
et vous résume le rapport dès qu'il est prêt.

## Installation manuelle

```bash
git clone https://github.com/Sosoflamez/websec-audit.git
cd websec-audit
pip install -r requirements.txt
playwright install chromium
```

## Utilisation en tant que skill Claude Code

Copiez ce dossier dans votre répertoire de skills Claude Code (ou tout agent
compatible avec le format Skill), puis invoquez-le en demandant par exemple :

> "Audit la sécurité de mon application sur https://staging.monapp.test,
> j'en suis le propriétaire."

L'agent lira `SKILL.md`, confirmera votre autorisation, installera les
dépendances si besoin, puis lancera `scripts/run_scan.py` avec les bons
arguments et vous résumera le rapport généré.

## Utilisation en ligne de commande

```bash
python scripts/run_scan.py \
  --target https://staging.monapp.test \
  --i-have-authorization \
  --out reports/
```

Options avancées (comptes de test pour IDOR, endpoints à tester pour SQLi,
upload, API privées...) : voir `python scripts/run_scan.py --help` et
[SKILL.md](./SKILL.md).

## Rapport

Chaque exécution génère un rapport Markdown dans `reports/`, structuré en
fiches de vulnérabilité (catégorie, sévérité, preuve, recommandation),
accompagné d'un résumé exécutif et d'une checklist de clôture.

## Valider le fonctionnement en local

Une petite application Flask volontairement vulnérable est fournie dans
`tests/mock_app.py` pour valider le comportement des scripts sans dépendre
d'une cible externe :

```bash
pip install flask
python3 tests/mock_app.py &   # démarre sur http://127.0.0.1:5151
python3 scripts/run_scan.py --target http://127.0.0.1:5151 --i-have-authorization \
  --login-path /login --account-a user1:x --account-b user2:x \
  --resource-template "/api/invoices/{id}" --resource-id-a 100 --resource-id-b 101 \
  --search-endpoint "/search:q" --upload-path /upload --private-endpoint /admin \
  --out reports/
```

Ne jamais exposer `tests/mock_app.py` sur un réseau public : il contient des
failles volontaires.

## Limites

- Détection non-destructive uniquement : les résultats sont des **indices**
  à confirmer manuellement (revue de code, tests ciblés complémentaires).
- Le module "logique métier" ne peut pas être entièrement automatisé : il
  génère une checklist de points à vérifier manuellement.
- Cet outil ne remplace pas un audit professionnel, une revue de code
  approfondie ni une expertise juridique/réglementaire.

## Références

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)

## Licence

MIT — voir [LICENSE](./LICENSE).
