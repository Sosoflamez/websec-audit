# websec-audit

Plugin / skill Claude Code pour réaliser un **audit de sécurité web
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
juridictions. Voir [SKILL.md](./skills/websec-audit/SKILL.md) pour le détail
du cadre légal et de la méthodologie.

Ce projet s'inspire de la méthodologie OWASP (Top 10, WSTG, ASVS, API
Security Top 10) et privilégie systématiquement la détection non-destructive :
aucune extraction réelle de données, aucune action destructive, aucun
brute-force de comptes réels.

## Installation via le marketplace Claude Code (recommandé)

Ce dépôt est à la fois un plugin et une marketplace Claude Code. Dans Claude
Code :

```
/plugin marketplace add Sosoflamez/websec-audit
/plugin install websec-audit@sosoflamez-websec-audit
```

Puis installez les dépendances Python (le plugin ne les installe pas
automatiquement) :

```bash
pip install -r requirements.txt   # depuis le dossier du plugin installé
playwright install chromium
```

Ensuite, dans n'importe quel projet, tapez simplement :

```
/soso-secure https://staging.monapp.test je suis autorisé, c'est mon app
```

La commande lit `SKILL.md`, confirme l'autorisation si besoin, **lance le
scan en arrière-plan** (vous pouvez continuer à travailler pendant ce temps)
et vous résume le rapport dès qu'il est prêt.

## Installation manuelle (sans marketplace)

```bash
git clone https://github.com/Sosoflamez/websec-audit.git
cd websec-audit
./install.sh              # installation globale (~/.claude/)
# ou : ./install.sh --project   # installation dans le projet courant

pip install -r ~/.claude/skills/websec-audit/requirements.txt
playwright install chromium
```

`install.sh` copie le skill dans `~/.claude/skills/websec-audit/` et la
commande dans `~/.claude/commands/soso-secure.md`.

## Utilisation en ligne de commande (sans Claude Code)

```bash
cd skills/websec-audit
pip install -r requirements.txt
playwright install chromium

python scripts/run_scan.py \
  --target https://staging.monapp.test \
  --i-have-authorization \
  --out reports/
```

Options avancées (comptes de test pour IDOR, endpoints à tester pour SQLi,
upload, API privées...) : voir `python scripts/run_scan.py --help` et
[SKILL.md](./skills/websec-audit/SKILL.md).

## Rapport

Chaque exécution génère un rapport Markdown dans le dossier `--out` indiqué,
structuré en fiches de vulnérabilité (catégorie, sévérité, preuve,
recommandation), accompagné d'un résumé exécutif et d'une checklist de
clôture.

## Valider le fonctionnement en local

Une petite application Flask volontairement vulnérable est fournie dans
`skills/websec-audit/tests/mock_app.py` pour valider le comportement des
scripts sans dépendre d'une cible externe :

```bash
cd skills/websec-audit
pip install flask
python3 tests/mock_app.py &   # démarre sur http://127.0.0.1:5151
python3 scripts/run_scan.py --target http://127.0.0.1:5151 --i-have-authorization \
  --login-path /login --account-a user1:x --account-b user2:x \
  --resource-template "/api/invoices/{id}" --resource-id-a 100 --resource-id-b 101 \
  --search-endpoint "/search:q" --upload-path /upload --private-endpoint /admin \
  --out reports/
```

Ne jamais exposer `mock_app.py` sur un réseau public : il contient des
failles volontaires.

## Structure du dépôt

```
.claude-plugin/
  marketplace.json   # déclare ce dépôt comme marketplace Claude Code
  plugin.json         # manifeste du plugin "websec-audit"
commands/
  soso-secure.md       # commande /soso-secure
skills/websec-audit/
  SKILL.md             # méthodologie + garde-fous légaux
  scripts/             # les 12 modules + orchestrateur + rapport
  tests/mock_app.py    # cible locale pour valider le skill
install.sh              # installation manuelle (hors marketplace)
```

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
