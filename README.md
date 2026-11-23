# websec-audit

Un plugin Claude Code qui réalise un audit de sécurité web non-destructif.
Il couvre douze familles de tests classiques, alignées sur la méthodologie
OWASP :

1. Reconnaissance et identification des technologies
2. Scan de ports et services
3. Authentification
4. Gestion des sessions
5. Contrôle d'accès et IDOR
6. Injection SQL
7. XSS et CSRF
8. Upload de fichiers
9. API REST
10. Configuration serveur
11. Fuite de données
12. Logique métier

## Avant de commencer

N'utilisez ce skill que sur des applications que vous possédez, ou pour
lesquelles vous avez une autorisation écrite explicite. Scanner une
application tierce sans autorisation est illégal dans la quasi-totalité des
juridictions. Le détail du cadre légal et de la méthodologie se trouve dans
[SKILL.md](./skills/websec-audit/SKILL.md).

L'outil privilégie systématiquement la détection non-destructive : aucune
extraction réelle de données, aucune action destructive, aucun brute-force
de comptes réels. Chaque résultat est un indice à vérifier manuellement, pas
une preuve définitive.

## Installation

La méthode recommandée passe par le marketplace de plugins Claude Code.
Ce dépôt est à la fois un plugin et une marketplace. Dans Claude Code :

```
/plugin marketplace add Sosoflamez/websec-audit
/plugin install websec-audit@sosoflamez-websec-audit
```

Installez ensuite les dépendances Python, car le plugin ne les installe pas
lui-même :

```bash
pip install -r requirements.txt   # depuis le dossier du plugin installé
playwright install chromium
```

Une fois cela fait, la commande suivante fonctionne dans n'importe quel
projet :

```
/soso-audit https://staging.monapp.test je suis autorisé, c'est mon app
```

Elle lit SKILL.md, confirme l'autorisation si besoin, lance le scan en
arrière-plan pour que vous puissiez continuer à travailler, puis résume le
rapport dès qu'il est prêt.

### Sans le marketplace

```bash
git clone https://github.com/Sosoflamez/websec-audit.git
cd websec-audit
./install.sh                 # installation globale dans ~/.claude/
# ou : ./install.sh --project   # installation dans le projet courant

pip install -r ~/.claude/skills/websec-audit/requirements.txt
playwright install chromium
```

`install.sh` copie le skill dans `~/.claude/skills/websec-audit/` et la
commande dans `~/.claude/commands/soso-audit.md`.

### Sans Claude Code, en ligne de commande

```bash
cd skills/websec-audit
pip install -r requirements.txt
playwright install chromium

python scripts/run_scan.py \
  --target https://staging.monapp.test \
  --i-have-authorization \
  --out reports/
```

Les options avancées (comptes de test pour IDOR, endpoints à tester pour
l'injection SQL, upload, API privées) sont décrites par
`python scripts/run_scan.py --help` et dans SKILL.md.

## Le rapport

Chaque exécution génère un rapport Markdown dans le dossier indiqué par
`--out`. Il est structuré en fiches de vulnérabilité : catégorie, sévérité,
preuve, recommandation. Il contient aussi un résumé exécutif et une
checklist de clôture.

## Tester le skill en local

Une petite application Flask volontairement vulnérable est fournie dans
`skills/websec-audit/tests/mock_app.py`. Elle permet de vérifier le
comportement des scripts sans dépendre d'une cible externe :

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
  marketplace.json    déclare ce dépôt comme marketplace Claude Code
  plugin.json          manifeste du plugin websec-audit

commands/
  soso-audit.md         la commande /soso-audit

skills/websec-audit/
  SKILL.md               méthodologie et cadre légal
  scripts/                les douze modules, l'orchestrateur et le rapport
  tests/mock_app.py       cible locale pour valider le skill

install.sh              installation manuelle, hors marketplace
```

## Limites

La détection est non-destructive uniquement : les résultats sont des
indices à confirmer manuellement, par exemple par une revue de code ou des
tests ciblés complémentaires. Le module de logique métier ne peut pas être
entièrement automatisé ; il se contente de générer une liste de points à
vérifier à la main. Enfin, cet outil ne remplace pas un audit professionnel,
une revue de code approfondie, ni une expertise juridique.

## Références

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)

## Licence

MIT, voir [LICENSE](./LICENSE).
