---
description: Lance un audit de sécurité web non-destructif (websec-audit, 12 familles de tests) en arrière-plan
argument-hint: <url-cible> [options avancées]
---

Tu vas lancer le skill **websec-audit** sur la cible fournie dans `$ARGUMENTS`,
en tâche de fond, pour que l'utilisateur puisse continuer à travailler
pendant que le scan tourne.

## Étape 0 — Localiser le skill

Cherche le dossier du skill (celui qui contient `SKILL.md` et `scripts/run_scan.py`),
typiquement `~/.claude/skills/websec-audit/` ou `.claude/skills/websec-audit/`
dans le projet courant. S'il est introuvable, dis-le à l'utilisateur et arrête-toi.

## Étape 1 — Lire SKILL.md

Lis entièrement `SKILL.md` dans ce dossier et applique ses règles, en particulier
le cadre légal : **tu ne dois jamais lancer le scan sans confirmation explicite
de l'utilisateur qu'il est autorisé à tester la cible.**

## Étape 2 — Extraire la cible et les options depuis `$ARGUMENTS`

`$ARGUMENTS` contient l'URL cible et éventuellement d'autres options en langage
naturel (comptes de test pour IDOR, endpoint de recherche à tester pour SQLi,
endpoint d'upload, endpoints privés, etc.). Déduis-en les arguments CLI de
`scripts/run_scan.py` (voir `python scripts/run_scan.py --help` ou SKILL.md).

Si aucune URL cible n'est présente dans `$ARGUMENTS`, demande-la à l'utilisateur
avant de continuer.

## Étape 3 — Confirmer l'autorisation

Si `$ARGUMENTS` ne contient pas déjà une confirmation explicite d'autorisation
("je suis autorisé", "c'est mon app", "j'ai un mandat écrit", etc.), demande à
l'utilisateur de confirmer explicitement qu'il est propriétaire de la cible ou
qu'il dispose d'une autorisation écrite. N'avance pas sans cette confirmation.

## Étape 4 — Préparer l'environnement

Vérifie que les dépendances sont installées (`pip show requests playwright`).
Si absentes, installe-les :

```bash
pip install -r <chemin_du_skill>/requirements.txt
playwright install chromium
```

## Étape 5 — Lancer le scan EN ARRIÈRE-PLAN

Lance `scripts/run_scan.py` avec `--i-have-authorization` et les arguments
déduits, en tâche de fond (ne bloque pas la conversation), en redirigeant la
sortie vers un fichier de log, par exemple :

```bash
cd <chemin_du_skill> && nohup python3 scripts/run_scan.py \
  --target <URL> \
  --i-have-authorization \
  [...autres options...] \
  --out reports/ > /tmp/websec-audit-$(date +%s).log 2>&1 &
```

Utilise ton outil Bash en mode arrière-plan (`run_in_background: true` si
disponible) pour ce lancement, afin que l'utilisateur récupère la main
immédiatement.

Dis ensuite à l'utilisateur, en une phrase, que l'audit tourne en fond sur
`<URL>`, avec le chemin du log, et que tu le préviendras dès qu'il sera
terminé (ou comment vérifier l'avancement si le mode arrière-plan automatique
n'est pas disponible dans ce contexte).

## Étape 6 — À la fin du scan

Quand le scan se termine (notification automatique, ou vérification manuelle
du log/du dossier `reports/`), lis le rapport Markdown généré et résume les
constats à l'utilisateur en langage clair, triés par sévérité (élevée →
information), avec les recommandations concrètes. Rappelle que chaque constat
doit être vérifié manuellement avant correction.

Ne tente jamais d'exploiter davantage une faille détectée sans nouvelle
demande explicite de l'utilisateur.
