---
name: websec-audit
description: Audit de sécurité web non-intrusif (reconnaissance, auth, sessions, IDOR, SQLi, XSS/CSRF, upload, API, config serveur, fuite de données, logique métier) pour les applications web, piloté par navigateur (Playwright). À utiliser UNIQUEMENT sur des cibles pour lesquelles l'utilisateur a une autorisation explicite (ses propres projets ou un mandat écrit).
license: MIT
---

# Web Security Audit Skill

Ce skill permet à Claude Code (ou tout agent IA compatible avec les Skills) de
lancer un audit de sécurité **non-destructif** d'une application web, en
pilotant un vrai navigateur (Chromium via Playwright) et en combinant des
vérifications HTTP de bas niveau.

## ⚠️ Avertissement légal et éthique (lire avant toute exécution)

- Ce skill ne doit être exécuté **que sur des applications que l'utilisateur
  possède, ou pour lesquelles il dispose d'une autorisation écrite explicite**
  (mandat de pentest, programme de bug bounty, environnement de test/staging
  personnel).
- Scanner une application tierce sans autorisation est **illégal dans la
  quasi-totalité des juridictions** (ex: en France, art. 323-1 à 323-7 du Code
  pénal ; aux États-Unis, Computer Fraud and Abuse Act).
- Avant de lancer le moindre test, l'agent DOIT :
  1. Demander à l'utilisateur de confirmer explicitement qu'il est autorisé à
     tester la cible (`--i-have-authorization` est requis par le script, voir
     plus bas — refuser de lancer le scan sans cette confirmation).
  2. Rappeler que les tests génèrent du trafic qui peut déclencher des
     systèmes de détection (WAF, SOC, fail2ban) côté cible.
  3. Recommander de tester en priorité sur un environnement de
     dev/staging plutôt qu'en production.
- Ce skill est conçu pour de la **détection non-destructive** : il ne tente
  pas d'extraire de vraies données, de supprimer/modifier des enregistrements,
  ni de forcer des mots de passe réels. Il signale des *indices* de
  vulnérabilité (en-têtes manquants, messages d'erreur verbeux, reflets non
  échappés, endpoints exposés, etc.) que l'utilisateur doit ensuite vérifier
  et confirmer manuellement avant toute remédiation ou rapport formel.

## Quand utiliser ce skill

L'utilisateur demande un audit, un scan ou un test de sécurité d'une
application web qu'il développe ou qu'il est autorisé à tester
("teste la sécurité de mon app", "fais un pentest de ce site", "audit OWASP
de mon projet", "scanne les vulnérabilités de mon API").

## Pré-requis

```bash
pip install -r requirements.txt
playwright install chromium
```

## Méthodologie (12 catégories)

Le scan suit cet ordre, chaque module étant indépendant et pouvant être lancé
isolément :

1. **Reconnaissance & fingerprinting** (`scripts/recon.py`) — technologies,
   CMS, frameworks, en-têtes serveur, favicon hash, `robots.txt`,
   `sitemap.xml`, fichiers `.well-known`.
2. **Scan de ports/services** (`scripts/port_scan.py`) — ports TCP courants
   ouverts sur l'hôte cible (scan léger, limité à une liste de ports usuels
   web/admin, jamais un scan complet agressif).
3. **Tests d'authentification** (`scripts/auth_tests.py`) — présence de
   rate-limiting / lockout, politique de mot de passe visible, messages
   d'erreur qui révèlent l'existence d'un compte (énumération), formulaires
   sans CAPTCHA/2FA, cookies d'auth non sécurisés.
4. **Gestion des sessions** (`scripts/session_tests.py`) — flags des cookies
   (`HttpOnly`, `Secure`, `SameSite`), régénération de l'ID de session après
   login, expiration, fixation de session.
5. **Contrôle d'accès / IDOR** (`scripts/access_control_idor.py`) — avec
   deux comptes de test fournis par l'utilisateur, vérifie si l'un peut
   accéder aux ressources de l'autre en changeant un identifiant dans l'URL
   ou le payload (test en lecture uniquement).
6. **Injection SQL** (`scripts/sqli_tests.py`) — détection par signatures
   d'erreur (envoi de caractères spéciaux bénins type `'`, `"`, `;` et
   recherche de messages d'erreur SQL dans la réponse), **pas d'extraction
   de données réelles**.
7. **XSS & CSRF** (`scripts/xss_csrf_tests.py`) — injection de marqueurs
   inoffensifs pour détecter un reflet non échappé (pas de `<script>` qui
   s'exécute réellement sauf si l'utilisateur active explicitement le mode
   `--confirm-xss-poc` en environnement de test) ; vérification de la
   présence de tokens CSRF sur les formulaires sensibles.
8. **Upload de fichiers** (`scripts/upload_tests.py`) — tente l'upload d'un
   fichier texte inoffensif avec une extension à risque (`.php.txt`,
   `.svg`, etc.) pour vérifier les contrôles de type MIME/extension ; ne
   dépose jamais de payload exécutable actif.
9. **API REST** (`scripts/api_tests.py`) — découverte d'endpoints (via
   `swagger.json`/`openapi.json` si exposé), vérification de l'auth
   obligatoire, rate-limiting, verbes HTTP autorisés, CORS trop permissif.
10. **Configuration serveur** (`scripts/server_config_tests.py`) — en-têtes
    de sécurité (`CSP`, `X-Frame-Options`, `Strict-Transport-Security`,
    `X-Content-Type-Options`), méthodes HTTP dangereuses (`PUT`, `TRACE`),
    version logicielle exposée, certificat TLS.
11. **Fuite de données** (`scripts/data_leak_tests.py`) — fichiers sensibles
    accessibles (`.env`, `.git/`, `.svn/`, backups `*.sql.gz`, `*.zip`),
    messages d'erreur verbeux (stack traces), métadonnées dans le code
    source (commentaires, clés API en clair).
12. **Logique métier** (`scripts/business_logic_tests.py`) — checklist
    guidée (pas automatisable à 100%) : contournement de workflow,
    manipulation de prix/quantités côté client, race conditions sur des
    actions sensibles. Ce module pose des questions à l'utilisateur et
    documente des points à vérifier manuellement plutôt que d'agir seul.

## Utilisation

```bash
python scripts/run_scan.py \
  --target https://staging.monapp.exemple \
  --i-have-authorization \
  --out reports/

# Avec comptes de test pour IDOR (optionnel) :
python scripts/run_scan.py \
  --target https://staging.monapp.exemple \
  --i-have-authorization \
  --account-a user1:pass1 \
  --account-b user2:pass2 \
  --out reports/
```

Le script génère un rapport Markdown (`reports/audit_<timestamp>.md`) listant
chaque finding avec : catégorie, sévérité (info/low/medium/high), preuve
(extrait de requête/réponse), et recommandation de correction.

## Comportement attendu de l'agent

1. Vérifier avec l'utilisateur qu'il confirme être autorisé à tester la
   cible. Ne jamais lancer le scan sans cette confirmation explicite dans la
   conversation.
2. Installer les dépendances si absentes.
3. Lancer `run_scan.py` avec les bons arguments.
4. Lire le rapport généré et le résumer à l'utilisateur en langage clair,
   trié par sévérité, avec des recommandations concrètes.
5. Ne jamais tenter d'exploiter davantage une faille détectée sans demande
   explicite et nouvelle confirmation de l'utilisateur.
6. Rappeler que les faux positifs sont possibles et que chaque finding doit
   être vérifié manuellement avant d'être considéré comme confirmé.
