"""
Module 12 : Tests de logique métier.

Comme indiqué dans le guide, ce type de test n'est pas automatisable à 100%
et nécessite de comprendre le métier. Ce module ne lance aucune requête : il
génère une checklist de points à vérifier MANUELLEMENT par l'utilisateur ou
l'agent, à documenter dans le rapport final comme "non testé
automatiquement".
"""
from __future__ import annotations

from typing import List

from common import Finding, Severity  # noqa: F401 (Finding used below)

CHECKLIST = [
    (
        "Manipulation de prix/quantités côté client",
        "Modifier le prix, la remise ou la quantité dans la requête avant envoi : "
        "le serveur doit recalculer ces valeurs depuis des données fiables, jamais "
        "faire confiance à ce qui est envoyé par le client.",
    ),
    (
        "Rejeu de callback/confirmation de paiement",
        "Rejouer un webhook ou une confirmation de paiement : le traitement doit "
        "être idempotent (pas de double crédit/livraison).",
    ),
    (
        "Double réservation / race condition",
        "Confirmer deux fois la même ressource en parallèle (double-clic, requêtes "
        "concurrentes) : pas de double réservation en cas de concurrence.",
    ),
    (
        "Contournement de workflow",
        "Tenter de passer directement à une étape avancée (ex: 'approuvé') sans "
        "passer par les étapes intermédiaires requises ('soumis', 'validé').",
    ),
    (
        "Dépassement de quota par requêtes parallèles",
        "Envoyer plusieurs requêtes simultanées pour dépasser un plafond (quota, "
        "stock, montant maximum) : la limite doit être respectée de façon atomique "
        "côté serveur.",
    ),
    (
        "Remboursement supérieur au montant payé",
        "Vérifier que le montant remboursé est plafonné et contrôlé côté serveur, "
        "jamais fourni tel quel par le client.",
    ),
    (
        "Changement de propriétaire via un champ caché",
        "Vérifier qu'un champ comme ownerId/userId dans un formulaire ou un payload "
        "JSON n'est pas modifiable par le client pour changer la propriété d'un "
        "objet.",
    ),
]


def generate_checklist() -> List[Finding]:
    """Retourne la checklist sous forme de Findings informatifs, à documenter
    manuellement par l'utilisateur dans le rapport final."""
    findings = []
    for title, description in CHECKLIST:
        findings.append(
            Finding(
                category="Logique métier",
                title=f"À vérifier manuellement : {title}",
                severity=Severity.INFO,
                evidence="Non testé automatiquement (nécessite une compréhension du métier).",
                recommendation=description,
                url=None,
            )
        )
    return findings
