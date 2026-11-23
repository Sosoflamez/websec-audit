#!/usr/bin/env bash
# Installe le skill websec-audit et la commande /soso-secure pour Claude Code.
#
# Usage :
#   ./install.sh            # installation globale (~/.claude/)
#   ./install.sh --project  # installation dans le projet courant (./.claude/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--project" ]]; then
  BASE_DIR="$(pwd)/.claude"
else
  BASE_DIR="$HOME/.claude"
fi

SKILLS_DIR="$BASE_DIR/skills/websec-audit"
COMMANDS_DIR="$BASE_DIR/commands"

mkdir -p "$SKILLS_DIR" "$COMMANDS_DIR"

echo "Installation du skill dans $SKILLS_DIR ..."
cp -r "$SCRIPT_DIR/skills/websec-audit/." "$SKILLS_DIR/"

echo "Installation de la commande /soso-secure dans $COMMANDS_DIR ..."
cp "$SCRIPT_DIR/commands/soso-secure.md" "$COMMANDS_DIR/soso-secure.md"

echo ""
echo "Installation terminée."
echo "  Skill   : $SKILLS_DIR"
echo "  Commande: $COMMANDS_DIR/soso-secure.md"
echo ""
echo "Installe maintenant les dépendances Python :"
echo "  pip install -r $SKILLS_DIR/requirements.txt"
echo "  playwright install chromium"
echo ""
echo "Puis, dans Claude Code, tape par exemple :"
echo "  /soso-secure https://staging.monapp.test je suis autorisé, c'est mon app"
