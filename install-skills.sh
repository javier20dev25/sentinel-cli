#!/usr/bin/env bash
set -euo pipefail

SENTINEL_DIR="${SENTINEL_DIR:-${HOME}/sentinel-cli}"
SKILLS_SRC="${SENTINEL_DIR}/skills"

if [ ! -d "${SKILLS_SRC}" ]; then
  echo "Error: skills directory not found at ${SKILLS_SRC}"
  echo "Set SENTINEL_DIR to your sentinel-cli checkout, or run from the project root."
  exit 1
fi

detect_and_install() {
  local agent="$1"
  local target="$2"
  local label="$3"

  if [ ! -d "${target}" ]; then
    mkdir -p "${target}" 2>/dev/null || return 1
  fi

  local count=0
  for f in "${SKILLS_SRC}"/*.md "${SKILLS_SRC}"/adapters/*; do
    if [ -f "${f}" ]; then
      cp "${f}" "${target}/" 2>/dev/null && count=$((count + 1)) || true
    fi
  done

  echo "  [${label}] ${agent}: ${count} file(s) -> ${target}"
}

echo "Sentinel Skills Installer"
echo "========================="
echo ""

INSTALLED=0

# Claude
if command -v claude &>/dev/null; then
  detect_and_install "claude" "${HOME}/.claude/commands" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Cursor
if command -v cursor &>/dev/null || [ -d "${HOME}/.cursor" ]; then
  detect_and_install "cursor" "${HOME}/.cursor/rules" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Cline
CLINE_EXT="${HOME}/.vscode/extensions/saoudrizwan.claude-dev"
if [ -d "${CLINE_EXT}" ]; then
  detect_and_install "cline" "${CLINE_EXT}/skills" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Windsurf
if command -v windsurf &>/dev/null || [ -d "${HOME}/.windsurf" ]; then
  # Copy root-level .windsurfrules
  if [ -f "${SKILLS_SRC}/adapters/windsurf/.windsurfrules" ]; then
    cp "${SKILLS_SRC}/adapters/windsurf/.windsurfrules" "${HOME}/.windsurfrules" 2>/dev/null && echo "  [OK] windsurf: .windsurfrules -> ${HOME}"
  fi
  INSTALLED=$((INSTALLED + 1))
fi

# OpenCode
if command -v opencode &>/dev/null || [ -d "${HOME}/.config/opencode" ]; then
  detect_and_install "opencode" "${HOME}/.config/opencode/skills" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Roo
if command -v roo &>/dev/null || [ -d "${HOME}/.config/roo" ]; then
  detect_and_install "roo" "${HOME}/.config/roo/skills" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Gemini
if command -v gemini &>/dev/null; then
  detect_and_install "gemini" "${HOME}/.config/gemini/cli/skills" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

# Codex
if command -v codex &>/dev/null; then
  detect_and_install "codex" "${HOME}/.codex/skills" "OK"
  INSTALLED=$((INSTALLED + 1))
fi

if [ "${INSTALLED}" -eq 0 ]; then
  echo "No supported AI coding agents detected."
  echo "Install an agent first or run: sentinel install-skills --all"
  exit 1
fi

echo ""
echo "Done. Skills installed for ${INSTALLED} agent(s)."
