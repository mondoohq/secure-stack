#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GENERATED_FILES=(
  "agents/SKILLS.md"
  "README.md"
)

run_generate() {
  npx tsx scripts/generate_agents.ts
}

run_check() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  local changed=()

  # Save originals
  for path in "${GENERATED_FILES[@]}"; do
    if [[ -f "$path" ]]; then
      cp "$path" "$tmpdir/$(echo "$path" | tr '/' '_')"
    fi
  done

  run_generate

  # Compare generated output against saved originals
  for path in "${GENERATED_FILES[@]}"; do
    local saved="$tmpdir/$(echo "$path" | tr '/' '_')"
    if [[ ! -f "$saved" ]] || ! diff -q "$path" "$saved" > /dev/null 2>&1; then
      changed+=("$path")
    fi
  done

  # Restore originals so check mode is side-effect free
  for path in "${GENERATED_FILES[@]}"; do
    local saved="$tmpdir/$(echo "$path" | tr '/' '_')"
    if [[ -f "$saved" ]]; then
      cp "$saved" "$path"
    fi
  done

  rm -rf "$tmpdir"

  if [[ ${#changed[@]} -gt 0 ]]; then
    echo "Generated artifacts are outdated."
    echo "Run: ./scripts/publish.sh"
    echo
    echo "Changed files:"
    for path in "${changed[@]}"; do
      echo "$path"
    done
    exit 1
  fi

  echo "All generated artifacts are up to date."
}

case "${1:-}" in
  "")
    run_generate
    echo "Publish artifacts generated successfully."
    ;;
  "--check")
    run_check
    ;;
  "-h"|"--help")
    cat <<'EOF'
Usage:
  ./scripts/publish.sh         Generate all publish artifacts
  ./scripts/publish.sh --check Verify generated artifacts are up to date

This script regenerates:
  - agents/SKILLS.md
  - README.md (skills table section)
EOF
    ;;
  *)
    echo "Unknown option: $1" >&2
    echo "Use --help for usage." >&2
    exit 2
    ;;
esac
