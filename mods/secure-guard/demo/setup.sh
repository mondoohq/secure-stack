# Sourced (hidden) by demo.tape before recording. Not meant to run on its own.
#
# Gets the demo shell into a known state so the recording shows only the guard:
#   - an xgrep new enough for `xgrep guard --command` first on PATH, so the mod
#     doesn't announce a download mid-recording;
#   - a scratch project to run Claude in (.demo/acme-app at the repo root);
#   - a `claude` function that loads this checkout's secure-guard mod (not an
#     installed copy, with any installed guard disabled so only one pane shows)
#     and pre-allows Bash, Write/Edit (accept-edits mode) and the report tool, so the
#     guard's own panes are the only prompts on screen.

# Recording from inside another Claude Code session (e.g. asking Claude to run
# vhs) would leak that session into the demo; start from a clean slate.
for v in $(env | grep -o '^CLAUDE[A-Z_]*='); do unset "${v%=}"; done

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD_DIR="$(dirname "$DEMO_DIR")"
# The release the mod pins, so the demo runs the scanner users get.
XGREP_PIN="$(sed -n 's/^export const XGREP_PIN = "\(.*\)";.*/\1/p' "$MOD_DIR/hooks/core.mjs")"

if ! xgrep guard --command "echo ok" 2>/dev/null | grep -q '^{'; then
  if [ ! -x "$DEMO_DIR/.bin/node_modules/.bin/xgrep" ]; then
    npm install --silent --prefix "$DEMO_DIR/.bin" "@mondoohq/xgrep@$XGREP_PIN" >/dev/null 2>&1
  fi
  export PATH="$DEMO_DIR/.bin/node_modules/.bin:$PATH"
fi

# The scratch project lives OUTSIDE the mod's folder: Claude Code always asks
# before an edit inside a loaded plugin's own files, which would put a
# permission prompt in front of every write the demo shows.
REPO_DIR="$(dirname "$(dirname "$MOD_DIR")")"
mkdir -p "$REPO_DIR/.demo/acme-app"
cd "$REPO_DIR/.demo/acme-app" || return
# Its own git repo, so Claude Code doesn't show the enclosing checkout's
# branch or pull request in the recording's status bar.
[ -d .git ] || git init -q

claude() {
  command claude \
    --plugin-dir "$MOD_DIR" \
    --settings '{"enabledPlugins":{"secure-guard@secure-stack":false,"xgrep-guard@mondoohq":false}}' \
    --permission-mode acceptEdits \
    --allowedTools Bash Write Edit mcp__secure-guard__report_false_positive \
    "$@"
}

export PS1='$ '
clear
