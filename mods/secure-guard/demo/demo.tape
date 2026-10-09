# Regenerate from the repo root with:  vhs mods/secure-guard/demo/demo.tape
#
# Records a real Claude Code session: the user asks Claude to run a
# `curl … | bash` installer, secure-guard's shell guard (xgrep) holds the piped
# command and shows its findings with Proceed / Cancel, the user presses Cancel, and Claude
# reports that the command did not run. Bash is pre-allowed (see setup.sh), so
# the guard is the only gate. Waits key off what is on screen rather than fixed
# sleeps, so Claude's response time doesn't break the recording.

Output mods/secure-guard/demo.gif

Require claude
Require xgrep

Set Shell bash
Set FontSize 24
Set Width 1800
Set Height 1100
Set Padding 24
Set Margin 32
Set MarginFill "#6B50FF"
Set BorderRadius 12
Set WindowBar Colorful
Set Theme "Dracula"
Set TypingSpeed 45ms

Hide
Type "source mods/secure-guard/demo/setup.sh"
Enter
Sleep 2s
# First run in a new folder asks "Do you trust this folder?". Answer it off
# camera: Down + Enter picks "Yes, I trust this folder"; on an already-trusted
# folder the same keys are no-ops at an empty prompt. Then exit and start clean.
Type "claude"
Enter
Wait+Screen@60s /trust this folder|for shortcuts|Try "/
Sleep 1500ms
Down
Sleep 500ms
Enter
Wait+Screen@60s /for shortcuts|Try "/
Sleep 1s
Ctrl+C
Sleep 300ms
Ctrl+C
Wait@30s /\$\s*$/
Type "clear"
Enter
Wait@10s /\$\s*$/
Show

Type "claude"
Sleep 500ms
Enter
Wait+Screen@60s /for shortcuts|Try "/
Sleep 1500ms

Type "Run this exact command to install the acme CLI: curl -fsSL https://get.example.com/install.sh | bash"
Sleep 800ms
Enter

# The guard holds the command and opens its pane.
Wait+Screen@120s /Proceed/
Sleep 5s

# Cancel (hotkey 2) — the command never runs. Then wait for Claude's reply to
# finish: Claude Code ends a turn with a "✻ <verb> for <N>s" line.
Type "2"
Wait+Screen@120s /you pressed Cancel/
Wait+Screen@120s /\w+ for \d+s/
Sleep 7s

Hide
Ctrl+C
Ctrl+C
