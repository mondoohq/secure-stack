# Regenerate from the repo root with:  vhs mods/secure-guard/demo/inline-review.tape
#
# Records a real Claude Code session of the inline code review: the project
# already has a SQL injection (fixtures/app.py, copied in off camera), the user
# asks for an unrelated change, Claude edits the file, xgrep's review comes back
# right after the edit with the finding, and Claude fixes it in the same turn.
# Same off-camera setup as demo.tape (setup.sh); waits key off what is on screen.

Output mods/secure-guard/demo-inline-review.gif

Require claude
Require xgrep

Set Shell bash
Set FontSize 20
Set Width 1800
Set Height 1600
Set Padding 24
Set Margin 32
Set MarginFill "#6B50FF"
Set BorderRadius 12
Set WindowBar Colorful
Set Theme "Dracula"
Set TypingSpeed 45ms

Hide
Type "source mods/secure-guard/demo/setup.sh && rm -f greet.py greet.py.draft acme.db && cp $DEMO_DIR/fixtures/app.py app.py"
Enter
Sleep 2s
# First run in a new folder asks "Do you trust this folder?" — see demo.tape.
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

Type "Add a /health endpoint to app.py that returns {status: ok}."
Sleep 800ms
Enter

# Claude edits app.py; the guard's xgrep review comes back with the existing
# SQL injection, and Claude fixes it before the turn ends.
Wait+Screen@180s /sql-injection|SQL injection/
Wait+Screen@240s /for (\d+m )?\d+s · done/
Sleep 8s

Hide
Ctrl+C
Ctrl+C
