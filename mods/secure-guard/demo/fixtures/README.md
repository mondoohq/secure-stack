# Demo fixtures

Inputs for the recordings in [`../`](..). Not real code.

- **`app.py`** is **intentionally vulnerable**: `/user` builds SQL by string concatenation.
  [`inline-review.tape`](../inline-review.tape) copies it into the demo project, asks Claude
  for an unrelated change, and shows the guard's inline xgrep review catching the injection
  so Claude fixes it in the same turn. The file itself carries no comment saying so: Claude
  reads it, and a note like that tells it to leave the bug alone.

xgrep treats `fixtures/` as test scope and doesn't report findings here; the copy in the
demo project is production scope.
