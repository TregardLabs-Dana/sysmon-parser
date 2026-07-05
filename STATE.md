# Project State

Snapshot as of 2026-07-05.

## Repo

Local git repo, no remote configured yet (`gh repo create` was started but interrupted before completion — see `HANDOFF.md`).

Latest commits (newest first):

```
0a30cf9 Add STATE.md and update CLAUDE.md with architecture notes
9676e39 Add HANDOFF.md
c765cf2 Add unit tests for parser.py
dca15bf Add README with usage instructions
c314822 Add Sysmon Event ID 1 XML parser
```

## Working tree

Clean — matches the last commit (`0a30cf9`).

## Files

- `parser.py` — the CLI tool
- `test_parser.py` — 16 unit tests, all passing
- `samples/` — `event1.xml`, `event2.xml`, `event3.xml`, `multi_events.xml`
- `README.md`, `CLAUDE.md`, `HANDOFF.md`, `STATE.md` — documentation
- `.gitignore` — excludes `output.json` and `__pycache__/`
- `output.json`, `__pycache__/` — present locally from manual runs, gitignored (not tracked)

## Outstanding

- Push to a remote — need to confirm `gh` CLI availability/auth (last check found `gh` not on PATH in the bash shell; not yet retried in PowerShell) and run `gh repo create`.
- See `HANDOFF.md` for the fuller list of what's left to do and the design decisions behind the current implementation.
