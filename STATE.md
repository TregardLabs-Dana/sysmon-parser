# Project State

Snapshot as of 2026-07-05.

## Repo

Pushed to remote: https://github.com/TregardLabs-Dana/sysmon-parser (`origin/master`, up to date).

Note: commit hashes were rewritten once via `git filter-branch` to fix commit author/committer email (GitHub rejected the initial push over its email-privacy protection) before the push succeeded — the hashes below are the current, pushed ones, and won't match any hashes referenced in earlier notes.

Latest commits (newest first):

```
c269e3b Add --format flag (json/jsonl/csv) with tests
64ae071 Update STATE.md to reflect current repo state
10a46e6 Add STATE.md and update CLAUDE.md with architecture notes
e4830e3 Add HANDOFF.md
cc6133f Add unit tests for parser.py
2735661 Add README with usage instructions
9026bf6 Add Sysmon Event ID 1 XML parser
```

## Working tree

Clean — matches `origin/master`.

## Files

- `parser.py` — the CLI tool (`--format json|jsonl|csv`, filters, `-o`)
- `test_parser.py` — 26 unit tests, all passing
- `samples/` — `event1.xml`, `event2.xml`, `event3.xml`, `multi_events.xml`
- `README.md`, `CLAUDE.md`, `HANDOFF.md`, `STATE.md` — documentation
- `.gitignore` — excludes `output.json` and `__pycache__/`
- `output.json`, `__pycache__/` — present locally from manual runs, gitignored (not tracked)

## Outstanding

- None currently tracked. See `HANDOFF.md` for the fuller list of longer-term gaps (error handling, other Event IDs, packaging) and the design decisions behind the current implementation.
