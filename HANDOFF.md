# Handoff: sysmon-parser

## What we built

A standalone Python script (`parser.py`, stdlib only — no dependencies) that parses Windows Sysmon Event ID 1 (Process Creation) XML logs and extracts key forensic fields into JSON:

`EventID`, `Computer`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Hashes`.

It accepts either a single `<Event>` XML file or a batch `<Events>` file wrapping multiple `<Event>` entries, and supports filtering by image, user, integrity level, and command line.

Also included:
- `samples/` — four realistic fixture files (`event1.xml`: whoami execution, `event2.xml`: cmd → powershell, `event3.xml`: macro doc → encoded PowerShell, `multi_events.xml`: all three combined under one `<Events>` root)
- `test_parser.py` — 16 unit tests (parsing, filtering, CLI behavior via subprocess)
- `README.md` — usage documentation
- `CLAUDE.md` — guidance for future Claude Code sessions in this repo

Git repo is initialized locally (3 commits: parser, README, tests) but **not yet pushed to a remote** — see "What's left" below.

## How to use it

```
python parser.py samples/event1.xml
python parser.py samples/multi_events.xml -o output.json
python parser.py samples/multi_events.xml --user CORP\jsmith
python parser.py samples/multi_events.xml --integrity-level Medium --image powershell
python parser.py samples/multi_events.xml --command-line=-enc
python -m unittest test_parser -v
```

Full flag reference is in `README.md`.

## What's left to do

- **Push to a remote.** We were about to run `gh repo create` when this was interrupted — `gh` isn't on PATH in the bash shell here; needs to be checked/run from PowerShell (or another shell where `gh` is installed), and `gh auth status` hadn't been confirmed yet.
- No error handling for malformed XML or a missing/unreadable input file — currently these just raise a raw Python traceback instead of a clean CLI error message.
- No support for other Sysmon Event IDs (e.g. Event ID 3 network connections, Event ID 11 file creation) — scope was deliberately limited to Event ID 1 (Process Creation).
- `--command-line` (and the other filters) only support a single substring/value each — multi-value OR filtering (e.g. matching several command-line substrings in one invocation) was explicitly considered and deferred (see decisions below).
- No packaging (`pyproject.toml`/`setup.py`) — it's run directly as a script, not installed as a package.

## Decisions made and why

- **Stdlib only** (`xml.etree.ElementTree`, `argparse`, `json`) — keeps the tool dependency-free and simple to run anywhere Python 3 is available.
- **Single vs. batch input handled by root tag detection** (`<Event>` vs `<Events>`) rather than requiring two separate code paths/flags — one script transparently handles both real-world export shapes.
- **Output shape reflects match count, not input shape**: exactly one matching event → JSON object; zero or multiple → JSON array (including `[]` when a filter excludes everything). This was chosen so downstream consumers get predictable, count-driven JSON shape rather than having to special-case "did the input file have one `<Event>` or many."
- **Filters combine with AND, not OR.** Simpler mental model; if you need OR semantics you run the command multiple times or post-process the JSON.
- **`--image` and `--user` are case-insensitive**; Windows paths and domain\username values vary in case in practice, so exact-case matching would be surprising and error-prone.
- **`--integrity-level` uses argparse `choices`** restricted to the four real Sysmon values (`High`/`Medium`/`Low`/`System`) so typos fail fast with a clear error instead of silently matching nothing.
- **`--command-line` is a single substring filter, not multi-value OR.** When asked about filtering on "encoded" or "-enc", we deliberately chose the simpler option: a single substring (e.g. `-enc`) already catches both cases since `-enc` is itself a substring of `-encodedcommand`. Multi-value OR filtering was considered but explicitly deferred as unnecessary complexity.
- **`output.json` is gitignored** — it's a generated artifact from manual testing, not source, so it's excluded via `.gitignore` rather than committed.
- **Sample "suspicious" XML uses an RFC 5737 documentation-range IP** (`192.0.2.10`) in the encoded PowerShell command so the fixture is realistic-looking but inert/non-functional (won't resolve or do anything if anyone actually ran it).
- **Git identity was set locally (repo-scoped), not globally** — `user.name`/`user.email` were configured only for this repo (Dana Stubben / dana.stubben@tregardlabs.com) rather than touching global git config.
