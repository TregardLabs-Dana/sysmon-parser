# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Sysmon Parser — a Python tool that parses Windows Sysmon XML event logs and extracts key fields from Event ID 1 (Process Creation) events, emitting the results as JSON.

### Fields extracted (Event ID 1)

- EventID
- UtcTime
- Image (process path)
- CommandLine
- User
- IntegrityLevel
- ParentImage
- ParentCommandLine
- Computer
- Hashes

### Output

JSON — a single object when exactly one event matches, otherwise a JSON array (including an empty array `[]` when filters exclude every event). Output shape is driven by match count, not by whether the input file had a single `<Event>` root or a batch `<Events>` root.

## Architecture

- **Parsing**: `xml.etree.ElementTree` (stdlib) — no external dependencies. `parse_file()` detects a single `<Event>` root vs. a batch `<Events>` root (via `root.tag.endswith("Events")`) and always returns a list of parsed event dicts internally; `main()` collapses that list to a single dict or leaves it as an array based on match count after filtering.
- **Field extraction**: `parse_event()` pulls `EventID`/`Computer` from `System`, and the rest of `FIELDS` from `EventData/Data[@Name]` elements, defaulting to `None` when a field is absent.

### Filter flags (CLI)

All filters are optional and combine with **AND** semantics — an event must satisfy every filter supplied to be included:

- `--image` — substring match on `Image`, case-insensitive
- `--user` — exact match on `User`, case-insensitive
- `--integrity-level` — exact match on `IntegrityLevel`; constrained via argparse `choices` to `High`/`Medium`/`Low`/`System` so typos fail fast
- `--command-line` — substring match on `CommandLine`, case-insensitive (deliberately single-value only, not multi-value OR — e.g. filtering on `-enc` already catches `-encodedcommand` since one is a substring of the other)

Implemented in `filter_events()`, applied after parsing and before the dict/array collapse in `main()`.

## Commands

```
python parser.py <path-to-sysmon-xml>              # parse, print JSON to stdout
python parser.py <path> -o output.json             # write JSON to a file instead
python -m unittest test_parser -v                  # run the test suite
```
