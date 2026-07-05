# sysmon-parser

A Python tool that parses Windows Sysmon Event ID 1 (Process Creation) XML logs and extracts key forensic fields as JSON.

## Requirements

- Python 3 (standard library only, no dependencies to install)

## Usage

```
python parser.py <path-to-sysmon-xml>
```

This prints a JSON object (single event) or JSON array (multiple events) to stdout.

### Input formats

`parser.py` accepts either:

- A single `<Event>` root element (one Sysmon log entry)
- An `<Events>` root wrapping multiple `<Event>` children (a batch of entries)

See `samples/` for examples of both.

### Extracted fields

- `EventID`
- `Computer`
- `UtcTime`
- `Image`
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Hashes`

### Write output to a file

```
python parser.py samples/event1.xml -o output.json
```

### Filtering

Filters can be combined; an event must match every filter supplied (AND logic). If no events match, the output is an empty JSON array (`[]`).

| Flag | Match type | Example |
|---|---|---|
| `--image` | substring, case-insensitive | `--image powershell` |
| `--user` | exact match, case-insensitive | `--user CORP\jsmith` |
| `--integrity-level` | exact match (`High`, `Medium`, `Low`, `System`) | `--integrity-level Medium` |
| `--command-line` | substring, case-insensitive | `--command-line=-enc` |

```
python parser.py samples/multi_events.xml --user CORP\jsmith
python parser.py samples/multi_events.xml --integrity-level Medium --image powershell
python parser.py samples/multi_events.xml --command-line=-enc
```

Note: if a filter value itself starts with `-` (e.g. `-enc`), use `--flag=value` syntax so it isn't parsed as another option.

## Samples

- `samples/event1.xml` — `whoami.exe /all` spawned from `cmd.exe`
- `samples/event2.xml` — `cmd.exe` spawning `powershell.exe`
- `samples/event3.xml` — a macro-enabled document (`WINWORD.EXE`) spawning `powershell.exe` with an encoded (`-enc`) command
- `samples/multi_events.xml` — all three events combined under a single `<Events>` root, for testing batch parsing

## Tests

```
python -m unittest test_parser -v
```
