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

JSON — a single object per event, or a JSON array when parsing multiple events.

## Status

No source files, build configuration, or tests exist yet. This section will be replaced with build/lint/test commands and architecture notes once code is added.
