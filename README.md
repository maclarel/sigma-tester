# sigma-tester-macos

A lightweight CLI for real-time testing and development of [Sigma](https://sigmahq.io/) detection rules against macOS [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) events via `eslogger`.

It reads newline-delimited JSON from stdin, evaluates each event against all rules in `./rules/`, and writes matches as structured JSON to stdout.

## Usage

```bash
# Stream live events (requires appropriate entitlements or SIP configuration)
sudo eslogger exec fork | ./sigma-tester

# Point at a different rules directory
./sigma-tester /path/to/rules

# Replay a captured log
cat events.ndjson | ./sigma-tester
```

Operational output (loaded rules, warnings, final stats) goes to **stderr**. Only matches are written to **stdout**, so the two streams can be redirected independently.

## Writing Rules

Rules are standard Sigma YAML files placed in `./rules/` (`.yml` / `.yaml`). Field references should use dot-notation matching the raw `eslogger` JSON structure:

```yaml
title: Process Execution from Temporary Directory
status: test
logsource:
  product: macos
  category: process_creation
detection:
  selection_event:
    event_type: exec
  selection_path:
    event.exec.target.executable.path|startswith:
      - '/tmp/'
      - '/private/tmp/'
  condition: selection_event and selection_path
level: high
```

### Field Flattening

Nested JSON objects are flattened to dot-notation keys (`a.b.c`). Arrays are stored at both indexed keys (`args.0`, `args.1`, …) and as a space-joined string at the parent key, so `|contains` works across all elements without per-index references:

```yaml
event.exec.args|contains: ' --output '
```

### Derived Fields

`eslogger` reports `event_type` as a numeric ES framework constant (e.g. `9` for exec). A synthetic `event_type_name` field is added to each event by inspecting the key present inside the `event` object, giving a human-readable string for use in rules:

```yaml
event_type_name: exec   # instead of event_type: 9
```

Common values: `exec`, `fork`, `exit`, `open`, `close`, `create`, `rename`, `unlink`, `write`.

### Keyword Detections

The full raw JSON line is stored in `LogEntry.Message`, so bare keyword detections (no field name) match against the entire event body.

## Match Output Format

Each match is a JSON object written to stdout:

```json
{
  "timestamp": "2026-03-17T21:02:22Z",
  "rule": {
    "title": "Process Execution from Temporary Directory",
    "id": "7e3f1a2b-...",
    "level": "high",
    "tags": ["attack.execution", "attack.t1036.005"]
  },
  "event": { ... original eslogger event ... }
}
```

## Building

```bash
go build -o sigma-tester .
```

Requires Go 1.23+.

## Credits

Sigma rule parsing and evaluation is provided by [**sigmalite**](https://github.com/runreveal/sigmalite) by [RunReveal](https://github.com/runreveal), licensed under the Apache 2.0 License.
