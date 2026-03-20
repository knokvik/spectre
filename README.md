# spectre

SPECTRE is a Redis-streamed security assessment pipeline with Go and Python microservices.

## Local Launch

1. Start Redis:

```bash
redis-server
```

2. Start the services:

```bash
cd /Users/nirajrajendranaphade/Programming/spectre
./start_local.sh
```

3. Launch the CLI in another terminal:

```bash
cd /Users/nirajrajendranaphade/Programming/spectre/spectre-cli
go run .
go run . doctor
go run . scan http://127.0.0.1:3000
```

`go run .` opens the interactive terminal menu. `go run . scan ...` starts a session directly and, unless `--detach` is used, follows the live session output in the terminal.

4. Open the UI directly if needed:

```bash
cd /Users/nirajrajendranaphade/Programming/spectre/spectre-cli
go run . ui
```

## CLI Commands

The new CLI is intentionally thin and talks to the API gateway and intel service instead of reimplementing the pipeline:

- `go run . scan <target>`
- `go run . watch <session_id>`
- `go run . ui`
- `go run . session list`
- `go run . session status <session_id>`
- `go run . session approve <session_id>`
- `go run . session decline <session_id>`
- `go run . session stop <session_id>`
- `go run . intel <cve>`
- `go run . doctor`

## Runtime Notes

The new frontend-triggered RASM flow and backend attack planner call external tooling when it is available in the service runtime:

- `katana`
- `ParamSpider`
- `enumapis`
- `Arjun` / `arjun`
- `sqlmap`
- `nuclei`

The code degrades safely when a binary is missing by publishing a warning event instead of failing the session. For full RASM and backend attack execution inside containers, install those binaries in the relevant service images before deployment.

## SploitScan Integration

Threat intelligence enrichment is handled by `intel-service`, which can optionally call SploitScan without copying its code into this repository.

Set one of these:

- `SPLOITSCAN_PATH=/absolute/path/to/sploitscan.py`
- `SPLOITSCAN_PATH=/absolute/path/to/sploitscan/repo`
- `SPLOITSCAN_PATH=/absolute/path/to/sploitscan-executable`

Then query intelligence from the CLI:

```bash
cd /Users/nirajrajendranaphade/Programming/spectre/spectre-cli
SPLOITSCAN_PATH=/absolute/path/to/sploitscan.py go run . intel CVE-2023-1234
```

At this stage, SploitScan is used for enrichment, session persistence, and scoring inputs. It is not yet changing attack execution order.
