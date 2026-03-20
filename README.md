# spectre

SPECTRE is a Redis-streamed security assessment pipeline with Go and Python microservices.

## Runtime Notes

The new frontend-triggered RASM flow and backend attack planner call external tooling when it is available in the service runtime:

- `katana`
- `ParamSpider`
- `enumapis`
- `Arjun` / `arjun`
- `sqlmap`
- `nuclei`

The code degrades safely when a binary is missing by publishing a warning event instead of failing the session. For full RASM and backend attack execution inside containers, install those binaries in the relevant service images before deployment.
