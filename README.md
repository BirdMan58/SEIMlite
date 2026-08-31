# SEIMlite

A lightweight, self-contained SIEM for homelab operators. Single binary, zero config, real-time threat detection.

> **Project Status:** Active development. Not final. Contributions and feedback welcome.

## Service Support (In Progress)

- [x] SSH – monitoring, correlation, and process enforcement (complete)
- [ ] Nextcloud
- [ ] Pi-hole
- [ ] Jellyfin
- [ ] Vaultwarden

## Quick Start

```bash
git clone https://github.com/BirdMan58/SEIMlite.git
cd SEIMlite
go build -o build/SEIMlite cmd/SEIMlite/main.go
./build/SEIMlite -addr :9000 -config configs/ssh-config.json
```

Open `http://localhost:9000` for the dashboard.

## Features

- Automated service discovery (`/proc`, systemd, Docker)
- SSH session monitoring (process trees, resource usage, black/whitelist enforcement)
- Real‑time correlation engine with pluggable rules (brute‑force, root login, user enumeration, resource violations)
- Embedded SQLite storage
- Web dashboard with live WebSocket alerts and topology view
- API for alerts, services, stats, and dynamic config updates

## Architecture

- **Discovery** – identifies running services
- **Normalizer** – parses logs into structured events
- **Correlator** – evaluates rules and fires alerts
- **API + Dashboard** – serves UI and WebSocket updates

All components are Go routines; data persists in SQLite.

## Testing

```bash
go test ./...
```

## License

MIT