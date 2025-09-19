# Miles Syslog Server (with Roles, TCP/UDP, Retention, Realtime UI)

A production-friendly, self‑hosted syslog receiver and viewer:

- **Receives syslog over UDP and TCP** (RFC 3164 & RFC 5424 parsing; TCP supports octet-counted framing).
- **Persists events** to a SQL database (SQLite by default; any SQLAlchemy URI works).
- **Web UI** to review, filter, sort, and export events (CSV).
- **Management portal** with tabs: **Logs** (export, retention, purge) and **Users** (admin‑only).
- **Auth & Roles**: `admin`, `reviewer`, `user`. CSRF protection enabled.
- **Realtime panel** (refreshes every 10s), plus **sticky, mobile‑collapsible search**.
- **Auto‑install bootstrap**: missing Python deps are installed at start unless disabled.

---

## Contents

- [Quick Start (Local)](#quick-start-local)
- [Quick Start (Docker)](#quick-start-docker)
- [Sending Syslog to the Server](#sending-syslog-to-the-server)
- [Web UI Overview](#web-ui-overview)
- [Authentication & Roles](#authentication--roles)
- [Management Portal](#management-portal)
- [Configuration](#configuration)
- [CLI Commands](#cli-commands)
- [API](#api)
- [Data & Backups](#data--backups)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Quick Start (Local)

```bash
# 1) Run the app (auto-installs Flask and friends if missing)
python app.py

# Optional: disable auto-install to fail fast on missing deps
# SKIP_AUTO_PIP=1 python app.py
```

Then open: **http://localhost:8000**

By default the app listens for syslog on:
- UDP **:5514**
- TCP **:5515** (supports RFC 6587 octet-counted framing as well as newline‑delimited lines)

> First run creates a default admin: **meraki / merakimiles**.  
> Disable this by setting `CREATE_DEFAULT_ADMIN=0`.

---

## Quick Start (Docker)

```bash
docker build -t syslog-server .

docker run -d --name syslog   -e SECRET_KEY=$(python - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
)   -e CREATE_DEFAULT_ADMIN=1   -e RETENTION_CHECK_SECONDS=3600   -e DATABASE_URL=sqlite:////data/syslog.db   -p 8000:8000   -p 5514:5514/udp   -p 5515:5515   -v syslog_data:/data   syslog-server
```

Open **http://localhost:8000**. Data persists in the `syslog_data` volume.

---

## Sending Syslog to the Server

### Using `logger` (util-linux)
UDP:
```bash
logger --server 127.0.0.1 --port 5514 "hello from UDP"
```
TCP:
```bash
logger --server 127.0.0.1 --port 5515 --tcp "hello from TCP"
```

### Using `rsyslog`
Example `/etc/rsyslog.d/50-forward.conf`:
```
# UDP
*.* @your-server:5514
# TCP (reliable)
*.* @@your-server:5515
```
Restart rsyslog after saving:
```bash
sudo systemctl restart rsyslog
```

> The server understands both classic RFC 3164 and RFC 5424. For TCP it accepts RFC 6587 octet-counted framing; if length prefixes are missing it falls back to newline‑delimited lines.

---

## Web UI Overview

- **Events**: filter by host, app, source IP, protocol, severity/facility, text query, and time range. Sortable columns and pagination.
- **Realtime panel**: shows newest events and refreshes every **10s** (pause/clear controls).
- **Search bar**: sticky under the navbar, **collapsible on mobile** with a chevron toggle.
- **Event detail**: full message, metadata, and raw payload.
- **Export CSV**: respects current filters and sort.

---

## Authentication & Roles

- **admin**: full access, including user management and destructive deletes.
- **reviewer**: can view, filter, and export events (no delete operations).
- **user**: basic viewing only.

### Default admin
On first boot we create or update:
- **Username:** `meraki`
- **Password:** `merakimiles`
- Toggle with `CREATE_DEFAULT_ADMIN=0` in the environment.

---

## Management Portal

Open **Manage** (requires login). There are two tabs:

### Logs tab
- **Overview**: totals, last event, host count, export CSV.
- **Auto‑Purge (Retention)**: set `N` days; a background worker deletes events older than `N` every hour (configurable).
- **Delete older than N days**: one‑time purge button.
- **Delete EVERYTHING**: drops all events (irreversible).

### Users tab (admin‑only)
- **Create** users (choose role: user, reviewer, admin).
- **Reset password** and **change role** for existing users.
- **Delete** users (cannot delete yourself or the last remaining admin).

---

## Configuration

All configuration is via environment variables (defaults shown):

| Variable | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | `dev-change-me` | Flask session/CSRF key. **Set a strong value in production.** |
| `DATABASE_URL` | `sqlite:///syslog.db` (local) or `sqlite:////data/syslog.db` (Docker) | Any SQLAlchemy URL works (Postgres, MySQL, etc.). |
| `SYSLOG_HOST` | `0.0.0.0` | Bind address for syslog listeners. |
| `SYSLOG_PORT` | `5514` | UDP syslog port. |
| `SYSLOG_TCP_PORT` | `5515` | TCP syslog port. |
| `SYSLOG_ENABLE_UDP` | `1` | Set `0` to disable UDP listener. |
| `SYSLOG_ENABLE_TCP` | `1` | Set `0` to disable TCP listener. |
| `EXPORT_REQUIRES_LOGIN` | `1` | Require login for CSV export (recommended). |
| `CREATE_DEFAULT_ADMIN` | `1` | Auto-create `meraki/merakimiles` admin on boot; set `0` to disable. |
| `RETENTION_CHECK_SECONDS` | `3600` | How often the retention worker runs (seconds). |
| `PORT` | `8000` | Flask HTTP port (container/internal). |
| `SKIP_AUTO_PIP` | `0` | Set `1` to **disable** auto-install of missing Python deps on startup. |

> For Postgres: `DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/dbname` (install driver in your image).

---

## CLI Commands

Run from the project directory:

```bash
# Initialize database tables
flask --app app.py init-db

# Create or update a user
flask --app app.py create-user alice 'StrongPass123' --role reviewer
# roles: admin | reviewer | user
```

---

## API

### `GET /api/events/recent`
Returns recent events for the realtime panel.

Query params:
- `since_id` — only return events with `id` greater than this.
- `limit` — max number to return (default 20, max 200).

Example:
```
/api/events/recent?limit=20&since_id=12345
```

---

## Data & Backups

- Default SQLite file location:
  - Local: `./syslog.db`
  - Docker: `/data/syslog.db` (bind-mounted volume recommended: `-v syslog_data:/data`).
- Backups: stop the container/app or ensure DB is quiescent; copy the database file or use your RDBMS tools if on Postgres/MySQL.

---

## Security Notes

- **Change `SECRET_KEY`** and rotate it on schedule.
- Disable the default admin (`CREATE_DEFAULT_ADMIN=0`) and create your own accounts.
- Restrict listener exposure (e.g., run behind a reverse proxy/VPN; limit inbound ports at the firewall).
- Use HTTPS in front (nginx/traefik) for the web UI.
- Keep `EXPORT_REQUIRES_LOGIN=1` unless you explicitly want public exports.
- Consider adding rate limiting (e.g., `Flask-Limiter`) if exposed to untrusted networks.

---

## Troubleshooting

**Ports already in use**  
Change `SYSLOG_PORT` / `SYSLOG_TCP_PORT` or stop other services using those ports.

**No events appearing**  
- Verify the sender: `logger --server <host> --port 5514 "test"`
- Check container logs: `docker logs syslog`

**SQLite permission denied (Docker)**  
Ensure the `/data` directory is writable by the container user, or recreate the named volume.

**Healthcheck failing**  
Confirm the container can reach its own `http://localhost:8000/` and that the app started; inspect logs.

---

## License


