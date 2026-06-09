# Render deploy guide — IPMG In-Person Day Log

This package is a Render-ready Node/Express web service for the shared day-log workspace.

## Important storage note

The app saves shared appointment state to JSON files. On Render, you should attach a **Persistent Disk** and set:

```text
DATA_DIR=/var/data/daylog
```

The included `render.yaml` creates a 1 GB disk at `/var/data`. Without a persistent disk, Render's filesystem is ephemeral and data can be lost on redeploy/restart.

## Deploy using GitHub + Blueprint

1. Create a private GitHub repo, e.g. `ipmg-daysheet`.
2. Upload all files from this folder to the repo root.
3. Go to Render → **New** → **Blueprint**.
4. Connect the repo.
5. Render will read `render.yaml`.
6. Enter the secret environment variables when prompted:

```text
DAYLOG_PASSWORD = strong shared password
SESSION_SECRET = long random secret, 40+ characters
ALLOWED_IPS = optional, e.g. 203.0.113.10/32
```

7. Deploy.
8. Open the Render URL and test `/healthz`.
9. Open the main URL and confirm the password screen loads.

## Manual Web Service setup

If you do not use Blueprint:

- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`
- Add a persistent disk:
  - Mount path: `/var/data`
  - Size: `1 GB`
- Environment variables:
  - `DAYLOG_PASSWORD`
  - `SESSION_SECRET`
  - `DATA_DIR=/var/data/daylog`
  - `DAYLOG_TIMEZONE=America/Los_Angeles`
  - `RETENTION_BACKUPS=true`
  - `ALLOWED_IPS=your.office.ip/32` optional

## IP restriction note

This build includes app-level IP restriction through `ALLOWED_IPS`.
Use CIDR notation, comma-separated:

```text
ALLOWED_IPS=203.0.113.10/32,198.51.100.0/24
```

If blank, the password screen is accessible from any IP.

Render also has platform-level inbound IP rules, but those may require higher-tier workspace options. The app-level `ALLOWED_IPS` gate is included so a small clinic can still do a practical first version.

## Daily retention behavior

The server keeps today's appointments and future appointments. Past-dated rows are purged after local midnight based on:

```text
DAYLOG_TIMEZONE=America/Los_Angeles
```

Backups are saved before purge when:

```text
RETENTION_BACKUPS=true
```
