# netwatch - Project Manifest

## Overview
Network device monitoring and email scam detection system.

## Primary Human Contact
- **Andy** (Discord ID: 729578557419945984)

## Collaborators
- **Verta** - AI coordinator/PM
- **Meno** - AI assistant (collaborated with Andy)

## Documents
| Type | Path | Auto-load? | Description |
|------|------|------------|-------------|
| README | README.md | ✅ | Project overview |
| Core App | app.py | ✅ | Main application logic |
| Database | db.py | ✅ | Database schema & queries |
| Scanner | scanner.py | ✅ | Network device scanner |
| Email Protection | email_scams.py | ✅ | Phishing/scam detection |
| Dashboard | dashboard.py | ✅ | Web dashboard UI |
| Server | server.py | ✅ | HTTP server |

## Agent Rules
- Before network scan changes → read `scanner.py` + `db.py`
- Before email detection changes → read `email_scams.py` + review `email_scans/`
- Before UI changes → read `dashboard.py` + `index.html`
- After major decisions → log to `memory/decisions.md` (create if needed)
- Check `devices.json` and `history.json` for current state

## Current Status
- Last updated: 2026-03-21
- Active agents: verta, meno
- Location: `~/.openclaw/workspace/projects/netwatch`
- Database: netwatch.db (SQLite)
- Live data: devices.json, history.json

## External Dependencies
- PhishTank cache: `~/.openclaw/.phishtank_cache.json` (56K+ URLs)
- Guarded tools for email sending

## Known Files
- `email_scans/` - Scan results directory
- `sandbox/` - Email sandbox isolation
- `index.html` - Dashboard UI (59KB)
