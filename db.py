"""SQLite database layer for NetWatch."""
from __future__ import annotations

import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.environ.get("NETWATCH_DB", os.path.join(os.path.dirname(__file__), "netwatch.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                hostname TEXT DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'online'
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_at TEXT NOT NULL,
                device_count INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_taken_at ON snapshots(taken_at);

            CREATE TABLE IF NOT EXISTS netwatch_live_incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT    NOT NULL,
                sender      TEXT    NOT NULL,
                subject     TEXT    DEFAULT '',
                domain      TEXT    NOT NULL,
                mino_verdict TEXT   NOT NULL,   -- LEGIT | SUSPICIOUS | FORGERY
                trust_score INTEGER NOT NULL DEFAULT 0,
                verdict_detail TEXT DEFAULT '',
                flags       TEXT    DEFAULT '[]',  -- JSON array of flag strings
                raw_result  TEXT    DEFAULT '{}'   -- full inspect() result JSON
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_received_at
                ON netwatch_live_incidents(received_at);
        """)
        # Migration: add source_ref column to existing DBs that predate this schema
        cols = {r[1] for r in conn.execute("PRAGMA table_info(netwatch_live_incidents)").fetchall()}
        if "source_ref" not in cols:
            conn.execute("ALTER TABLE netwatch_live_incidents ADD COLUMN source_ref TEXT DEFAULT ''")
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_source_ref "
                "ON netwatch_live_incidents(source_ref) WHERE source_ref != ''"
            )
        except Exception:
            pass


def upsert_devices(devices: list[dict]):
    """Insert or update devices; mark previously-seen devices not in this scan as offline."""
    if not devices:
        return
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        # Mark all currently-online devices as offline first
        conn.execute("UPDATE devices SET status='offline' WHERE status='online'")

        for d in devices:
            mac = d.get("mac") or ""
            ip = d.get("ip", "")
            hostname = d.get("hostname", "")

            if mac:
                # Upsert by MAC
                existing = conn.execute(
                    "SELECT first_seen FROM devices WHERE mac=?", (mac,)
                ).fetchone()
                first_seen = existing["first_seen"] if existing else now
                conn.execute(
                    """INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, status)
                       VALUES (?, ?, ?, ?, ?, 'online')
                       ON CONFLICT(mac) DO UPDATE SET
                           ip=excluded.ip,
                           hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
                           last_seen=excluded.last_seen,
                           status='online'
                    """,
                    (mac, ip, hostname, first_seen, now),
                )
            else:
                # No MAC — upsert by IP
                existing = conn.execute(
                    "SELECT mac, first_seen FROM devices WHERE ip=? AND mac=''", (ip,)
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE devices SET hostname=COALESCE(NULLIF(?, ''), hostname),
                               last_seen=?, status='online' WHERE ip=? AND mac=''""",
                        (hostname, now, ip),
                    )
                else:
                    conn.execute(
                        """INSERT OR IGNORE INTO devices (mac, ip, hostname, first_seen, last_seen, status)
                           VALUES ('', ?, ?, ?, ?, 'online')""",
                        (ip, hostname, now, now),
                    )

        # Record snapshot
        online_count = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE status='online'"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO snapshots (taken_at, device_count) VALUES (?, ?)",
            (now, online_count),
        )


def get_devices(status: str | None = None) -> list[dict]:
    with get_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM devices WHERE status=? ORDER BY ip", (status,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY status DESC, ip"
            ).fetchall()
    return [dict(r) for r in rows]


def get_snapshots(hours: int = 24) -> list[dict]:
    """Return snapshots from the last N hours, bucketed by hour."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00', taken_at) AS hour,
                   MAX(device_count) AS max_count,
                   AVG(device_count) AS avg_count
            FROM snapshots
            WHERE taken_at >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
            """,
            (f"-{hours} hours",),
        ).fetchall()
    return [dict(r) for r in rows]


def get_new_devices(days: int = 7) -> list[dict]:
    """Return new devices discovered in the last N days, grouped by day."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT strftime('%Y-%m-%d', first_seen) AS day,
                   COUNT(*) AS new_count
            FROM devices
            WHERE first_seen >= datetime('now', ?)
            GROUP BY day
            ORDER BY day
            """,
            (f"-{days} days",),
        ).fetchall()
    return [dict(r) for r in rows]


def get_device_counts_by_day(days: int = 7) -> list[dict]:
    """Return total devices connected on each day for the last N days (from snapshots, with interpolation for missing days)."""
    result = []
    from datetime import datetime, timedelta
    
    # Get all snapshots grouped by day
    with get_conn() as conn:
        daily_data = conn.execute(
            """
            SELECT strftime('%Y-%m-%d', taken_at) AS day,
                   AVG(device_count) AS avg_count
            FROM snapshots
            GROUP BY day
            ORDER BY day
            """,
        ).fetchall()
    
    daily_counts = {r['day']: int(r['avg_count']) for r in daily_data}
    
    # For each of the last 7 days, find the count
    for i in range(days - 1, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        
        if date in daily_counts:
            # We have data for this day
            count = daily_counts[date]
        else:
            # No scans this day - find the most recent prior day with data
            count = 0
            for prev_date in sorted(daily_counts.keys()):
                if prev_date <= date:
                    count = daily_counts[prev_date]
                else:
                    break
        
        result.append({
            'day': date,
            'device_count': count
        })
    return result


def cleanup_fake_devices() -> None:
    """Remove multicast, link-local, and placeholder entries from database."""
    with get_conn() as conn:
        # Delete multicast IPs (224.x.x.x, 239.x.x.x)
        conn.execute("DELETE FROM devices WHERE ip LIKE '224.%' OR ip LIKE '239.%'")
        # Delete link-local IPs (169.254.x.x)
        conn.execute("DELETE FROM devices WHERE ip LIKE '169.254.%'")
        # Delete empty MACs
        conn.execute("DELETE FROM devices WHERE mac = ''")
        # Delete placeholder MACs
        conn.execute("DELETE FROM devices WHERE mac = '00:00:00:00:00:00'")
        # Delete multicast MACs (01:00:5E:xx:xx:xx)
        conn.execute("DELETE FROM devices WHERE mac LIKE '01:00:5E:%'")


# ── Live Incidents (webhook-ingested emails) ──────────────────────────────────

def store_live_incident(
    sender: str,
    subject: str,
    domain: str,
    mino_verdict: str,
    trust_score: int,
    verdict_detail: str,
    flags: list,
    raw_result: dict,
    received_at: str = "",
    source_ref: str = "",
) -> int:
    """Insert a new live incident row; return its id (0 if skipped as duplicate)."""
    import json as _json
    ts = received_at or datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO netwatch_live_incidents
               (received_at, sender, subject, domain, mino_verdict,
                trust_score, verdict_detail, flags, raw_result, source_ref)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, sender, subject, domain, mino_verdict,
             trust_score, verdict_detail,
             _json.dumps(flags), _json.dumps(raw_result), source_ref),
        )
    return cur.lastrowid or 0


def get_live_incidents(limit: int = 100) -> list[dict]:
    """Return the most recent incidents, newest first."""
    import json as _json
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, received_at, sender, subject, domain, mino_verdict,
                      trust_score, verdict_detail, flags
               FROM netwatch_live_incidents
               ORDER BY received_at DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["flags"] = _json.loads(d["flags"] or "[]")
        except Exception:
            d["flags"] = []
        result.append(d)
    return result


def get_stats() -> dict:
    with get_conn() as conn:
        online = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE status='online'"
        ).fetchone()["c"]
        total = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"]
        latest_snapshot = conn.execute(
            "SELECT taken_at FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "online": online,
        "total": total,
        "last_scan": latest_snapshot["taken_at"] if latest_snapshot else None,
    }
