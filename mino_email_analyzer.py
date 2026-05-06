#!/usr/bin/env python3
"""
mino_email_analyzer.py — Mino batch email security scanner.

Fetches recent emails from Gmail (IMAP) and Outlook (Graph API),
runs each through the NetWatch email inspector (Tier 1, fast mode),
and stores results in netwatch_live_incidents for the Live Incidents widget.

Deduplication: source_ref = "gmail:<imap_uid>" / "outlook:<msg_id_hash>"
so re-running the script is safe and idempotent.

Usage:
    python3 mino_email_analyzer.py            # scan both inboxes
    python3 mino_email_analyzer.py gmail      # Gmail only
    python3 mino_email_analyzer.py outlook    # Outlook only
    python3 mino_email_analyzer.py --limit 50 # cap per inbox (default 100)
"""

from __future__ import annotations

import sys
import os
import re
import json
import imaplib
import email as _email_lib
import hashlib
import argparse
from email.header import decode_header
from datetime import datetime, timezone
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from email_inspector import inspect as _ei_inspect   # noqa: E402
from db import init_db, store_live_incident           # noqa: E402

# ── Auth paths (same as existing scripts) ────────────────────────────────────
GMAIL_APP_PASSWORD_FILE = os.path.expanduser("~/.verta_gmail_app_password")
GMAIL_ADDRESS           = "vertajxiao@gmail.com"
OUTLOOK_TOKEN_FILE      = os.path.expanduser("~/.verta_outlook_token.json")
OUTLOOK_CLIENT_ID       = "a61614ad-2c7e-46ae-ac3e-ff37ff23539c"
OUTLOOK_TENANT          = "consumers"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _decode_header_val(raw: str) -> str:
    """Decode RFC-2047 encoded header value to plain unicode."""
    parts = []
    for chunk, enc in decode_header(raw or ""):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(enc or "utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


def _classify_verdict(result: dict) -> tuple[str, list[str]]:
    """Lightweight FORGERY/SUSPICIOUS/LEGIT classifier (mirrors server._classify_mino_verdict)."""
    verdict = (result.get("verdict") or "").upper()
    score   = result.get("trust_score", 50)
    sa      = result.get("subject_alignment") or {}
    ha      = result.get("header_audit")      or {}
    flags: list[str] = []

    if sa.get("alignment_status") == "BRAND_DISSONANCE":
        brands = ", ".join(b.split(".")[0].title() for b in (sa.get("extracted_brands") or [])[:2])
        flags.append(f"Brand Dissonance — {brands or 'corporate brand'} claimed via consumer inbox")

    if ha.get("status") == "SECONDARY_HEADER_SPOOFING":
        addrs = ", ".join((ha.get("flagged_addresses") or [])[:2])
        flags.append(f"Header Ghosting — {addrs}")

    _forgery_kw = ("CRITICAL", "FORGERY", "GHOST", "BEC", "SPOOFING", "DISSONANCE", "NON-EXISTENT")
    if any(kw in verdict for kw in _forgery_kw):
        if not flags:
            flags.append(result.get("verdict", verdict))
        return "FORGERY", flags

    if flags:
        return "FORGERY", flags

    sus_flags: list[str] = []
    if score < 50:
        sus_flags.append(f"Low trust score ({score}/100)")
    sa_status = sa.get("alignment_status", "")
    if sa_status in ("MISALIGNED", "IDENTITY_THEFT", "HIGH_RISK_BILLING"):
        sus_flags.append(f"Subject alignment: {sa_status}")
    if "SUSPICIOUS" in verdict:
        sus_flags.append(result.get("verdict", ""))

    if sus_flags:
        return "SUSPICIOUS", sus_flags

    return "LEGIT", []


def _analyze_and_store(
    sender: str,
    subject: str,
    cc_bcc: str,
    received_at: str,
    source_ref: str,
) -> str:
    """Run Tier-1 inspection and persist; returns mino_verdict or 'SKIPPED'."""
    if not sender:
        return "SKIPPED"

    try:
        result = _ei_inspect(
            sender,
            realtime=True,
            run_tier2=False,   # fast mode — no DNS deep-dive for batch scan
            subject=subject,
            cc_bcc=cc_bcc,
        )
    except Exception as exc:
        print(f"  [warn] inspect() failed for {sender}: {exc}", file=sys.stderr)
        return "SKIPPED"

    mino_verdict, flags = _classify_verdict(result)

    domain = result.get("domain", "")
    if not domain:
        m = re.search(r"@([\w.\-]+)", sender)
        domain = m.group(1).lower() if m else sender

    row_id = store_live_incident(
        sender        = sender,
        subject       = subject,
        domain        = domain,
        mino_verdict  = mino_verdict,
        trust_score   = result.get("trust_score", 0),
        verdict_detail= result.get("verdict", ""),
        flags         = flags,
        raw_result    = {
            "source":     source_ref.split(":")[0],
            "verdict":    result.get("verdict"),
            "trust_score": result.get("trust_score"),
            "tier1":      result.get("tier1"),
        },
        received_at   = received_at,
        source_ref    = source_ref,
    )

    status = "NEW" if row_id else "DUP"
    return f"{mino_verdict}({status})"


# ── Gmail scanner ─────────────────────────────────────────────────────────────

def scan_gmail(limit: int = 100) -> dict:
    """Fetch recent Gmail messages and run Mino analysis."""
    stats = {"scanned": 0, "new": 0, "skipped": 0, "errors": 0}

    try:
        app_password = open(GMAIL_APP_PASSWORD_FILE).read().strip()
    except FileNotFoundError:
        print("[gmail] App password not found — skipping Gmail scan.", file=sys.stderr)
        return stats

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(GMAIL_ADDRESS, app_password)
    except Exception as exc:
        print(f"[gmail] IMAP login failed: {exc}", file=sys.stderr)
        return stats

    folders_to_scan = [("INBOX", "inbox"), ("[Gmail]/Spam", "spam")]

    for folder, folder_label in folders_to_scan:
        try:
            mail.select(folder, readonly=True)
        except Exception:
            continue

        _, data = mail.search(None, "ALL")
        all_ids = data[0].split() if data[0] else []
        recent = all_ids[-limit:]   # most recent N

        print(f"[gmail] {folder_label}: {len(all_ids)} total, scanning last {len(recent)}")

        for imap_uid in recent:
            uid_str = imap_uid.decode()
            source_ref = f"gmail:{folder_label}:{uid_str}"

            try:
                _, msg_data = mail.fetch(imap_uid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
            except Exception as exc:
                stats["errors"] += 1
                continue

            try:
                msg = _email_lib.message_from_bytes(raw)
                sender   = _decode_header_val(msg.get("From", ""))
                subject  = _decode_header_val(msg.get("Subject", ""))
                cc       = _decode_header_val(msg.get("Cc", ""))
                bcc      = _decode_header_val(msg.get("Bcc", ""))
                date_str = msg.get("Date", "")
                cc_bcc   = ", ".join(filter(None, [cc, bcc]))

                # Parse date → ISO
                try:
                    from email.utils import parsedate_to_datetime
                    received_at = parsedate_to_datetime(date_str).isoformat()
                except Exception:
                    received_at = datetime.now(timezone.utc).isoformat()

            except Exception as exc:
                stats["errors"] += 1
                continue

            stats["scanned"] += 1
            verdict = _analyze_and_store(sender, subject, cc_bcc, received_at, source_ref)
            if verdict == "SKIPPED":
                stats["skipped"] += 1
            elif "(NEW)" in verdict:
                stats["new"] += 1
                print(f"  {verdict:20s} {sender[:40]:40s} | {subject[:35]}")

    try:
        mail.close()
        mail.logout()
    except Exception:
        pass

    return stats


# ── Outlook scanner ───────────────────────────────────────────────────────────

def _refresh_outlook_token() -> str:
    """Refresh OAuth token and return new access_token."""
    import requests
    with open(OUTLOOK_TOKEN_FILE) as f:
        tokens = json.load(f)
    r = requests.post(
        f"https://login.microsoftonline.com/{OUTLOOK_TENANT}/oauth2/v2.0/token",
        data={
            "grant_type":    "refresh_token",
            "client_id":     OUTLOOK_CLIENT_ID,
            "refresh_token": tokens["refresh_token"],
            "scope":         "offline_access openid profile Mail.ReadWrite",
        },
        timeout=15,
    )
    r.raise_for_status()
    new_tokens = r.json()
    with open(OUTLOOK_TOKEN_FILE, "w") as f:
        json.dump(new_tokens, f)
    os.chmod(OUTLOOK_TOKEN_FILE, 0o600)
    return new_tokens["access_token"]


def scan_outlook(limit: int = 100) -> dict:
    """Fetch recent Outlook messages and run Mino analysis."""
    import requests

    stats = {"scanned": 0, "new": 0, "skipped": 0, "errors": 0}

    if not os.path.exists(OUTLOOK_TOKEN_FILE):
        print("[outlook] Token file not found — skipping Outlook scan.", file=sys.stderr)
        return stats

    try:
        access_token = _refresh_outlook_token()
    except Exception as exc:
        print(f"[outlook] Token refresh failed: {exc}", file=sys.stderr)
        return stats

    headers = {"Authorization": f"Bearer {access_token}"}
    folders_to_scan = [
        ("me/messages", "inbox"),
        ("me/mailFolders/junkemail/messages", "junk"),
    ]

    for endpoint, folder_label in folders_to_scan:
        url = (
            f"https://graph.microsoft.com/v1.0/{endpoint}"
            f"?$top={min(limit, 50)}"
            f"&$select=id,receivedDateTime,from,subject,ccRecipients,bccRecipients,toRecipients"
            f"&$orderby=receivedDateTime desc"
        )
        fetched = []
        page = 0
        while url and page < (limit // 50 + 1):
            try:
                r = requests.get(url, headers=headers, timeout=20)
                if r.status_code == 401:
                    # Token expired mid-batch — refresh once and retry
                    access_token = _refresh_outlook_token()
                    headers["Authorization"] = f"Bearer {access_token}"
                    r = requests.get(url, headers=headers, timeout=20)
                r.raise_for_status()
                data = r.json()
                fetched.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                page += 1
                if len(fetched) >= limit:
                    break
            except Exception as exc:
                print(f"[outlook] Fetch error ({folder_label}): {exc}", file=sys.stderr)
                break

        print(f"[outlook] {folder_label}: fetched {len(fetched)} messages")

        for msg in fetched[:limit]:
            msg_id     = msg.get("id", "")
            source_ref = f"outlook:{folder_label}:{hashlib.sha1(msg_id.encode()).hexdigest()[:16]}"

            from_info  = (msg.get("from") or {}).get("emailAddress", {})
            name       = from_info.get("name", "")
            addr       = from_info.get("address", "")
            sender     = f"{name} <{addr}>" if name else addr

            subject    = msg.get("subject", "")
            received   = msg.get("receivedDateTime", "")

            def _addrs(key):
                return ", ".join(
                    r.get("emailAddress", {}).get("address", "")
                    for r in (msg.get(key) or [])
                )

            cc_bcc = ", ".join(filter(None, [_addrs("ccRecipients"), _addrs("bccRecipients")]))

            stats["scanned"] += 1
            verdict = _analyze_and_store(sender, subject, cc_bcc, received, source_ref)
            if verdict == "SKIPPED":
                stats["skipped"] += 1
            elif "(NEW)" in verdict:
                stats["new"] += 1
                print(f"  {verdict:20s} {sender[:40]:40s} | {subject[:35]}")

    return stats


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Mino email security batch scanner")
    parser.add_argument("source", nargs="?", default="both",
                        choices=["both", "gmail", "outlook"],
                        help="Which inbox to scan (default: both)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max emails to scan per inbox (default: 100)")
    args = parser.parse_args()

    init_db()

    totals = {"scanned": 0, "new": 0, "skipped": 0, "errors": 0}

    if args.source in ("both", "gmail"):
        print(f"\n=== Gmail scan (limit {args.limit}) ===")
        s = scan_gmail(limit=args.limit)
        for k in totals:
            totals[k] += s.get(k, 0)

    if args.source in ("both", "outlook"):
        print(f"\n=== Outlook scan (limit {args.limit}) ===")
        s = scan_outlook(limit=args.limit)
        for k in totals:
            totals[k] += s.get(k, 0)

    print(
        f"\n=== Mino scan complete ==="
        f"\n  Scanned : {totals['scanned']}"
        f"\n  New     : {totals['new']}"
        f"\n  Skipped : {totals['skipped']}"
        f"\n  Errors  : {totals['errors']}"
    )


if __name__ == "__main__":
    main()
