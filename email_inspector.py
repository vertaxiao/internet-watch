#!/usr/bin/env python3
"""
NetWatch Email Inspector — Five-Module Domain Security Pipeline.

CORE IDENTITY ENGINE  (Tier 1, <1 s):
    • DNS existence check — NXDOMAIN flags 'CRITICAL: GHOST DOMAIN' and stops
    • Official Anchor     — Google/DDG brand search for #1 ranked domain
    • Alignment Guard     — sender domain ≠ Official Anchor → FORGERY
    • Homograph Shield    — Punycode / Unicode lookalike character detection
    • Typosquat checks    — char-substitution, homoglyph, Levenshtein, brand embedding

DEEP FORENSIC MODULE  (Tier 2 — when headers/body provided):
    • Auth Audit          — parse spf/dkim/dmarc from Authentication-Results
    • Envelope Audit      — From: vs Return-Path: domain mismatch → DECEPTIVE ENVELOPE
    • Registration Pattern — domain < 90 days old or exactly 1-year burner expiry

MINO RESEARCHER  (Tier 2, ~10-20 s, signals run concurrently):
    1. Anchor search      — Google + DDG for "{brand} official website"
    2. HTTP redirect chain— follow redirects; compare final domain to anchor
    3. Community          — DDG scam/fraud search + ScamAdviser trust-score scrape
    4. DNSBL Reputation   — Spamhaus DBL + SURBL multi + URIBL black
    5. WHOIS Ownership    — registrant org + nameserver comparison; registration age/expiry
    6. Site DNA           — favicon hash + page-title Jaccard similarity vs anchor
    7. Dynamic Threat Hunt— credential-harvesting forms, obfuscated scripts (eval/atob/hex)
    8. Business Audit     — OpenCorporates legal registration + LinkedIn social proof

HEURISTIC INTELLIGENCE  (body/header analysis):
    • Urgency language     — threat/deadline phrases
    • Link masking         — <a> display-URL vs actual href mismatch
    • Generic greetings    — 'Dear Customer' pattern detection

DASHBOARD TABS:
    • forensic_dna   — populated when headers/body passed to inspect()
    • business_audit — legal registration + social proof (always populated in Tier 2)

Output: SecurityVerdict dict  with 0–100 Weighted Trust Score, structured tier1/tier2
        sub-results, forensic_dna, business_audit, and Claude-synthesised Mino reasoning.

Cache: 6-hour TTL (disk-backed).  realtime=True bypasses the cache.
Background: refresh thread re-scans domains older than 5.5 h automatically.

CLI usage:
    python3 email_inspector.py support@deltaairlines.com
    python3 email_inspector.py microsoftcarriers.com
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import unicodedata
import urllib.request

import dns.resolver
import dns.exception
import requests

# ── Constants ─────────────────────────────────────────────────────────────────

_DIR = Path(__file__).parent

LEGIT_DOMAINS: list[str] = [
    # Big tech / cloud
    "microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com",
    "google.com", "gmail.com", "youtube.com", "googlemail.com",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "amazonaws.com", "amazon.co.uk",
    "facebook.com", "fb.com", "instagram.com", "meta.com",
    "twitter.com", "x.com", "linkedin.com", "netflix.com",
    "adobe.com", "dropbox.com", "salesforce.com", "zoom.us", "slack.com",
    # Dev / infra
    "github.com", "gitlab.com", "bitbucket.org",
    "cloudflare.com", "digitalocean.com", "heroku.com",
    # Finance / payments
    "paypal.com", "paypal.me", "stripe.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "americanexpress.com",
    # Airlines / travel
    "delta.com", "aa.com", "united.com", "southwest.com",
    "jetblue.com", "alaskaair.com", "spirit.com", "frontier.com",
    "airfrance.com", "britishairways.com", "lufthansa.com",
    "booking.com", "expedia.com", "hotels.com", "airbnb.com",
    # Retail / logistics
    "ebay.com", "etsy.com", "shopify.com",
    "fedex.com", "ups.com", "usps.com", "dhl.com",
    # Comms / social
    "discord.com", "telegram.org", "whatsapp.com", "signal.org",
    # Government / health
    "irs.gov", "ssa.gov", "medicare.gov",
]

FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me",
    "yandex.com", "mail.com",
}

# Domains owned by a legitimate brand as a defensive registration but NEVER used
# for sending official email.  Even when WHOIS confirms same owner, an email
# arriving FROM one of these domains is suspicious — the brand communicates via
# its primary domain only.
# Format: fake_domain → (real_email_domain, human note)
UNAUTHORIZED_EMAIL_DOMAINS: dict[str, tuple[str, str]] = {
    "deltaairlines.com":   ("delta.com",      "Delta Air Lines sends email from @delta.com and @t.delta.com only"),
    "delta-airlines.com":  ("delta.com",      "Delta Air Lines sends email from @delta.com and @t.delta.com only"),
    "alaskaairlines.com":  ("alaskaair.com",  "Alaska Airlines sends email from @alaskaair.com only"),
    "alaska-airlines.com": ("alaskaair.com",  "Alaska Airlines sends email from @alaskaair.com only"),
}

_LEGIT_SET = set(LEGIT_DOMAINS)

# Explicitly known scam/squatter domains — instant CRITICAL in tier1_screen(),
# bypasses all scoring.  Maps fake domain → real domain it impersonates.
BLOCKED_SQUATTER_DOMAINS: dict[str, str] = {
    # Fake airline domains (real domains: delta.com, aa.com, united.com, etc.)
    "deltaairlines.com":              "delta.com",
    "delta-airlines.com":             "delta.com",
    "deltaair-lines.com":             "delta.com",
    "deltacarriers.com":              "delta.com",
    "americanairlinescarriers.com":   "aa.com",
    "americanairlines-support.com":   "aa.com",
    "americanairlinessupport.com":    "aa.com",
    "americanairlines-help.com":      "aa.com",
    "unitedairlines.com":             "united.com",
    "united-airlines.com":            "united.com",
    "unitedcarriers.com":             "united.com",
    "southwestairlines.com":          "southwest.com",
    "southwest-airlines.com":         "southwest.com",
    "alaskaairlines.com":             "alaskaair.com",
    "alaska-airlines.com":            "alaskaair.com",
    "jetblueairlines.com":            "jetblue.com",
    "jetblue-airlines.com":           "jetblue.com",
}

# base_label → full domain, for brand-embedding detection (labels ≥ 5 chars only)
BRAND_TO_LEGIT: dict[str, str] = {
    d.split(".")[0]: d
    for d in LEGIT_DOMAINS
    if len(d.split(".")[0]) >= 5
}

# Manual brand entries for companies whose official domain is too short
# to be auto-generated (e.g. aa.com → "aa" is only 2 chars).
_MANUAL_BRAND_TO_LEGIT: dict[str, str] = {
    "americanairlines": "aa.com",
    "americanair":      "aa.com",
    "britishair":       "britishairways.com",
}
BRAND_TO_LEGIT.update(_MANUAL_BRAND_TO_LEGIT)

# Sorted longest-first so "microsoft" wins over "micro" when both could match
PROTECTED_BRANDS: list[str] = sorted(BRAND_TO_LEGIT, key=len, reverse=True)

# Generic words that legitimate companies NEVER append to their primary domain
# to create transactional email domains.  When a domain is structured as
# {brand}{suffix}.com or {suffix}{brand}.com, it's a brand-extension squatter.
_NON_EMAIL_SUFFIXES: frozenset[str] = frozenset({
    # Customer-facing abuse vectors
    "support", "help", "helpdesk", "helpline", "helpcenter",
    "service", "services", "customerservice", "customersupport", "customercare",
    "care", "assist", "assistance",
    # Account / identity abuse
    "account", "accounts", "myaccount", "login", "signin", "signon",
    "verify", "verification", "secure", "security", "auth", "identity",
    # Billing / payment abuse
    "billing", "payments", "pay", "invoice", "refund", "checkout",
    # Information / notice abuse
    "alerts", "notifications", "notice", "update", "updates",
    # HR / recruiting abuse
    "careers", "jobs", "hiring", "recruitment", "hr",
    # Logistics / operational suffixes
    "carriers", "logistics", "shipping", "delivery", "tracking",
    "airlines", "airways", "flights", "air",
    # Miscellaneous squatter patterns
    "online", "official", "corp", "inc", "group", "team",
    "portal", "center", "centre",
})


def _is_brand_suffix_domain(domain_base: str, brand: str) -> bool:
    """Return True if domain_base looks like '{brand}{suffix}' or '{suffix}{brand}'.

    Examples that return True:
      applesupport    (apple + support)
      microsoftsupport (microsoft + support)
      linkedincareers (linkedin + careers)
      supportapple    (support + apple)
      deltaairlines   (delta + airlines)

    The brand argument is a key from BRAND_TO_LEGIT (already lower-case).
    domain_base is the registrable label with TLD stripped, lower-cased.
    """
    if not domain_base.startswith(brand) and not domain_base.endswith(brand):
        return False
    if domain_base.startswith(brand):
        suffix = domain_base[len(brand):]
        # Allow optional hyphen separator: apple-support → support
        suffix = suffix.lstrip("-")
        return suffix in _NON_EMAIL_SUFFIXES
    else:
        suffix = domain_base[: len(domain_base) - len(brand)]
        suffix = suffix.rstrip("-")
        return suffix in _NON_EMAIL_SUFFIXES

_HOMOGLYPH_MAP = str.maketrans("0134@", "oleao")

# Unicode confusable characters → ASCII equivalents (Cyrillic + Greek visual lookalikes)
_UNICODE_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u0455": "s",  # Cyrillic ѕ
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u0501": "d",  # Cyrillic ԁ
    "\u03bf": "o",  # Greek ο
    "\u03b1": "a",  # Greek α
    "\u03c1": "p",  # Greek ρ
    "\u03bd": "v",  # Greek ν
    "\u03c5": "u",  # Greek υ
    "\u03c9": "w",  # Greek ω
}


def _homograph_check(domain: str) -> dict:
    """
    Homograph Shield: detect Punycode encoding and Unicode lookalike characters
    (Cyrillic/Greek chars that are visually identical to ASCII letters).

    Returns:
        has_homograph   bool
        punycode        bool
        lookalike_chars list[dict]  — {char, codepoint, name, ascii_equiv, position}
        normalized      str         — domain with confusables replaced by ASCII
        detail          str
    """
    out: dict[str, Any] = {
        "has_homograph": False, "punycode": False,
        "lookalike_chars": [], "normalized": domain, "detail": "",
    }
    flags: list[str] = []

    # Punycode / IDN detection
    if "xn--" in domain.lower():
        out["punycode"] = True
        out["has_homograph"] = True
        flags.append("Punycode-encoded IDN domain detected")
        try:
            decoded = domain.encode("ascii").decode("idna")
            out["normalized"] = decoded
            flags.append(f"Decodes to: {decoded}")
        except Exception:
            pass

    # Unicode lookalike detection
    lookalikes: list[dict] = []
    normalized_chars = list(domain)
    for i, ch in enumerate(domain):
        if ord(ch) > 127:
            ascii_eq = _UNICODE_CONFUSABLES.get(ch, "")
            try:
                ch_name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            except Exception:
                ch_name = f"U+{ord(ch):04X}"
            lookalikes.append({
                "char": ch, "codepoint": f"U+{ord(ch):04X}",
                "name": ch_name, "ascii_equiv": ascii_eq or "?", "position": i,
            })
            if ascii_eq:
                normalized_chars[i] = ascii_eq
            out["has_homograph"] = True

    out["lookalike_chars"] = lookalikes
    if lookalikes:
        chars_desc = ", ".join(
            f"'{lk['char']}' ({lk['name']}) → '{lk['ascii_equiv']}'"
            for lk in lookalikes[:3]
        )
        flags.append(f"Unicode lookalike chars: {chars_desc}")
        out["normalized"] = "".join(normalized_chars)

    out["detail"] = "; ".join(flags) if flags else "No homograph/Punycode detected."
    return out


def _subject_homograph_check(subject: str) -> dict:
    """
    Detect Unicode lookalike characters in an email subject line that visually
    mimic Latin brand names (e.g. 'Paypаl' with Cyrillic 'а' → 'Paypal').

    Returns:
        has_homograph       bool
        lookalike_chars     list[dict]
        brand_hits          list[str]   — PROTECTED_BRANDS whose name appears after normalisation
        normalized_subject  str
        detail              str
    """
    lookalikes: list[dict] = []
    normalized_chars = list(subject)
    for i, ch in enumerate(subject):
        if ord(ch) > 127:
            ascii_eq = _UNICODE_CONFUSABLES.get(ch, "")
            try:
                ch_name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            except Exception:
                ch_name = f"U+{ord(ch):04X}"
            lookalikes.append({
                "char": ch, "codepoint": f"U+{ord(ch):04X}",
                "name": ch_name, "ascii_equiv": ascii_eq or "?", "position": i,
            })
            if ascii_eq:
                normalized_chars[i] = ascii_eq

    normalized_subject = "".join(normalized_chars)
    brand_hits: list[str] = []
    flags: list[str] = []

    if lookalikes:
        norm_lower = normalized_subject.lower()
        for brand in PROTECTED_BRANDS:
            if re.search(rf"\b{re.escape(brand)}\b", norm_lower) and brand not in brand_hits:
                brand_hits.append(brand)
        if brand_hits:
            for lk in lookalikes[:3]:
                flags.append(
                    f"Homograph char '{lk['char']}' ({lk['name']}) → '{lk['ascii_equiv']}' "
                    f"used near brand '{brand_hits[0]}'")
        else:
            for lk in lookalikes[:2]:
                flags.append(f"Non-ASCII char '{lk['char']}' ({lk['name']}) in subject")

    return {
        "has_homograph":      bool(lookalikes),
        "lookalike_chars":    lookalikes,
        "brand_hits":         brand_hits,
        "normalized_subject": normalized_subject,
        "flags":              flags,
        "detail": ("; ".join(flags) if flags
                   else "No homograph characters detected in subject."),
    }


_UA = "Mozilla/5.0 (compatible; NetWatch-Mino/2.0)"
_HTTP_TIMEOUT = 8

_GOOGLE_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# LiteLLM proxy for Mino AI synthesis
_LITELLM_URL      = os.environ.get("LITELLM_URL", "http://localhost:4000")
_LITELLM_KEY      = os.environ.get("LITELLM_API_KEY", os.environ.get("GATEWAY_TOKEN", ""))
_SYNTHESIS_MODEL  = os.environ.get("EI_SYNTHESIS_MODEL", "claude-sonnet-4-6")

# Scam-report site domains that indicate community concerns
_SCAM_REPORTERS: set[str] = {
    "scamadviser.com", "scamdoc.com", "fraudwatchinternational.com",
    "stopscammers.com", "scam.com", "reportfraud.ftc.gov",
    "consumer.ftc.gov", "hoax-slayer.net", "snopes.com",
    "spamhaus.org", "virustotal.com", "urlvoid.com", "mywot.com",
}

# ── Squatter persistence (shared with server.py) ──────────────────────────────

_SQUATTER_FILE = _DIR / "squatters.json"
_SQUATTER_LOCK = threading.Lock()


def _load_squatters() -> list:
    with _SQUATTER_LOCK:
        if _SQUATTER_FILE.exists():
            try:
                return json.loads(_SQUATTER_FILE.read_text()).get("squatters", [])
            except Exception:
                pass
    return []


def _save_squatters(sq: list) -> None:
    with _SQUATTER_LOCK:
        _SQUATTER_FILE.write_text(json.dumps({"squatters": sq}, indent=2))


def _add_squatter(domain: str, matched_legit: str, reason: str,
                  dns_status: str, verdict: str) -> None:
    sq = _load_squatters()
    if any(s["domain"] == domain for s in sq):
        return
    sq.insert(0, {
        "domain":        domain,
        "matched_legit": matched_legit,
        "reason":        reason,
        "dns_status":    dns_status,
        "verdict":       verdict,
        "first_seen":    datetime.utcnow().isoformat() + "Z",
    })
    _save_squatters(sq)


# ── Cache (6-hour TTL, disk-backed) ───────────────────────────────────────────

_CACHE: dict[str, tuple[float, dict]] = {}   # domain → (epoch_ts, result)
_CACHE_TTL      = 6 * 3600                    # seconds
_CACHE_LOCK     = threading.Lock()
_CACHE_PATH     = _DIR / "email_inspect_cache.json"


def _cache_load() -> None:
    try:
        if _CACHE_PATH.exists():
            now  = time.time()
            data = json.loads(_CACHE_PATH.read_text())
            with _CACHE_LOCK:
                for d, entry in data.items():
                    ts, result = entry[0], entry[1]
                    if now - ts < _CACHE_TTL:
                        _CACHE[d] = (ts, result)
    except Exception:
        pass


def _cache_save() -> None:
    try:
        with _CACHE_LOCK:
            data = {d: [ts, r] for d, (ts, r) in _CACHE.items()}
        _CACHE_PATH.write_text(json.dumps(data))
    except Exception:
        pass


def _cache_get(domain: str) -> dict | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(domain)
    if entry:
        ts, result = entry
        if time.time() - ts < _CACHE_TTL:
            return result
    return None


def _cache_set(domain: str, result: dict) -> None:
    with _CACHE_LOCK:
        _CACHE[domain] = (time.time(), result)
    _cache_save()


def _cache_age(domain: str) -> float | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(domain)
    return (time.time() - entry[0]) if entry else None


# ── Background refresh (6-hour update cycle) ──────────────────────────────────

_REFRESH_CHECK_INTERVAL = 3600       # wake every 1 h
_REFRESH_THRESHOLD      = 5.5 * 3600 # re-scan when age > 5.5 h


def _background_refresh_worker() -> None:
    while True:
        time.sleep(_REFRESH_CHECK_INTERVAL)
        try:
            now = time.time()
            with _CACHE_LOCK:
                stale = [d for d, (ts, _) in _CACHE.items()
                         if now - ts > _REFRESH_THRESHOLD]
            for domain in stale:
                try:
                    inspect(domain, realtime=True)
                except Exception:
                    pass
        except Exception:
            pass


threading.Thread(target=_background_refresh_worker, daemon=True, name="ei-refresh").start()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1,
                            prev[j - 1] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def _jaccard(a: str, b: str) -> float:
    sa, sb = set(a.lower().split()), set(b.lower().split())
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _s(text: str) -> str:
    """Strip JSON-unsafe control characters from scraped text."""
    return _CTRL_RE.sub("", text).strip() if text else ""


def _extract_domain_from_url(url: str) -> str:
    try:
        host = url.split("//")[-1].split("/")[0].split("?")[0].lower()
        return re.sub(r"^www\.", "", host)
    except Exception:
        return ""


def _fetch(url: str, *, params: dict | None = None,
           timeout: int = _HTTP_TIMEOUT, allow_redirects: bool = True) -> requests.Response | None:
    try:
        return requests.get(
            url, params=params, timeout=timeout,
            headers={"User-Agent": _UA}, allow_redirects=allow_redirects,
        )
    except Exception:
        return None


# ── Tier 1: Screener ──────────────────────────────────────────────────────────

def _is_legit_subdomain(domain: str) -> str | None:
    """
    Return the legitimate parent domain if *domain* is a verified subdomain.
    e.g. 'mail.google.com' → 'google.com'  (CLEAN — Identity Guard: subdomain rule)
         'microsoftonline.com' → None       (not a subdomain — brand embedding)
    """
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in _LEGIT_SET:
            return parent
    return None


def _dns_lookup(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    has_a, has_mx, nxdomain = False, False, False
    a_records: list[str] = []
    mx_records: list[str] = []
    try:
        ans    = resolver.resolve(domain, "A")
        has_a  = True
        a_records = [r.address for r in ans]
    except dns.resolver.NXDOMAIN:
        nxdomain = True
    except Exception:
        pass
    try:
        ans    = resolver.resolve(domain, "MX")
        has_mx = True
        mx_records = [str(r.exchange).rstrip(".") for r in ans]
    except Exception:
        pass
    status = ("DEAD" if (nxdomain or not (has_a or has_mx))
              else "LIVE" if has_a else "MAIL_ONLY")
    return {
        "has_a": has_a, "has_mx": has_mx, "nxdomain": nxdomain,
        "status": status, "a_records": a_records, "mx_records": mx_records,
    }


def tier1_screen(domain: str) -> dict:
    """
    Fast structural screener.  Returns dict:
        passed       bool   — True → pass to Tier 2
        verdict      str    — filled only when not passed
        risk_level   str
        matched_legit str|None
        detail       str
        dns          dict
        checks       list[dict]
        brand_name   str   — brand hint for Tier 2 anchor search
    """
    domain = domain.lower().strip()

    # 0. Hard blocklist — explicitly known scam domains.
    #    Checked before the legitimate-domain bypass so they can never be
    #    accidentally whitelisted and always return CRITICAL.
    if domain in BLOCKED_SQUATTER_DOMAINS:
        real = BLOCKED_SQUATTER_DOMAINS[domain]
        detail = (
            f"'{domain}' is a confirmed scam domain impersonating '{real}'. "
            f"The legitimate domain for this brand is '{real}'."
        )
        return {
            "passed": False,
            "verdict": "FORGERY DETECTED",
            "risk_level": "CRITICAL",
            "matched_legit": real,
            "detail": detail,
            "dns": {"status": "UNKNOWN", "has_a": None, "has_mx": None,
                    "nxdomain": False, "a_records": [], "mx_records": []},
            "checks": [{"name": "Known scam domain blocklist", "result": "FAIL",
                        "detail": detail}],
            "brand_name": real.split(".")[0],
        }

    # 1. Exact baseline match → immediately clean
    if domain in _LEGIT_SET:
        return {
            "passed": True, "verdict": "", "risk_level": "LOW",
            "matched_legit": domain,
            "detail": f"'{domain}' is a verified legitimate domain.",
            "dns": {"status": "LIVE", "has_a": True, "has_mx": None,
                    "nxdomain": False, "a_records": [], "mx_records": []},
            "checks": [{"name": "Exact baseline match", "result": "PASS",
                        "detail": "Found in verified domain baseline"}],
            "brand_name": domain.split(".")[0],
        }

    # 2. Identity Guard — subdomain rule:
    #    keyword.Brand.com  → CLEAN (legitimate subdomain)
    #    keyword-Brand.com  → proceeds to brand-embedding check (FORGERY)
    parent = _is_legit_subdomain(domain)
    if parent:
        return {
            "passed": True, "verdict": "", "risk_level": "LOW",
            "matched_legit": parent,
            "is_subdomain": True,
            "detail": f"'{domain}' is a legitimate subdomain of '{parent}'.",
            "dns": {"status": "LIVE", "has_a": True, "has_mx": None,
                    "nxdomain": False, "a_records": [], "mx_records": []},
            "checks": [{"name": "Identity Guard: subdomain rule", "result": "PASS",
                        "detail": f"Legitimate subdomain of verified domain '{parent}'"}],
            "brand_name": parent.split(".")[0],
        }

    dns_info   = _dns_lookup(domain)
    dns_status = dns_info["status"]
    checks: list[dict] = [{
        "name": "DNS existence",
        "result": ("PASS" if dns_status == "LIVE"
                   else "WARN" if dns_status == "MAIL_ONLY" else "FAIL"),
        "detail": (
            f"LIVE — A: {', '.join(dns_info['a_records']) or '—'}"
            if dns_status == "LIVE" else
            f"MAIL_ONLY — MX: {', '.join(dns_info['mx_records']) or '—'}, no A record"
            if dns_status == "MAIL_ONLY" else
            "DEAD — domain does not resolve (NXDOMAIN or no records)"
        ),
    }]

    # ── Homograph Shield ──────────────────────────────────────────────────────
    # Detect Punycode-encoded IDN domains and Unicode lookalike characters
    # (e.g. Cyrillic 'о' instead of Latin 'o').  Must run before typosquat so
    # that a confusable-normalised version of the domain can be compared.
    homo = _homograph_check(domain)
    if homo["has_homograph"]:
        checks.append({"name": "Homograph Shield", "result": "FAIL",
                       "detail": homo["detail"]})
        # Check if the normalised (ASCII) form impersonates a legitimate domain
        norm = homo.get("normalized", "")
        if norm and norm != domain and norm in _LEGIT_SET:
            homo_detail = (
                f"HOMOGRAPH ATTACK: '{domain}' is a Unicode/Punycode impersonation "
                f"of '{norm}'. {homo['detail']}"
            )
            _add_squatter(domain, norm, "homograph impersonation", dns_status,
                          "FORGERY DETECTED")
            return {
                "passed": False, "verdict": "FORGERY DETECTED",
                "risk_level": "CRITICAL", "matched_legit": norm,
                "detail": homo_detail,
                "dns": dns_info, "checks": checks,
                "brand_name": norm.split(".")[0],
                "homograph": homo,
            }
    else:
        checks.append({"name": "Homograph Shield", "result": "PASS",
                       "detail": "No Punycode or Unicode lookalike characters detected."})

    domain_base = domain.split(".")[0]
    typo_hits: list[tuple[str, str]] = []

    for legit in LEGIT_DOMAINS:
        lb = legit.split(".")[0]
        # A: equal-length char substitution ≤ 2
        if domain != legit and len(domain_base) == len(lb):
            diff = sum(1 for a, b in zip(domain_base, lb) if a != b)
            if 0 < diff <= 2:
                typo_hits.append((legit, f"character substitution ({diff} char(s) changed from '{legit}')"))
                continue
        # B: homoglyph / number-for-letter
        if domain_base.translate(_HOMOGLYPH_MAP) == lb and domain_base != lb:
            typo_hits.append((legit, f"homoglyph/number substitution → '{legit}'"))
            continue
        # C: full Levenshtein ≤ 2
        if len(domain_base) > 3 and domain_base != lb and _levenshtein(domain_base, lb) <= 2:
            typo_hits.append((legit, f"edit distance {_levenshtein(domain_base, lb)} from '{legit}'"))

    # D: brand-name embedding (catches prefix/suffix/embedded abuse)
    if not typo_hits:
        nohyphen = domain_base.replace("-", "").replace("_", "")
        for brand in PROTECTED_BRANDS:
            if brand in nohyphen and brand != nohyphen:
                matched  = BRAND_TO_LEGIT[brand]
                position = ("prefix"   if nohyphen.startswith(brand) else
                            "suffix"   if nohyphen.endswith(brand)   else "embedded")
                typo_hits.append((matched, f"protected brand '{brand}' {position} in '{domain}'"))
                break

    if typo_hits:
        best_legit, best_detail = typo_hits[0]
        if dns_status == "DEAD":
            verdict = "CRITICAL: Non-Existent Forgery"
            risk    = "CRITICAL"
            detail  = (f"'{domain}' does not exist (NXDOMAIN) but near-misses '{best_legit}': "
                       f"{best_detail}. Registered for future phishing.")
            _add_squatter(domain, best_legit, best_detail, dns_status, verdict)
        else:
            verdict = "FORGERY DETECTED"
            risk    = "CRITICAL"
            detail  = f"'{domain}' is a near-miss of '{best_legit}': {best_detail}."
        checks.append({"name": "Typosquat / brand embedding", "result": "FAIL",
                       "detail": best_detail})
        return {
            "passed": False, "verdict": verdict, "risk_level": risk,
            "matched_legit": best_legit, "detail": detail,
            "dns": dns_info, "checks": checks,
            "brand_name": best_legit.split(".")[0],
        }

    checks.append({"name": "Typosquat / brand embedding", "result": "PASS",
                   "detail": "No near-miss to known legitimate domains"})

    # ── Ghost Domain ──────────────────────────────────────────────────────────
    # NXDOMAIN with no brand match → unregistered throwaway / future-phishing domain.
    # Fires only here (after typosquat) so that brand-impersonating NXDOMAIN
    # domains still get the more specific "Non-Existent Forgery" verdict above.
    if dns_info.get("nxdomain"):
        ghost_detail = (
            f"CRITICAL: GHOST DOMAIN — '{domain}' does not exist in DNS (NXDOMAIN). "
            "The domain is unregistered. Ghost domains are pre-registered for future "
            "phishing campaigns or used as throwaway sender identities."
        )
        checks.append({"name": "Ghost Domain: NXDOMAIN", "result": "FAIL",
                       "detail": ghost_detail})
        return {
            "passed": False,
            "verdict": "CRITICAL: GHOST DOMAIN",
            "risk_level": "CRITICAL",
            "matched_legit": None,
            "detail": ghost_detail,
            "dns": dns_info,
            "checks": checks,
            "brand_name": _extract_brand_name(domain),
        }
    checks.append({"name": "Ghost Domain", "result": "PASS",
                   "detail": "Domain exists in DNS — not a ghost domain."})

    # E: Unknown-brand suffix-stripping check
    # Catches brand-extension squatters for companies NOT in LEGIT_DOMAINS.
    # e.g. hensongroupcareers.com → strip "careers" → try hensongroup.com
    # If the stripped base resolves as a real website, the sender domain is
    # almost certainly not the official company email domain.
    if not typo_hits:
        nohyphen_base = domain_base.replace("-", "").replace("_", "").lower()
        _suffix_match: tuple[str, str] | None = None  # (matched_suffix, candidate_base_label)
        for _sfx in sorted(_NON_EMAIL_SUFFIXES, key=len, reverse=True):
            if nohyphen_base.endswith(_sfx) and len(nohyphen_base) > len(_sfx) + 3:
                _candidate = nohyphen_base[: -len(_sfx)]
                if len(_candidate) >= 3:
                    _suffix_match = (_sfx, _candidate)
                    break
            if nohyphen_base.startswith(_sfx) and len(nohyphen_base) > len(_sfx) + 3:
                _candidate = nohyphen_base[len(_sfx):]
                if len(_candidate) >= 3:
                    _suffix_match = (_sfx, _candidate)
                    break
        if _suffix_match:
            _sfx, _candidate_label = _suffix_match
            _candidate_real: str | None = None
            for _tld in ("com", "net", "org", "io", "co"):
                _candidate_domain = f"{_candidate_label}.{_tld}"
                try:
                    _r = dns.resolver.resolve(_candidate_domain, "A", lifetime=4)
                    if _r:
                        _candidate_real = _candidate_domain
                        break
                except Exception:
                    pass
            if _candidate_real:
                _sfx_detail = (
                    f"'{domain}' looks like a brand-extension squatter: "
                    f"'{domain_base}' = '{_candidate_label}' + '{_sfx}'. "
                    f"The base domain '{_candidate_real}' exists as a real website. "
                    f"Legitimate companies send email from their primary domain "
                    f"('{_candidate_real}'), not from '{domain}'. "
                    f"This is a strong indicator of a fake recruiter, job scam, or phishing domain."
                )
                checks.append({"name": "Unknown-brand suffix squatter", "result": "FAIL",
                               "detail": _sfx_detail})
                return {
                    "passed": False,
                    "verdict": "SUSPICIOUS: Brand-Extension Squatter",
                    "risk_level": "HIGH",
                    "matched_legit": _candidate_real,
                    "detail": _sfx_detail,
                    "dns": dns_info,
                    "checks": checks,
                    "brand_name": _candidate_label,
                }
    checks.append({"name": "Unknown-brand suffix squatter", "result": "PASS",
                   "detail": "No suffix-stripping match to a real base domain"})

    # Mail-only shadow domain
    if dns_status == "MAIL_ONLY":
        return {
            "passed": False, "verdict": "SUSPICIOUS: Mail-Only Shadow Domain",
            "risk_level": "HIGH", "matched_legit": None,
            "detail": (f"'{domain}' has MX records ({', '.join(dns_info['mx_records'])}) "
                       "but no website — covert mail-relay infrastructure."),
            "dns": dns_info, "checks": checks, "brand_name": "",
        }

    # Quarantine patterns
    qp_path = (Path(__file__).parent.parent.parent.parent
               / ".openclaw" / "scripts" / "verta_quarantine_patterns.json")
    if qp_path.exists():
        try:
            for pat in json.loads(qp_path.read_text()).get("suspicious_domains", []):
                if pat.lower() in domain:
                    checks.append({"name": "Quarantine pattern", "result": "FAIL",
                                   "detail": f"Matched '{pat}'"})
                    return {
                        "passed": False, "verdict": "FORGERY DETECTED",
                        "risk_level": "HIGH", "matched_legit": None,
                        "detail": f"Quarantine pattern '{pat}' matched in domain.",
                        "dns": dns_info, "checks": checks, "brand_name": "",
                    }
        except Exception:
            pass
    checks.append({"name": "Quarantine pattern", "result": "PASS", "detail": "No match"})

    return {
        "passed": True, "verdict": "", "risk_level": "LOW",
        "matched_legit": None, "detail": "Passed all Tier 1 structural checks.",
        "dns": dns_info, "checks": checks,
        "brand_name": _extract_brand_name(domain),
    }


# ── Tier 2: Mino Researcher — individual signals ──────────────────────────────

def _extract_brand_name(domain: str) -> str:
    """
    Extract the likely brand name from a domain for anchor search.
    'deltaairlines.com' → 'delta airlines'
    'microsoftcarriers.com' → 'microsoft'  (protected brand takes priority)
    """
    base     = domain.split(".")[0]
    nohyphen = base.replace("-", "").replace("_", "")
    for brand in PROTECTED_BRANDS:
        if brand in nohyphen:
            return brand
    # Fall back: hyphens → spaces
    return base.replace("-", " ").replace("_", " ")


def _signal_anchor(brand_query: str) -> dict:
    """
    Anchor search: find the official domain for a brand using Google (primary)
    with DuckDuckGo as fallback.

    Search strategy:
      1. Google "I'm Feeling Lucky" → #1 organic result (most authoritative)
      2. DuckDuckGo Instant Answer API
      3. DuckDuckGo HTML scrape

    Returns:
        found          bool
        anchor_domain  str    (e.g. 'delta.com')
        anchor_url     str
        title          str
        snippet        str
        query          str
        source         str   — 'google' | 'ddg_ia' | 'ddg_html'
    """
    query = f"{brand_query} official website"
    out: dict[str, Any] = {
        "found": False, "anchor_domain": "", "anchor_url": "",
        "title": "", "snippet": "", "query": query, "source": "",
    }

    # ── Google: I'm Feeling Lucky (primary — most authoritative #1 result) ────
    try:
        resp = requests.get(
            "https://www.google.com/search",
            params={"q": query, "btnI": "1", "hl": "en", "gl": "us"},
            headers={"User-Agent": _GOOGLE_UA},
            allow_redirects=True, timeout=10,
        )
        final = resp.url
        # Case A: direct redirect to the actual site (not Google)
        if final and "google.com" not in final.split("//")[1].split("/")[0]:
            d = _extract_domain_from_url(final)
            if d:
                out.update({"found": True, "anchor_domain": d, "anchor_url": final,
                             "source": "google"})
                return out
        # Case B: Google wraps the URL in google.com/url?q=<actual_url>
        # (common when Google returns an intermediate redirect page)
        q_match = re.search(r'[?&]q=(https?[^&"]+)', final)
        if q_match:
            real_url = urllib.parse.unquote(q_match.group(1))
            d = _extract_domain_from_url(real_url)
            if d and "google" not in d:
                out.update({"found": True, "anchor_domain": d, "anchor_url": real_url,
                             "source": "google"})
                return out
    except Exception:
        pass

    # ── DuckDuckGo Instant Answer API ────────────────────────────────────────
    try:
        ia = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=6, headers={"User-Agent": _UA},
        ).json()
        redir = ia.get("Redirect", "")
        if redir:
            d = _extract_domain_from_url(redir)
            if d:
                out.update({"found": True, "anchor_domain": d, "anchor_url": redir,
                             "title": ia.get("Heading", ""),
                             "snippet": _s(ia.get("AbstractText", ""))[:200],
                             "source": "ddg_ia"})
                return out
    except Exception:
        pass

    # ── DuckDuckGo HTML scrape (last resort) ─────────────────────────────────
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": _UA}, timeout=8,
        )
        html = resp.text

        url_m     = re.search(r'uddg=([^&"]+)', html)
        title_m   = re.search(r'class="result__a"[^>]*>(.*?)</a>', html, re.S)
        snippet_m = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', html, re.S)

        if url_m:
            raw_url = urllib.parse.unquote(url_m.group(1))
            d       = _extract_domain_from_url(raw_url)
            if d:
                title   = _s(re.sub(r"<[^>]+>", "", title_m.group(1)))   if title_m   else ""
                snippet = _s(re.sub(r"<[^>]+>", "", snippet_m.group(1))) if snippet_m else ""
                out.update({"found": True, "anchor_domain": d, "anchor_url": raw_url,
                             "title": title[:120], "snippet": snippet[:200],
                             "source": "ddg_html"})
    except Exception as e:
        out["error"] = str(e)[:80]

    return out


def _signal_http_chain(domain: str) -> dict:
    """
    Follow HTTP/HTTPS redirect chain; return final domain + page metadata.
    Tries HTTPS first, falls back to HTTP on connection/SSL errors.
    """
    out: dict[str, Any] = {
        "final_domain": "", "final_url": "", "page_title": "", "meta_desc": ""}

    for scheme in ("https", "http"):
        try:
            resp  = requests.get(
                f"{scheme}://{domain}", timeout=_HTTP_TIMEOUT,
                headers={"User-Agent": _UA}, allow_redirects=True,
            )
            final = resp.url
            fd    = _extract_domain_from_url(final)
            html  = resp.text[:8_000]
            tm    = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            dm    = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html, re.I)
            out.update({
                "final_domain": fd, "final_url": final,
                "page_title":   (_s(tm.group(1))[:120] if tm else ""),
                "meta_desc":    (_s(dm.group(1))[:200] if dm else ""),
            })
            return out
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            continue
        except Exception as e:
            out["error"] = str(e)[:80]
            break
    return out


def _signal_community(domain: str) -> dict:
    """
    Community reputation signals:
    1. DuckDuckGo scam/fraud search — top results from fraud-reporting sites
    2. ScamAdviser trust score (HTML scrape, best-effort)

    Returns:
        scam_mentions     int
        scam_sites        list[str]
        scamadviser_score int|None  (0-100; lower = riskier)
        blacklisted       bool
        detail            str
    """
    out: dict[str, Any] = {
        "scam_mentions": 0, "scam_sites": [], "scamadviser_score": None,
        "blacklisted": False, "detail": "",
    }

    # DDG scam search
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": f"{domain} scam fraud phishing review"},
            headers={"User-Agent": _UA}, timeout=8,
        )
        hits: list[str] = []
        for encoded in re.findall(r'uddg=([^&"]+)', resp.text)[:12]:
            u = urllib.parse.unquote(encoded).lower()
            for reporter in _SCAM_REPORTERS:
                if reporter in u and reporter not in hits:
                    hits.append(reporter)
        out["scam_mentions"] = len(hits)
        out["scam_sites"]    = hits
        if hits:
            out["detail"] += f"Community reports on: {', '.join(hits)}. "
    except Exception as e:
        out["ddg_error"] = str(e)[:60]

    # ScamAdviser trust score
    try:
        sa = requests.get(
            f"https://www.scamadviser.com/check-website/{domain}",
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/124.0.0.0 Safari/537.36"),
                "Accept": "text/html,application/xhtml+xml",
                "Referer": "https://www.scamadviser.com/",
            },
            timeout=12, allow_redirects=True,
        )
        sa_html = sa.text
        # Try structured trust score
        sm = re.search(r'"trustScore"\s*:\s*(\d+)', sa_html)
        if not sm:
            sm = re.search(r'data-trust-score=["\'](\d+)["\']', sa_html, re.I)
        if not sm:
            sm = re.search(r'class="[^"]*trust-score[^"]*"[^>]*>\s*(\d{1,3})', sa_html, re.I)
        if sm:
            score = int(sm.group(1))
            if 0 <= score <= 100:
                out["scamadviser_score"] = score
                if score < 30:
                    out["blacklisted"] = True
                    out["detail"] += f"ScamAdviser: {score}/100 HIGH RISK. "
                elif score < 60:
                    out["detail"] += f"ScamAdviser: {score}/100 moderate concern. "
                else:
                    out["detail"] += f"ScamAdviser: {score}/100. "
        # Check for explicit negative verdict phrases — require strong contextual signals,
        # not isolated words like "phishing" that appear on any security-info page.
        # Patterns must indicate the domain under review IS the threat, not a target of one.
        _BLACKLIST_PHRASES = re.compile(
            r"(?:"
            r"this\s+(?:website|site|domain)\s+is\s+(?:a\s+)?(?:scam|fraud|fake|dangerous)"
            r"|confirmed\s+(?:scam|fraud|phishing\s+site)"
            r"|known\s+scam\s+(?:site|website|domain)"
            r"|reported\s+(?:as|for)\s+(?:scam|fraud|phishing)"
            r"|do\s+not\s+(?:trust|use)\s+this\s+(?:site|website)"
            r"|high\s+risk\s+website"
            r")",
            re.I,
        )
        if _BLACKLIST_PHRASES.search(sa_html):
            out["blacklisted"] = True
            out["detail"] += "ScamAdviser flagged explicit scam/fraud verdict. "
    except Exception as e:
        out["scamadviser_error"] = str(e)[:60]

    out["detail"] = out["detail"].strip() or "No community blacklist signals found."
    return out


def _signal_reputation(domain: str) -> dict:
    """
    DNS-BL reputation checks:
    • Spamhaus DBL   (dbl.spamhaus.org)   — spam/phish/malware domain list
    • SURBL multi    (multi.surbl.org)    — URI spam reputation
    • URIBL black    (black.uribl.com)    — known spam domains

    Returns:
        spamhaus_listed  bool
        spamhaus_type    str|None
        surbl_listed     bool
        uribl_listed     bool
        any_listed       bool
        detail           str
    """
    out: dict[str, Any] = {
        "spamhaus_listed": False, "spamhaus_type": None,
        "surbl_listed": False, "uribl_listed": False,
        "any_listed": False, "detail": "",
    }
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4

    _dbl_type = {
        "127.0.1.2": "spam domain",
        "127.0.1.4": "phishing domain",
        "127.0.1.5": "malware domain",
        "127.0.1.6": "botnet C&C",
        "127.0.1.102": "abused-legit (spam)",
        "127.0.1.104": "abused-legit (phishing)",
    }

    # Spamhaus DBL
    try:
        ans = resolver.resolve(f"{domain}.dbl.spamhaus.org", "A")
        ip  = ans[0].address
        out["spamhaus_listed"] = True
        out["spamhaus_type"]   = _dbl_type.get(ip, f"listed ({ip})")
        out["any_listed"]      = True
        out["detail"]         += f"Spamhaus DBL: {out['spamhaus_type']}. "
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        out["spamhaus_error"] = str(e)[:40]

    # SURBL multi
    try:
        resolver.resolve(f"{domain}.multi.surbl.org", "A")
        out["surbl_listed"] = True
        out["any_listed"]   = True
        out["detail"]      += "SURBL multi: listed. "
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        out["surbl_error"] = str(e)[:40]

    # URIBL black
    try:
        resolver.resolve(f"{domain}.black.uribl.com", "A")
        out["uribl_listed"] = True
        out["any_listed"]   = True
        out["detail"]      += "URIBL black: listed. "
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as e:
        out["uribl_error"] = str(e)[:40]

    out["detail"] = out["detail"].strip() or \
                    "Not listed in Spamhaus DBL, SURBL, or URIBL."
    return out


def _get_page_meta(domain: str) -> dict:
    """Fetch homepage metadata for Site DNA comparison."""
    meta: dict[str, str] = {"title": "", "meta_desc": "", "favicon_url": "", "error": ""}
    for scheme in ("https", "http"):
        try:
            resp  = requests.get(
                f"{scheme}://{domain}", timeout=_HTTP_TIMEOUT,
                headers={"User-Agent": _UA}, allow_redirects=True,
            )
            html  = resp.text[:10_000]
            final = resp.url
            base  = final.split("//")[0] + "//" + final.split("//")[1].split("/")[0]

            tm = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            dm = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html, re.I)
            fm = re.search(
                r'<link[^>]+rel=["\'][^"\']*(?:icon|shortcut)[^"\']*["\'][^>]+href=["\']([^"\']+)',
                html, re.I,
            )
            meta["title"]     = (_s(tm.group(1))[:120] if tm  else "")
            meta["meta_desc"] = (_s(dm.group(1))[:200] if dm  else "")
            fav = fm.group(1) if fm else "/favicon.ico"
            meta["favicon_url"] = (fav if fav.startswith("http")
                                   else base + (fav if fav.startswith("/") else "/" + fav))
            meta["final_url"] = final
            meta["error"]     = ""
            return meta
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            continue
        except Exception as e:
            meta["error"] = str(e)[:80]
            break
    return meta


def _favicon_hash(url: str) -> str | None:
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent": _UA})
        if resp.content and len(resp.content) > 50:
            return hashlib.md5(resp.content).hexdigest()
    except Exception:
        pass
    return None


def _signal_site_dna(input_domain: str, anchor_domain: str) -> dict:
    """
    Compare input site vs official anchor site.

    Returns:
        input_title       str
        anchor_title      str
        input_favicon_url  str
        anchor_favicon_url str
        favicon_hash_input  str|None   (MD5)
        favicon_hash_anchor str|None
        favicon_clone       bool
        title_similarity    float  0-1 (Jaccard)
        title_clone         bool   (sim > 0.70)
        is_clean_fork       bool
        detail              str
    """
    out: dict[str, Any] = {
        "input_domain": input_domain, "anchor_domain": anchor_domain,
        "input_title": "", "anchor_title": "",
        "input_favicon_url": "", "anchor_favicon_url": "",
        "favicon_hash_input": None, "favicon_hash_anchor": None,
        "favicon_clone": False, "title_similarity": 0.0,
        "title_clone": False, "is_clean_fork": False, "detail": "",
    }

    if input_domain == anchor_domain:
        out["detail"] = "Input is the anchor domain — no comparison needed."
        return out

    # Fetch both pages concurrently — guard every future.result() against
    # TimeoutError whose str() is '' (empty), which would propagate as a
    # 500 with no error message, surfacing as "Error: unknown" in the UI.
    _empty_meta = {"title": "", "meta_desc": "", "favicon_url": "", "error": "timeout"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fi = pool.submit(_get_page_meta, input_domain)
        fa = pool.submit(_get_page_meta, anchor_domain)
        try:
            inp_meta = fi.result(timeout=15)
        except Exception:
            inp_meta = {**_empty_meta}
        try:
            anc_meta = fa.result(timeout=15)
        except Exception:
            anc_meta = {**_empty_meta}

    if inp_meta.get("error") and anc_meta.get("error"):
        out["detail"] = "Could not fetch either site for DNA comparison."
        return out

    out["input_title"]        = inp_meta.get("title", "")
    out["anchor_title"]       = anc_meta.get("title", "")
    out["input_favicon_url"]  = inp_meta.get("favicon_url", "")
    out["anchor_favicon_url"] = anc_meta.get("favicon_url", "")
    out["input_final_url"]    = inp_meta.get("final_url", "")
    out["anchor_final_url"]   = anc_meta.get("final_url", "")

    # Favicon hash comparison
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fhi = pool.submit(_favicon_hash, inp_meta.get("favicon_url", ""))
        fha = pool.submit(_favicon_hash, anc_meta.get("favicon_url", ""))
        try:
            out["favicon_hash_input"]  = fhi.result(timeout=8)
        except Exception:
            out["favicon_hash_input"]  = None
        try:
            out["favicon_hash_anchor"] = fha.result(timeout=8)
        except Exception:
            out["favicon_hash_anchor"] = None

    if out["favicon_hash_input"] and out["favicon_hash_anchor"]:
        out["favicon_clone"] = (out["favicon_hash_input"] == out["favicon_hash_anchor"])

    # Title similarity
    sim = _jaccard(out["input_title"], out["anchor_title"])
    out["title_similarity"] = round(sim, 3)
    out["title_clone"]      = sim > 0.70

    # Summary
    clone_flags: list[str] = []
    if out["favicon_clone"]:
        clone_flags.append("favicon identical to anchor")
    if out["title_clone"]:
        clone_flags.append(f"page title {sim:.0%} similar to anchor")

    if clone_flags:
        out["detail"] = "HIGH-FIDELITY CLONE DETECTED: " + "; ".join(clone_flags) + "."
    elif not inp_meta.get("error") and not anc_meta.get("error"):
        out["is_clean_fork"] = True
        out["detail"] = f"Site DNA is distinct from '{anchor_domain}' — not a clone."
    else:
        out["detail"] = "Partial DNA comparison (one site unreachable)."

    return out


# ── Tier 2: Ownership / WHOIS verification ────────────────────────────────────

def _registration_age_flags(created: str, expiry: str) -> dict:
    """
    Detect suspicious registration patterns.
    - Young domain: registered < 90 days ago
    - Burner expiry: exactly 1-year registration (360–380 day lifespan)

    Returns:
        young_domain  bool
        burner_expiry bool
        age_days      int|None
        flags         list[str]
    """
    result: dict[str, Any] = {
        "young_domain": False, "burner_expiry": False,
        "age_days": None, "flags": [],
    }
    if created:
        try:
            # Normalise to YYYY-MM-DD by stripping time component
            clean = re.sub(r"[T ].+", "", created.strip())[:10]
            parts = clean.split("-")
            created_dt = datetime(int(parts[0]), int(parts[1]), int(parts[2]),
                                  tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created_dt).days
            result["age_days"] = age
            if 0 <= age < 90:
                result["young_domain"] = True
                result["flags"].append(
                    f"YOUNG DOMAIN: registered only {age} days ago (threshold: 90 days)")
        except Exception:
            pass

    if created and expiry:
        try:
            c_clean = re.sub(r"[T ].+", "", created.strip())[:10]
            e_clean = re.sub(r"[T ].+", "", expiry.strip())[:10]
            cp = c_clean.split("-"); ep = e_clean.split("-")
            c_dt = datetime(int(cp[0]), int(cp[1]), int(cp[2]), tzinfo=timezone.utc)
            e_dt = datetime(int(ep[0]), int(ep[1]), int(ep[2]), tzinfo=timezone.utc)
            lifespan = (e_dt - c_dt).days
            if 350 <= lifespan <= 380:
                result["burner_expiry"] = True
                result["flags"].append(
                    f"BURNER REGISTRATION: exactly 1-year expiry (lifespan: {lifespan} days)")
        except Exception:
            pass

    return result


def _signal_ownership(input_domain: str, official_domain: str) -> dict:
    """
    WHOIS-based domain ownership check.

    Compares the registrant organisation of *input_domain* against the known-good
    *official_domain* (e.g. deltaairlines.com vs delta.com).  Also compares
    nameserver infrastructure as a secondary signal.

    Returns:
        same_owner      bool   — True when registrant orgs match
        input_org       str
        official_org    str
        input_ns        list[str]
        official_ns     list[str]
        ns_overlap      bool
        input_created   str    (ISO date string or "")
        input_private   bool   — registrant hidden by a privacy service
        verdict         str    — "SAME_OWNER" | "DIFFERENT_OWNER" | "UNKNOWN"
        detail          str
    """
    _PRIVACY_TERMS = {
        "privacy", "redacted", "withheld", "whoisguard",
        "domains by proxy", "contact privacy", "data protected",
        "registration private", "perfect privacy", "identity protection",
    }

    def _is_private(text: str) -> bool:
        t = text.lower()
        return any(p in t for p in _PRIVACY_TERMS)

    def _whois_info(domain: str) -> dict:
        try:
            r = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=12,
                env={**os.environ, "LANG": "C"},
            )
            # Drop comment / remark lines
            lines = [ln for ln in r.stdout.splitlines()
                     if not ln.strip().startswith("%") and ":" in ln]
            clean = "\n".join(lines)

            org_m     = re.search(r'Registrant\s+Org(?:anization)?\s*:\s*(.+)',  clean, re.I)
            name_m    = re.search(r'Registrant\s+Name\s*:\s*(.+)',               clean, re.I)
            created_m = re.search(
                r'(?:Creation\s+Date|Created\s+On|created|Registration\s+Date)\s*:\s*(.+)',
                clean, re.I)
            expiry_m  = re.search(
                r'(?:Expir(?:ation|y|es?)\s+(?:Date|On)?|Registry\s+Expiry\s+Date'
                r'|paid-till)\s*:\s*(.+)',
                clean, re.I)
            ns_hits   = re.findall(r'Name\s*Server\s*:\s*(\S+)',                 clean, re.I)

            org     = (org_m.group(1).strip()          if org_m     else "")
            name    = (name_m.group(1).strip()         if name_m    else "")
            created = (created_m.group(1).strip()[:10] if created_m else "")
            expiry  = (expiry_m.group(1).strip()[:10]  if expiry_m  else "")
            ns      = [n.strip().lower().rstrip(".") for n in ns_hits[:4]]
            return {"org": org, "name": name, "created": created,
                    "expiry": expiry, "ns": ns}
        except Exception as exc:
            return {"error": str(exc)[:80], "org": "", "name": "", "ns": []}

    # Run both WHOIS lookups concurrently to stay within the outer signal timeout
    _empty_whois = {"org": "", "name": "", "created": "", "ns": [], "error": "timeout"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fi = pool.submit(_whois_info, input_domain)
        fo = pool.submit(_whois_info, official_domain)
        try:
            inp = fi.result(timeout=15)
        except Exception:
            inp = {**_empty_whois}
        try:
            off = fo.result(timeout=15)
        except Exception:
            off = {**_empty_whois}

    inp_org = inp.get("org", "")
    off_org = off.get("org", "")
    inp_private = _is_private(inp_org) or (not inp_org and not inp.get("name"))
    off_private = _is_private(off_org)

    # Org comparison: case-insensitive substring match (handles "Delta Air Lines Inc." vs "Delta Air Lines")
    same_owner = False
    if inp_org and off_org and not inp_private and not off_private:
        il, ol = inp_org.lower(), off_org.lower()
        # Remove common legal suffixes before comparing
        for suf in (" inc", " llc", " ltd", " corp", ".", ","):
            il = il.replace(suf, "")
            ol = ol.replace(suf, "")
        il = il.strip()
        ol = ol.strip()
        same_owner = bool(il and ol and (il == ol or il in ol or ol in il))

    # Nameserver root comparison (e.g. "ns1.akam.net" → "akam.net")
    def _ns_root(ns: str) -> str:
        parts = ns.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ns

    inp_roots = {_ns_root(n) for n in inp.get("ns", [])}
    off_roots = {_ns_root(n) for n in off.get("ns", [])}
    ns_overlap = bool(inp_roots & off_roots)

    # Verdict — ordered from strongest signal to weakest:
    # 1. Explicit org match → SAME_OWNER
    # 2. Shared NS infrastructure → SAME_OWNER (BEC attackers never share enterprise NS with the target)
    # 3. No WHOIS data at all (NXDOMAIN-like) → DIFFERENT_OWNER
    # 4. Registrant hidden, no NS overlap → UNKNOWN (can't confirm or deny)
    # 5. Orgs present and differ, no NS overlap → DIFFERENT_OWNER
    if same_owner:
        own_verdict = "SAME_OWNER"
    elif ns_overlap:
        # Shared enterprise NS (e.g. both use UltraDNS/Azure DNS) is strong proof of same owner
        same_owner  = True
        own_verdict = "SAME_OWNER"
    elif not inp.get("ns") and not inp_org:
        # No WHOIS data returned — domain likely does not properly exist or is not registered
        own_verdict = "DIFFERENT_OWNER"
    elif inp_private:
        own_verdict = "UNKNOWN"
    else:
        own_verdict = "DIFFERENT_OWNER"

    # ── Registration pattern analysis ────────────────────────────────────────
    reg_flags = _registration_age_flags(
        inp.get("created", ""), inp.get("expiry", ""))

    # Human-readable detail
    detail_parts: list[str] = []
    if inp_org and not inp_private:
        detail_parts.append(f"Input registrant: '{inp_org}'.")
    elif inp_private:
        detail_parts.append("Input registrant: hidden by privacy/proxy service.")
    else:
        detail_parts.append("Input registrant: not found in WHOIS.")
    if off_org and not off_private:
        detail_parts.append(f"Official registrant: '{off_org}'.")
    if inp.get("created"):
        detail_parts.append(f"Domain created: {inp['created']}.")
    if inp.get("expiry"):
        detail_parts.append(f"Expires: {inp['expiry']}.")
    if reg_flags["flags"]:
        detail_parts.extend(reg_flags["flags"])
    if ns_overlap:
        shared = inp_roots & off_roots
        detail_parts.append(
            f"Nameservers share enterprise infrastructure with official domain "
            f"({', '.join(sorted(shared))}) — strong ownership indicator.")
    elif inp_roots and off_roots:
        detail_parts.append(
            f"Nameserver infrastructure differs: input uses {', '.join(inp_roots)}; "
            f"official uses {', '.join(off_roots)}.")

    return {
        "input_org":     inp_org,
        "official_org":  off_org,
        "input_ns":      inp.get("ns", []),
        "official_ns":   off.get("ns", []),
        "input_created": inp.get("created", ""),
        "input_expiry":  inp.get("expiry", ""),
        "same_owner":    same_owner,
        "ns_overlap":    ns_overlap,
        "input_private": inp_private,
        "verdict":       own_verdict,
        "registration":  reg_flags,
        "detail":        " ".join(detail_parts) or "WHOIS data unavailable.",
    }


# ── Tier 2: Dynamic Threat Hunt ───────────────────────────────────────────────

def _signal_threat_hunt(domain: str) -> dict:
    """
    Scan the destination website for active threat indicators:
    - Credential harvesters: HTML forms whose action= posts to a 3rd-party domain
    - Obfuscated scripts: eval(), unescape(), String.fromCharCode(), atob(), long hex/base64
    - External resource injection from unrelated origins

    Returns:
        external_forms      list[dict]   — {action_url, action_domain}
        obfuscated_scripts  list[str]    — pattern labels found
        external_resources  list[str]    — non-CDN external domains loading scripts/iframes
        threat_level        str          — NONE | LOW | HIGH | CRITICAL
        detail              str
    """
    out: dict[str, Any] = {
        "external_forms": [], "obfuscated_scripts": [],
        "external_resources": [], "threat_level": "NONE", "detail": "",
    }

    html = ""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", timeout=_HTTP_TIMEOUT,
                headers={"User-Agent": _UA}, allow_redirects=True,
            )
            html = resp.text[:60_000]
            break
        except Exception:
            continue

    if not html:
        out["detail"] = "Could not fetch site for threat analysis."
        return out

    flags: list[str] = []

    # 1. Credential harvesters: forms whose action= posts to an external domain
    for action in re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I):
        if action.startswith("http"):
            action_domain = _extract_domain_from_url(action)
            if (action_domain and action_domain != domain
                    and not action_domain.endswith(f".{domain}")):
                out["external_forms"].append(
                    {"action_url": action[:150], "action_domain": action_domain})
    if out["external_forms"]:
        flags.append(
            f"CREDENTIAL HARVESTER: {len(out['external_forms'])} form(s) post to "
            f"external domain(s): "
            f"{', '.join(f['action_domain'] for f in out['external_forms'][:3])}")

    # 2. Obfuscated script patterns
    _OBFUS: list[tuple[str, str]] = [
        (r"\beval\s*\(",                                 "eval() call"),
        (r"\bunescape\s*\(",                             "unescape() call"),
        (r"String\.fromCharCode\s*\(",                   "String.fromCharCode()"),
        (r"\batob\s*\(",                                 "atob() Base64 decode"),
        (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}", "long hex-encoded string"),
        (r"document\.write\s*\(",                        "document.write() injection"),
    ]
    found_obfus: list[str] = []
    for pat, label in _OBFUS:
        if re.search(pat, html, re.I) and label not in found_obfus:
            found_obfus.append(label)
    out["obfuscated_scripts"] = found_obfus
    if found_obfus:
        flags.append(f"OBFUSCATED SCRIPTS: {', '.join(found_obfus[:4])}")

    # 3. External resources from non-CDN origins
    _CDN_ALLOWLIST = {
        "googleapis.com", "gstatic.com", "cloudflare.com", "jquery.com",
        "bootstrapcdn.com", "fontawesome.com", "unpkg.com", "cdnjs.cloudflare.com",
        "ajax.aspnetcdn.com", "cdn.jsdelivr.net",
    }
    ext_srcs: list[str] = []
    for src in re.findall(r'(?:src|href)=["\']https?://([^/"\'>\s]+)', html, re.I):
        src_d = src.lower()
        if (src_d != domain and not src_d.endswith(f".{domain}")
                and not any(cdn in src_d for cdn in _CDN_ALLOWLIST)
                and src_d not in ext_srcs):
            ext_srcs.append(src_d)
    out["external_resources"] = ext_srcs[:10]

    # Threat level
    if out["external_forms"]:
        out["threat_level"] = "CRITICAL"
    elif len(found_obfus) >= 3:
        out["threat_level"] = "HIGH"
    elif found_obfus:
        out["threat_level"] = "LOW"

    out["detail"] = "; ".join(flags) if flags else "No active threat indicators detected in site HTML."
    return out


# ── Tier 2: Business Audit ────────────────────────────────────────────────────

def _signal_business_audit(domain: str, brand_name: str) -> dict:
    """
    Query OpenCorporates for legal business registration and check social proof.

    1. OpenCorporates API: search for the brand, return company name, jurisdiction,
       company number, and registered address.
    2. LinkedIn presence: DuckDuckGo site:linkedin.com/company search.

    Returns:
        registered          bool
        company_name        str
        jurisdiction        str
        company_number      str
        registered_address  str
        opencorporates_url  str
        linkedin_slug       str
        no_linkedin         bool
        detail              str
    """
    out: dict[str, Any] = {
        "registered": False, "company_name": "", "jurisdiction": "",
        "company_number": "", "registered_address": "",
        "opencorporates_url": "", "linkedin_slug": "", "no_linkedin": False,
        "detail": "",
    }

    query = brand_name.replace("-", " ").strip()
    if not query or len(query) < 3:
        out["detail"] = "Brand name too short for business lookup."
        return out

    detail_parts: list[str] = []

    # ── OpenCorporates API ────────────────────────────────────────────────────
    try:
        resp = requests.get(
            "https://api.opencorporates.com/v0.4/companies/search",
            params={"q": query, "per_page": "3", "format": "json"},
            timeout=10, headers={"User-Agent": _UA},
        )
        data = resp.json()
        companies = data.get("results", {}).get("companies", [])
        if companies:
            best = companies[0].get("company", {})
            out["registered"]          = True
            out["company_name"]        = best.get("name", "")
            out["jurisdiction"]        = best.get("jurisdiction_code", "")
            out["company_number"]      = best.get("company_number", "")
            out["opencorporates_url"]  = best.get("opencorporates_url", "")
            addr = best.get("registered_address") or {}
            if isinstance(addr, dict):
                addr_parts = [addr.get("street_address", ""), addr.get("locality", ""),
                              addr.get("region", ""), addr.get("country", "")]
                out["registered_address"] = ", ".join(p for p in addr_parts if p)
            detail_parts.append(
                f"Legal registration found: '{out['company_name']}' "
                f"({out['jurisdiction'].upper()}, #{out['company_number']}).")
            if out["registered_address"]:
                detail_parts.append(f"Address: {out['registered_address']}.")
        else:
            detail_parts.append(
                f"No legal registration found for '{query}' on OpenCorporates.")
    except Exception as e:
        detail_parts.append(f"OpenCorporates lookup failed: {str(e)[:60]}")

    # ── LinkedIn social proof check ───────────────────────────────────────────
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": f"site:linkedin.com/company {query}"},
            headers={"User-Agent": _UA}, timeout=8,
        )
        li_m = re.search(r'linkedin\.com/company/([A-Za-z0-9\-]+)', resp.text)
        if li_m:
            out["linkedin_slug"] = li_m.group(1)
            detail_parts.append(
                f"LinkedIn company page found: /company/{li_m.group(1)}.")
        else:
            out["no_linkedin"] = True
            detail_parts.append("No LinkedIn company page found (possible synthetic identity).")
    except Exception:
        pass

    out["detail"] = " ".join(detail_parts) or "Business audit inconclusive."
    return out


# ── Tier 2: Google AI Overview + scam search ──────────────────────────────────

def _signal_google_overview(domain: str, brand_name: str) -> dict:
    """
    Google search signals:
      1. '{brand} official website' → Google #1 anchor (cross-check vs DDG anchor)
      2. Google AI Overview / featured snippet text (best-effort scrape)
      3. Scam/fraud search for the specific domain via Google

    Returns:
        google_anchor           str     — #1 Google organic domain
        ai_overview             str     — raw AI Overview / snippet text (may be empty)
        ai_overview_scam        bool    — AI overview contains scam/fraud language
        official_confirmed      bool    — Google #1 result matches the input domain
        scam_search_hits        int     — scam-reporter sites in scam-search results
        scam_search_sites       list
        detail                  str
    """
    out: dict[str, Any] = {
        "google_anchor":          "",
        "ai_overview":            "",
        "ai_overview_scam":       False,
        "official_confirmed":     False,
        "scam_search_hits":       0,
        "scam_search_sites":      [],
        "detail":                 "",
    }

    # ── Helper: Google #1 result via I'm Feeling Lucky redirect ──────────────
    def _google_lucky(q: str) -> str:
        """Return the #1 Google organic domain for query *q*, or ''."""
        try:
            resp = requests.get(
                "https://www.google.com/search",
                params={"q": q, "btnI": "1", "hl": "en", "gl": "us"},
                headers={"User-Agent": _GOOGLE_UA},
                allow_redirects=True, timeout=10,
            )
            final = resp.url
            # Direct redirect to target site
            host = final.split("//")[1].split("/")[0] if "//" in final else ""
            if host and "google" not in host:
                return _extract_domain_from_url(final)
            # Google wraps real URL in google.com/url?q=<url>
            q_m = re.search(r'[?&]q=(https?[^&"]+)', final)
            if q_m:
                real = urllib.parse.unquote(q_m.group(1))
                d = _extract_domain_from_url(real)
                if d and "google" not in d:
                    return d
        except Exception:
            pass
        return ""

    # ── 1. Brand anchor via Google Lucky (#1 organic result) ─────────────────
    g_anchor = _google_lucky(f"{brand_name} official website")
    if g_anchor:
        out["google_anchor"] = g_anchor
        if g_anchor == domain:
            out["official_confirmed"] = True

    # ── 2. Scam signals via DDG (Google blocks scraping for multi-result pages)
    # Use DuckDuckGo scam-specific search and check the known reporter domains
    hits: list[str] = []
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": f'"{domain}" scam fraud phishing report'},
            headers={"User-Agent": _UA}, timeout=8,
        )
        for raw in re.findall(r'uddg=([^&"]+)', resp.text)[:15]:
            url  = urllib.parse.unquote(raw).lower()
            d    = _extract_domain_from_url(url)
            if d and any(rep in d for rep in _SCAM_REPORTERS) and d not in hits:
                hits.append(d)
    except Exception:
        pass
    out["scam_search_hits"]  = len(hits)
    out["scam_search_sites"] = hits

    # ── Detail summary ────────────────────────────────────────────────────────
    dp: list[str] = []
    if out["google_anchor"]:
        if out["official_confirmed"]:
            dp.append(f"Google #1 result confirms '{domain}' as the official domain.")
        else:
            dp.append(
                f"Google #1 result shows '{out['google_anchor']}' as official "
                f"(input '{domain}' is not the top result).")
    if out["ai_overview_scam"]:
        dp.append("Google AI Overview contains scam/fraud language for this brand.")
    if hits:
        dp.append(f"Scam search found hits on: {', '.join(hits[:3])}.")
    if not dp:
        dp.append("Google search completed — no adverse signals detected.")

    out["detail"] = " ".join(dp)
    return out


# ── Subject-to-Domain Alignment ──────────────────────────────────────────────

def _analyze_subject_alignment(
    subject: str,
    domain: str,
    tier2: dict | None,
    tier1: dict | None = None,
) -> dict:
    """
    Cross-reference brands found in the email Subject against the sender domain.

    NER pass: match subject text (and its homograph-normalised form) against
    PROTECTED_BRANDS and LEGIT_DOMAINS labels.

    Alignment rules applied in priority order:
      1. Subject contains [Brand] AND domain ≠ Official Anchor → MISALIGNED, score=0
      2. Subject contains billing keywords AND domain is free provider
         → HIGH_RISK: UNVERIFIED BILLING
      3. Subject contains security-alert keywords AND domain age < 90 days
         → IDENTITY THEFT ATTEMPT, score=0

    Also runs _subject_homograph_check() to catch visual-impersonation subjects.

    Returns:
        alignment_status   ALIGNED | MISALIGNED | AMBIGUOUS |
                           HIGH_RISK_BILLING | IDENTITY_THEFT
        alignment_badge    str   (emoji + label for UI)
        extracted_brands   list[str]
        official_anchor    str
        subject_homograph  dict
        forced_score       int|None   — when set, overrides the trust score
        flags              list[str]
        detail             str
    """
    out: dict[str, Any] = {
        "alignment_status": "AMBIGUOUS",
        "alignment_badge":  "🟡 Ambiguous",
        "extracted_brands": [],
        "official_anchor":  "",
        "subject_homograph": {},
        "forced_score":     None,
        "flags":            [],
        "detail":           "",
    }
    flags: list[str] = []
    subj_lower = subject.lower()

    # ── Step 1: Homograph scan ────────────────────────────────────────────────
    homo = _subject_homograph_check(subject)
    out["subject_homograph"] = homo
    if homo["has_homograph"]:
        if homo["brand_hits"]:
            flags.append(
                f"SUBJECT HOMOGRAPH: brand '{homo['brand_hits'][0]}' spelled with "
                f"Unicode lookalike characters — visual brand impersonation. "
                f"{homo['detail']}"
            )
            out["forced_score"] = 0
        else:
            flags.append(f"Non-ASCII characters detected in subject: {homo['detail']}")

    # ── Step 2: NER — extract brand/service names from subject ───────────────
    # Use the homograph-normalised form so 'Paypаl' → 'Paypal' still matches.
    scan_text = homo.get("normalized_subject", subject).lower()
    extracted: list[str] = []

    # Pass A: PROTECTED_BRANDS (sorted longest-first — already ordered)
    for brand in PROTECTED_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", scan_text):
            legit = BRAND_TO_LEGIT.get(brand, brand + ".com")
            if legit not in extracted:
                extracted.append(legit)

    # Pass B: domain labels of LEGIT_DOMAINS (≥ 4 chars)
    for legit_dom in LEGIT_DOMAINS:
        label = legit_dom.split(".")[0].lower()
        if len(label) >= 4 and re.search(rf"\b{re.escape(label)}\b", scan_text):
            if legit_dom not in extracted:
                extracted.append(legit_dom)

    out["extracted_brands"] = extracted[:5]

    # ── Step 3: Resolve Official Anchor ──────────────────────────────────────
    t2 = tier2 or {}
    gov     = t2.get("google_overview", {})
    anchor  = t2.get("anchor", {})
    official_anchor = (gov.get("google_anchor") or anchor.get("anchor_domain") or "")
    out["official_anchor"] = official_anchor

    # ── Step 4: Alignment Rule 1 — brand mismatch ────────────────────────────
    if extracted:
        # Sender is authorised for the brand if the sender domain equals (or is a
        # subdomain of) one of the brand domains extracted from the subject.
        # NOTE: official_anchor is the sender domain's own Google anchor — it cannot
        # be used here because it always matches the sender for legitimate domains,
        # which would suppress every valid misalignment flag.
        def _sender_matches(brand_dom: str) -> bool:
            return (domain == brand_dom or domain.endswith(f".{brand_dom}"))

        direct_match = any(_sender_matches(b) for b in extracted)

        if direct_match:
            if out["alignment_status"] != "MISALIGNED":
                out["alignment_status"] = "ALIGNED"
                out["alignment_badge"]  = "🟢 Aligned"
                brand_label = ", ".join(
                    b.split(".")[0].title() for b in extracted[:2])
                flags.append(
                    f"Subject brand '{brand_label}' aligns with sender domain '{domain}'.")
        else:
            # Domain doesn't match any extracted brand → MISALIGNED
            out["alignment_status"] = "MISALIGNED"
            out["alignment_badge"]  = "🔴 MISALIGNED"
            out["forced_score"]     = 0
            brand_label = ", ".join(b.split(".")[0].title() for b in extracted[:2])
            flags.append(
                f"SUBJECT-DOMAIN MISMATCH: Subject references '{brand_label}' but "
                f"email is sent from '{domain}'. "
                f"Trust Score forced to 0.")

    # ── Step 5: Alignment Rule 2 — billing + free provider ───────────────────
    _BILLING_RE = re.compile(
        r"\b(invoice|payment|billing|receipt|order\s+confirm|"
        r"statement|charge|transaction|refund|subscription)\b", re.I)
    if _BILLING_RE.search(subject) and domain in FREE_EMAIL_PROVIDERS:
        if out["alignment_status"] not in ("MISALIGNED",):
            out["alignment_status"] = "HIGH_RISK_BILLING"
            out["alignment_badge"]  = "🔴 HIGH RISK: UNVERIFIED BILLING"
            flags.append(
                f"HIGH RISK: UNVERIFIED BILLING — Subject contains billing/payment "
                f"keywords but email is sent from free provider '{domain}'. "
                f"Legitimate businesses never invoice from Gmail/Yahoo/Outlook.")

    # ── Step 6: Alignment Rule 3 — security alert + young domain ─────────────
    _SECURITY_RE = re.compile(
        r"\b(security\s+alert|account\s+suspended|account\s+locked|"
        r"unusual\s+(?:sign.?in|activity|login)|unauthorized\s+access|"
        r"verify\s+your\s+(?:account|identity)|password\s+(?:reset|expired)|"
        r"locked\s+out|action\s+required)\b", re.I)
    if _SECURITY_RE.search(subject):
        reg      = t2.get("ownership", {}).get("registration", {}) if tier2 else {}
        age_days = reg.get("age_days")
        if age_days is not None and 0 <= age_days < 90:
            if out["alignment_status"] not in ("MISALIGNED",):
                out["alignment_status"] = "IDENTITY_THEFT"
                out["alignment_badge"]  = "🔴 IDENTITY THEFT ATTEMPT"
                out["forced_score"]     = 0
                flags.append(
                    f"IDENTITY THEFT ATTEMPT: Subject contains security-alert language "
                    f"and domain '{domain}' was registered only {age_days} days ago. "
                    f"Newly registered domains issuing security alerts are a "
                    f"hallmark of credential-phishing campaigns.")

    # ── Final state ───────────────────────────────────────────────────────────
    if not extracted and not flags:
        out["detail"] = "No brand names detected in subject — alignment check not applicable."
    else:
        out["detail"] = " ".join(flags) if flags else (
            f"Subject-domain alignment confirmed for '{domain}'.")
    out["flags"] = flags
    return out


# ── Email Forensics: Deep header + body analysis ─────────────────────────────

def _analyze_email_forensics(
    headers: dict[str, str],
    body_html: str = "",
) -> dict:
    """
    Deep forensic analysis of a received email's headers and body.

    1. Auth Audit       — parse Authentication-Results for spf/dkim/dmarc failures
    2. Envelope Audit   — compare From: vs Return-Path: domain mismatch
    3. Heuristic signals:
       - Urgency/threat language in body
       - Link masking: <a href="X">display-that-looks-like-URL</a> where X ≠ display
       - Generic greeting detection ('Dear Customer' etc.)

    Args:
        headers:   dict of header-name → value (case-insensitive)
        body_html: full email body HTML or plain text

    Returns:
        auth_audit      dict
        envelope_audit  dict
        heuristics      dict
        forensic_flags  list[str]
        forensic_score  int   0-100 risk score
        detail          str
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}

    out: dict[str, Any] = {
        "auth_audit": {
            "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
            "spf_fail": False, "dkim_fail": False, "dmarc_fail": False,
        },
        "envelope_audit": {
            "from_domain": "", "return_path_domain": "",
            "mismatch": False, "detail": "",
        },
        "heuristics": {
            "urgency_phrases": [],
            "masked_links": [],
            "generic_greeting": False,
            "generic_greeting_phrase": "",
        },
        "forensic_flags": [],
        "forensic_score": 0,
        "detail": "",
    }
    flags: list[str] = []
    score = 0

    # ── 1. Auth Audit ─────────────────────────────────────────────────────────
    auth_raw = h.get("authentication-results", "")
    if auth_raw:
        for proto in ("spf", "dkim", "dmarc"):
            m = re.search(
                rf'\b{proto}=(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)\b',
                auth_raw, re.I)
            if m:
                val = m.group(1).lower()
                out["auth_audit"][proto] = val
                is_fail = val in ("fail", "softfail") if proto == "spf" else val == "fail"
                out["auth_audit"][f"{proto}_fail"] = is_fail

        auth_fails = [p.upper() for p in ("spf", "dkim", "dmarc")
                      if out["auth_audit"][f"{p}_fail"]]
        if auth_fails:
            flags.append(f"AUTH FAILURES: {', '.join(auth_fails)}")
            score += len(auth_fails) * 22

    # ── 2. Envelope Audit ────────────────────────────────────────────────────
    from_header  = h.get("from", "")
    return_path  = h.get("return-path", "")
    fm = re.search(r"@([\w.\-]+)", from_header)
    rp = re.search(r"@([\w.\-]+)", return_path)
    from_dom = fm.group(1).lower().rstrip(">") if fm else ""
    rp_dom   = rp.group(1).lower().rstrip(">") if rp else ""

    out["envelope_audit"]["from_domain"]        = from_dom
    out["envelope_audit"]["return_path_domain"] = rp_dom

    if from_dom and rp_dom and from_dom != rp_dom:
        env_detail = (
            f"DECEPTIVE ENVELOPE: From: '{from_dom}' ≠ Return-Path: '{rp_dom}'")
        out["envelope_audit"]["mismatch"] = True
        out["envelope_audit"]["detail"]   = env_detail
        flags.append(env_detail)
        score += 30

    # ── 3. Heuristics ────────────────────────────────────────────────────────
    body       = body_html or ""
    body_lower = body.lower()

    # Urgency / threat language
    _URGENCY = [
        r"\b(urgent|immediately|asap|act now|action required)\b",
        r"\b(account (?:suspended|blocked|disabled|compromised|at risk))\b",
        r"\b(verify (?:now|immediately|your (?:account|identity)))\b",
        r"\b(24.?hour|48.?hour|expires? (?:in|today|tonight|soon))\b",
        r"\b(unusual (?:activity|sign.?in|login)|security (?:alert|warning|breach))\b",
        r"\b(confirm your (?:password|credentials|details|information))\b",
        r"\b(your (?:account|access) (?:will be|has been) (?:terminated|suspended|cancelled))\b",
    ]
    urgency_hits: list[str] = []
    for pat in _URGENCY:
        m = re.search(pat, body_lower, re.I)
        if m:
            phrase = m.group()[:60]
            if phrase not in urgency_hits:
                urgency_hits.append(phrase)
    out["heuristics"]["urgency_phrases"] = urgency_hits
    if urgency_hits:
        flags.append(
            f"URGENCY LANGUAGE: {urgency_hits[0]!r}"
            + (f" (+{len(urgency_hits)-1} more)" if len(urgency_hits) > 1 else ""))
        score += min(20, len(urgency_hits) * 6)

    # Link masking: <a href="X">display text that looks like a URL</a>
    masked: list[dict] = []
    for href, raw_display in re.findall(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body, re.I | re.S):
        display = re.sub(r"<[^>]+>", "", raw_display).strip()
        if re.match(r"https?://", display, re.I) or re.match(r"www\.", display, re.I):
            disp_dom = _extract_domain_from_url(
                display if display.startswith("http") else "https://" + display)
            href_dom = _extract_domain_from_url(href) if href.startswith("http") else ""
            if disp_dom and href_dom and disp_dom != href_dom:
                masked.append({"display": display[:80], "href": href[:150]})
        if len(masked) >= 5:
            break
    out["heuristics"]["masked_links"] = masked
    if masked:
        flags.append(
            f"LINK MASKING: display '{masked[0]['display'][:40]}' "
            f"→ actual '{masked[0]['href'][:60]}'")
        score += min(25, len(masked) * 10)

    # Generic greeting
    _GREETINGS = [
        r"\b(dear\s+(?:customer|user|member|account\s+holder|valued\s+(?:customer|member|user)))\b",
        r"\b(hello\s+(?:customer|user|member))\b",
        r"\b(attention\s+(?:customer|user|account\s+holder))\b",
    ]
    for pat in _GREETINGS:
        gm = re.search(pat, body_lower, re.I)
        if gm:
            phrase = gm.group()[:60]
            out["heuristics"]["generic_greeting"]        = True
            out["heuristics"]["generic_greeting_phrase"] = phrase
            flags.append(f"GENERIC GREETING: {phrase!r}")
            score += 10
            break

    out["forensic_flags"]  = flags
    out["forensic_score"]  = min(100, score)
    out["detail"] = (
        "; ".join(flags) if flags
        else "No forensic anomalies detected in email headers/body.")
    return out


# ── Tier 2: Claude AI synthesis (Mino Reasoning) ──────────────────────────────

def _synthesize_mino_reasoning(
    domain: str,
    tier1: dict,
    tier2: dict,
    score: int,
    verdict: str,
    raw_reasoning: str,
) -> str:
    """
    Call Claude (via LiteLLM) to synthesize a concise security assessment from
    all collected signals. Falls back to *raw_reasoning* on any failure.
    """
    if not _LITELLM_KEY:
        return raw_reasoning

    t2       = tier2 or {}
    anchor   = t2.get("anchor",          {})
    redirect = t2.get("redirect",        {})
    own      = t2.get("ownership",       {})
    comm     = t2.get("community",       {})
    rep      = t2.get("reputation",      {})
    dna      = t2.get("site_dna",        {})
    gov      = t2.get("google_overview", {})

    lines: list[str] = [
        f"Domain: {domain}",
        f"Trust Score: {score}/100",
        f"Verdict: {verdict}",
        "",
        "=== Signals ===",
        f"Structural (Tier 1): {tier1.get('detail', 'passed')}",
    ]
    if gov.get("google_anchor"):
        lines.append(f"Google #1 Anchor: {gov['google_anchor']}")
    if anchor.get("anchor_domain"):
        lines.append(f"DDG Anchor: {anchor['anchor_domain']} (via {anchor.get('source','ddg')})")
    if redirect.get("final_url"):
        lines.append(f"Redirect Chain: {redirect['final_url'][:80]}")
    if own.get("verdict") and own["verdict"] != "SKIPPED":
        lines.append(f"WHOIS Ownership: {own['verdict']} — {own.get('detail','')[:100]}")
    if comm.get("detail"):
        lines.append(f"Community: {comm['detail'][:100]}")
    if rep.get("detail"):
        lines.append(f"DNSBL: {rep['detail'][:80]}")
    if dna.get("detail"):
        lines.append(f"Site DNA: {dna['detail'][:100]}")
    if gov.get("ai_overview"):
        lines.append(f"Google AI Overview: {gov['ai_overview'][:150]}")
    if gov.get("ai_overview_scam"):
        lines.append("⚠ AI Overview mentions scam/fraud context.")

    hunt = t2.get("threat_hunt", {})
    biz  = t2.get("business_audit", {})
    own  = t2.get("ownership", {})
    reg  = own.get("registration", {})

    if hunt.get("threat_level") not in (None, "NONE", ""):
        lines.append(f"Threat Hunt [{hunt['threat_level']}]: {hunt.get('detail','')[:120]}")
    if biz.get("detail"):
        lines.append(f"Business Audit: {biz.get('detail','')[:120]}")
    if reg.get("flags"):
        lines.append(f"Registration Pattern: {'; '.join(reg['flags'][:2])}")

    context = "\n".join(lines)
    system  = (
        "You are Mino, NetWatch's cybersecurity research agent. "
        "Write a concise 2–3 sentence security verdict based on the signals provided. "
        "Name the specific signals that drove the verdict. "
        "Use direct security-analyst language. No bullet points, no preamble."
    )

    try:
        payload = {
            "model":    _SYNTHESIS_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": context},
            ],
            "max_tokens":  250,
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            f"{_LITELLM_URL}/chat/completions",
            data=data,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {_LITELLM_KEY}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
        return body["choices"][0]["message"]["content"].strip()
    except Exception:
        return raw_reasoning


# ── Tier 2: Orchestrator ──────────────────────────────────────────────────────

def tier2_research(domain: str, brand_name: str, *, official_domain: str = "") -> dict:
    """
    Run all Mino research signals concurrently.
    Returns structured dict with sub-results for each signal.
    """
    out: dict[str, Any] = {
        "brand_name": brand_name, "input_domain": domain,
        "anchor": {}, "redirect": {}, "community": {}, "reputation": {},
        "ownership": {}, "google_overview": {}, "site_dna": {},
        "threat_hunt": {}, "business_audit": {},
    }

    # Signals run in parallel (8 workers when ownership check is needed)
    n_workers = 8 if official_domain and official_domain != domain else 7
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
        f_anchor    = pool.submit(_signal_anchor, brand_name)
        f_redirect  = pool.submit(_signal_http_chain, domain)
        f_community = pool.submit(_signal_community, domain)
        f_rep       = pool.submit(_signal_reputation, domain)
        f_goverview = pool.submit(_signal_google_overview, domain, brand_name)
        f_threat    = pool.submit(_signal_threat_hunt, domain)
        f_biz       = pool.submit(_signal_business_audit, domain, brand_name)
        f_ownership = (pool.submit(_signal_ownership, domain, official_domain)
                       if official_domain and official_domain != domain else None)

        try:
            out["anchor"]     = f_anchor.result(timeout=15)
        except Exception as e:
            out["anchor"]     = {"error": str(e), "found": False, "anchor_domain": ""}
        try:
            out["redirect"]   = f_redirect.result(timeout=18)
        except Exception as e:
            out["redirect"]   = {"error": str(e), "final_domain": ""}
        try:
            out["community"]  = f_community.result(timeout=20)
        except Exception as e:
            out["community"]  = {"error": str(e), "scam_mentions": 0, "blacklisted": False}
        try:
            out["reputation"] = f_rep.result(timeout=15)
        except Exception as e:
            out["reputation"] = {"error": str(e), "any_listed": False}
        try:
            out["google_overview"] = f_goverview.result(timeout=25)
        except Exception as e:
            out["google_overview"] = {
                "google_anchor": "", "ai_overview": "", "ai_overview_scam": False,
                "official_confirmed": False, "scam_search_hits": 0, "scam_search_sites": [],
                "detail": f"Google search failed: {str(e)[:60]}",
            }
        if f_ownership is not None:
            try:
                out["ownership"] = f_ownership.result(timeout=30)
            except Exception as e:
                out["ownership"] = {
                    "verdict": "UNKNOWN", "detail": "WHOIS lookup failed.",
                    "error": str(e)[:80], "same_owner": False, "input_private": True,
                }
        else:
            out["ownership"] = {
                "verdict": "SKIPPED",
                "detail": "No official domain to compare against.",
            }
        try:
            out["threat_hunt"] = f_threat.result(timeout=20)
        except Exception as e:
            out["threat_hunt"] = {
                "threat_level": "NONE", "detail": f"Threat hunt failed: {str(e)[:60]}",
                "external_forms": [], "obfuscated_scripts": [],
            }
        try:
            out["business_audit"] = f_biz.result(timeout=15)
        except Exception as e:
            out["business_audit"] = {
                "registered": False,
                "detail": f"Business audit failed: {str(e)[:60]}",
            }

    # Signal 5: Site DNA (needs anchor domain from signals above)
    anchor_domain  = out["anchor"].get("anchor_domain", "")
    redirect_final = out["redirect"].get("final_domain", "")
    # Prefer redirect final domain if it's known-legitimate (more authoritative)
    if redirect_final in _LEGIT_SET:
        compare_target = redirect_final
    elif anchor_domain:
        compare_target = anchor_domain
    elif redirect_final:
        compare_target = redirect_final
    else:
        compare_target = ""

    if compare_target and compare_target != domain:
        try:
            out["site_dna"] = _signal_site_dna(domain, compare_target)
        except Exception as e:
            out["site_dna"] = {
                "detail": f"Site DNA comparison failed: {str(e) or 'timeout'}",
                "favicon_clone": False, "title_clone": False, "is_clean_fork": False,
            }
    else:
        out["site_dna"] = {
            "detail": "No anchor domain available for Site DNA comparison.",
            "favicon_clone": False, "title_clone": False, "is_clean_fork": False,
        }

    return out


# ── Trust Score ───────────────────────────────────────────────────────────────

def _score_to_verdict(score: int) -> str:
    if score >= 80: return "LEGITIMATE"
    if score >= 62: return "LIKELY_LEGITIMATE"
    if score >= 42: return "UNKNOWN"
    if score >= 22: return "SUSPICIOUS"
    return "HIGH_RISK"


def _compute_trust_score(
    tier1: dict, tier2: dict | None, domain: str
) -> tuple[int, str, str]:
    """
    Derive 0–100 trust score, verdict, and human-readable reasoning.
    Returns (score, verdict, reasoning_paragraph).
    """
    score  = 50
    parts: list[str] = []
    override: str | None = None

    # ── Tier 1 ────────────────────────────────────────────────────────────────
    if tier1.get("matched_legit") == domain and domain in _LEGIT_SET:
        # Exact baseline match is definitive — Tier 2 scrapers cannot override a
        # domain we have manually curated as legitimate. Return immediately.
        return 98, "LEGITIMATE", (
            f"'{domain}' is a verified legitimate domain in the curated baseline. "
            "Tier 2 community/reputation signals are suppressed for baseline domains."
        )

    # Did Tier 1 detect brand impersonation (typosquat / brand embedding)?
    # When True, we resolve with a WHOIS ownership check rather than Tier 2 scraping.
    matched_legit     = tier1.get("matched_legit") or ""
    brand_impersonation = (
        not tier1.get("passed") and
        bool(matched_legit) and
        matched_legit != domain
    )

    if not tier1.get("passed"):
        v = tier1.get("verdict", "")
        if "CRITICAL" in v or "FORGERY" in v:
            score    = 5
            override = "FORGERY"
            parts.append(
                f"Tier 1 detected structural forgery: {tier1.get('detail', '')} "
                f"This domain impersonates '{matched_legit or 'a known brand'}'."
            )
        elif "SUSPICIOUS" in v:
            score = 28
            parts.append(f"Tier 1 flagged suspicious: {tier1.get('detail', '')}")
        else:
            score = 22
            parts.append(f"Tier 1 blocked: {tier1.get('verdict', '')}")
    else:
        score += 10
        parts.append("Domain passed all Tier 1 structural checks (no typosquat or brand embedding detected).")

    # ── Brand impersonation: resolve with WHOIS ownership check ───────────────
    # When Tier 1 detected that this domain impersonates a known brand, the
    # definitive question is: does the same organisation own both domains?
    # Skip all normal Tier 2 scoring and let ownership decide the verdict.
    if brand_impersonation:
        if tier2 is None:
            # Quick-check path — no deep research run; return structural forgery
            score = max(0, min(100, score))
            return score, override or "FORGERY", " ".join(parts)

        ownership  = tier2.get("ownership", {})
        own_v      = ownership.get("verdict", "SKIPPED")
        brand_label = matched_legit.split(".")[0].title()
        own_detail  = ownership.get("detail", "")

        if own_v == "SAME_OWNER":
            # Check whether this domain is a known non-email-sending alias.
            # The company owns it (defensive reg / redirect) but never uses it
            # for outbound email — so receiving email FROM it is still phishing.
            domain_base = domain.split(".")[0].lower()
            is_suffix_squatter = _is_brand_suffix_domain(domain_base, matched_legit.split(".")[0].lower())

            if domain in UNAUTHORIZED_EMAIL_DOMAINS:
                real_domain, note = UNAUTHORIZED_EMAIL_DOMAINS[domain]
                score    = 15
                override = "SUSPICIOUS"
                parts.append(
                    f"OWNERSHIP CONFIRMED but NOT an authorized email sender: "
                    f"'{domain}' is owned by the same organisation as '{real_domain}', "
                    f"however this domain is never used for official email. {note}. "
                    f"Receiving email from this domain is a phishing indicator."
                )
            elif is_suffix_squatter:
                # Brand owns this domain defensively (e.g. applesupport.com, microsoftsupport.com)
                # but '{brand}{generic_word}.com' is never used for real transactional email.
                score    = 15
                override = "SUSPICIOUS"
                parts.append(
                    f"OWNERSHIP CONFIRMED but NOT an authorized email sender: "
                    f"'{domain}' is owned by the same organisation as '{matched_legit}', "
                    f"but '{domain_base}' follows a brand+suffix squatter pattern "
                    f"({matched_legit.split('.')[0]}+generic-word). "
                    f"Legitimate companies never send transactional email from domains like this. "
                    f"Receiving email from '{domain}' is a phishing indicator."
                )
            else:
                # Confirmed legitimate alias (e.g. a brand-owned vanity domain)
                score    = 85
                override = None
                parts.append(
                    f"OWNERSHIP CONFIRMED: '{domain}' is registered to the same organisation "
                    f"as '{matched_legit}'. This is a verified legitimate alias. {own_detail}"
                )
        elif own_v == "DIFFERENT_OWNER":
            score    = 5
            override = "BEC"
            parts.append(
                f"BEC CONFIRMED: '{domain}' contains protected brand '{brand_label}' "
                f"but is owned by a DIFFERENT organisation — not {brand_label}. "
                f"{own_detail} "
                "Business Email Compromise — do not trust email from this domain."
            )
        else:
            # UNKNOWN (registrant hidden) or SKIPPED
            score    = 8
            override = "BEC"
            parts.append(
                f"SUSPECTED BEC: '{domain}' impersonates brand '{brand_label}' but the "
                f"registrant is hidden or unverifiable. {own_detail} "
                f"Ownership by {brand_label} cannot be confirmed. "
                "Treat all email from this domain as Business Email Compromise risk."
            )

        score = max(0, min(100, score))
        return score, override or _score_to_verdict(score), " ".join(parts)

    # ── Non-impersonation early return ────────────────────────────────────────
    if tier2 is None or override:
        score = max(0, min(100, score))
        return score, override or _score_to_verdict(score), " ".join(parts)

    # ── Tier 2: HTTP redirect chain ───────────────────────────────────────────
    redir    = tier2.get("redirect", {})
    redir_fd = redir.get("final_domain", "")

    # Consolidate best-known anchor domain from both search signals
    anchor    = tier2.get("anchor", {})
    anc_dom   = anchor.get("anchor_domain", "")
    gov       = tier2.get("google_overview", {})
    g_anchor  = gov.get("google_anchor", "")
    # Google result is more authoritative; use it as primary anchor when available
    best_anchor = g_anchor or anc_dom
    brand_q   = tier2.get("brand_name", "")

    if redir_fd and redir_fd != domain:
        if redir_fd in _LEGIT_SET:
            score += 20
            parts.append(f"Domain redirects to the verified legitimate domain '{redir_fd}'.")
        elif best_anchor and redir_fd != best_anchor and redir_fd not in _LEGIT_SET:
            # DECEPTIVE REDIRECTION: redirects to an unknown site that is NOT the anchor
            score    = 0
            override = "FORGERY"
            parts.append(
                f"FORGERY: Cloned Destination — '{domain}' redirects to '{redir_fd}' "
                f"which is NOT the official anchor '{best_anchor}'. "
                "Automatic -100 penalty for deceptive redirection.")
        else:
            for brand in PROTECTED_BRANDS:
                if brand in redir_fd:
                    score += 12
                    parts.append(
                        f"HTTP redirect chain leads to '{redir_fd}' (brand: '{brand}').")
                    break

    if override == "FORGERY":
        score = max(0, min(100, score))
        return score, override, " ".join(parts)

    # ── Tier 2: Anchor search (Google + DDG cross-check) ─────────────────────
    anchor_source = anchor.get("source", "ddg")
    if best_anchor:
        # Official Anchor Mismatch: -50 penalty (Identity Guard)
        # Fires when the search-confirmed official domain differs from input
        if (best_anchor != domain and best_anchor != redir_fd and
                best_anchor in _LEGIT_SET and redir_fd not in _LEGIT_SET):
            score   -= 50
            override = override or "FORGERY"
            brand_label = brand_q or domain.split(".")[0]
            parts.append(
                f"IDENTITY GUARD: Alignment Mismatch — "
                f"'{brand_label}' official website is '{best_anchor}' "
                f"(Google/DDG), not '{domain}'. "
                f"Input domain is not the Official Anchor or a valid subdomain. "
                f"Flagged as FORGERY. Automatic -50 penalty.")
        elif best_anchor == redir_fd or best_anchor == domain:
            score += 15
            parts.append(
                f"Anchor confirmed: search engine identifies '{best_anchor}' "
                f"as official (via {anchor_source}).")
        elif best_anchor in _LEGIT_SET:
            score += 5
            parts.append(f"Search anchor identified as '{best_anchor}' ({anchor_source}).")
        elif (best_anchor != domain and best_anchor != redir_fd
              and best_anchor not in FREE_EMAIL_PROVIDERS):
            # Official Domain Mismatch for UNKNOWN companies (not in LEGIT_SET).
            # Web search found the company's real domain and it ≠ sender domain.
            # Safety: only fire when the anchor plausibly relates to the brand being searched.
            # A related anchor has the brand label inside it, or the sender's base is inside it.
            _anchor_base   = best_anchor.split(".")[0].lower().replace("-", "")
            _sender_base   = domain.split(".")[0].lower().replace("-", "").replace("_", "")
            _brand_cleaned = (brand_q or "").lower().replace(" ", "").replace("-", "")
            _related = (
                _anchor_base in _sender_base          # hensongroup ⊆ hensongroupcareers
                or _sender_base.startswith(_anchor_base)
                or (_brand_cleaned and _anchor_base in _brand_cleaned)
                or (_brand_cleaned and _brand_cleaned.startswith(_anchor_base))
            )
            if _related:
                score   -= 45
                override = override or "SUSPICIOUS"
                parts.append(
                    f"OFFICIAL DOMAIN MISMATCH: Web search for '{brand_q or domain}' confirms "
                    f"'{best_anchor}' as the official company domain (via {anchor_source}). "
                    f"This email was sent from '{domain}', which is NOT the official domain. "
                    f"Legitimate companies only send email from their primary domain. "
                    f"This is a strong phishing/scam indicator — do not trust this email."
                )

    # ── Tier 2: Google AI Overview ────────────────────────────────────────────
    if gov.get("ai_overview_scam"):
        score   -= 50
        override = override or "HIGH_RISK"
        parts.append(
            f"Google AI Overview flags scam/fraud context for this brand. "
            f"Trust score reduced by 50.")
    elif gov.get("official_confirmed"):
        score += 8
        parts.append(f"Google AI Overview confirms '{domain}' as the official domain.")
    if gov.get("scam_search_hits", 0) > 0:
        hits = gov["scam_search_hits"]
        penalty = min(30, hits * 10)
        score -= penalty
        parts.append(
            f"Google scam search: {hits} report site(s) found "
            f"({', '.join(gov.get('scam_search_sites', [])[:3])}).")

    # ── Tier 2: Community ─────────────────────────────────────────────────────
    comm = tier2.get("community", {})
    if comm.get("blacklisted"):
        score   -= 50
        override = "COMMUNITY_BLACKLISTED"
        parts.append(f"Community blacklist: {comm.get('detail', '')}")
    else:
        sc = comm.get("scam_mentions", 0)
        if sc > 0:
            penalty = min(35, sc * 12)
            score  -= penalty
            parts.append(
                f"Found on {sc} scam-reporting site(s): "
                f"{', '.join(comm.get('scam_sites', [])[:3])}.")

    sa = comm.get("scamadviser_score")
    if sa is not None:
        if sa < 30:
            score  -= 28
            override = override or "HIGH_RISK"
            parts.append(f"ScamAdviser trust score: {sa}/100 (HIGH RISK).")
        elif sa < 60:
            score -= 12
            parts.append(f"ScamAdviser trust score: {sa}/100 (moderate concern).")
        else:
            score += 6
            parts.append(f"ScamAdviser trust score: {sa}/100.")

    # ── Tier 2: Reputation DNSBL ──────────────────────────────────────────────
    rep = tier2.get("reputation", {})
    if rep.get("spamhaus_listed"):
        score  -= 45
        override = override or "HIGH_RISK"
        parts.append(f"Spamhaus DBL: {rep.get('spamhaus_type', 'listed')}.")
    if rep.get("surbl_listed"):
        score -= 28
        parts.append("SURBL multi: listed as URI spam.")
    if rep.get("uribl_listed"):
        score -= 22
        parts.append("URIBL black: listed.")
    if not rep.get("any_listed") and not rep.get("spamhaus_error"):
        score += 6
        parts.append("Clean on all DNSBL checks (Spamhaus, SURBL, URIBL).")

    # ── Tier 2: Site DNA ──────────────────────────────────────────────────────
    dna = tier2.get("site_dna", {})
    # If the input domain redirects to the anchor/compare_target (i.e. it is an
    # alias or subdomain), a matching favicon is expected — do not penalise it.
    # A clone that doesn't redirect would have its OWN A-record landing page.
    redirect_is_anchor = (redir_fd and redir_fd in _LEGIT_SET)
    if dna.get("favicon_clone") and not redirect_is_anchor:
        score  -= 35
        override = override or "SUSPICIOUS"
        parts.append("Site DNA: favicon identical to official anchor — HIGH-FIDELITY CLONE DETECTED.")
    elif dna.get("favicon_clone") and redirect_is_anchor:
        # Redirect alias — expected to share favicon; treat as supporting evidence
        score += 8
        parts.append(
            f"Site DNA: favicon matches anchor '{redir_fd}' — consistent with a legitimate redirect alias.")
    if dna.get("title_clone") and not redirect_is_anchor:
        score  -= 18
        override = override or "SUSPICIOUS"
        sim = dna.get("title_similarity", 0)
        parts.append(
            f"Site DNA: page title {sim:.0%} similar to anchor '{dna.get('anchor_domain','')}'.")
    if dna.get("is_clean_fork") and not dna.get("favicon_clone") and not dna.get("title_clone"):
        score += 6
        parts.append("Site DNA is distinct from the anchor — no clone detected.")

    # ── Tier 2: Dynamic Threat Hunt ───────────────────────────────────────────
    hunt = tier2.get("threat_hunt", {})
    hunt_level = hunt.get("threat_level", "NONE")
    if hunt_level == "CRITICAL":
        score   -= 45
        override = override or "HIGH_RISK"
        ef       = hunt.get("external_forms", [])
        parts.append(
            f"ACTIVE THREAT: {len(ef)} credential-harvesting form(s) detected posting to "
            f"external domain(s): "
            f"{', '.join(f.get('action_domain','?') for f in ef[:2])}.")
    elif hunt_level == "HIGH":
        score   -= 25
        override = override or "SUSPICIOUS"
        parts.append(
            f"Obfuscated script indicators in site HTML: "
            f"{', '.join(hunt.get('obfuscated_scripts', [])[:3])}.")
    elif hunt_level == "LOW":
        score -= 10
        parts.append("Minor obfuscation patterns detected in site HTML.")

    # ── Tier 2: Registration pattern ─────────────────────────────────────────
    own   = tier2.get("ownership", {})
    reg   = own.get("registration", {})
    reg_flags = reg.get("flags", [])
    if reg.get("burner_expiry"):
        score   -= 20
        override = override or "SUSPICIOUS"
        parts.append(f"Registration pattern: {reg_flags[-1]}.")
    elif reg.get("young_domain"):
        score -= 12
        override = override or "SUSPICIOUS"
        parts.append(f"Registration pattern: {reg_flags[0]}.")

    # ── Tier 2: Business Audit ────────────────────────────────────────────────
    biz = tier2.get("business_audit", {})
    if not biz.get("registered") and not biz.get("detail", "").startswith("Brand name"):
        # No legal registration found — mild penalty for unknown companies
        score -= 5
        parts.append("Business audit: no legal registration found on OpenCorporates.")
    if biz.get("no_linkedin") and not biz.get("registered"):
        score -= 8
        parts.append("Business audit: no LinkedIn company page found.")

    score   = max(0, min(100, score))
    verdict = override or _score_to_verdict(score)
    reason  = " ".join(parts) if parts else "Insufficient signals for a full assessment."
    return score, verdict, reason


# ── Main entry point ──────────────────────────────────────────────────────────

_VERDICT_DISPLAY: dict[str, str] = {
    "BEC":                   "BEC: Business Email Compromise",
    "FORGERY":               "FORGERY DETECTED",
    "COMMUNITY_BLACKLISTED": "CRITICAL: Community Blacklisted",
    "HIGH_RISK":             "SUSPICIOUS: High Risk Domain",
    "SUSPICIOUS":            "SUSPICIOUS: Unverified Domain",
    "UNKNOWN":               "SUSPICIOUS: Unverified Domain",
    "LIKELY_LEGITIMATE":     "CLEAN",
    "LEGITIMATE":            "CLEAN",
}


def inspect(
    email_or_domain: str,
    *,
    realtime: bool = True,
    run_tier2: bool = True,
    headers: dict | None = None,
    email_body: str = "",
    subject: str = "",
) -> dict:
    """
    Full two-tier domain security inspection.

    Args:
        email_or_domain  email address or bare domain
        realtime         bypass cache and run fresh (manual lookup priority)
        run_tier2        if False, only run Tier 1 (fast path, < 1 s)
        headers          optional dict of email headers for forensic analysis
        email_body       optional email body HTML/text for heuristic analysis
        subject          optional email subject line for alignment analysis

    Returns SecurityVerdict dict.
    """
    raw    = email_or_domain.strip()
    domain = (raw.split("@")[-1].lower().strip() if "@" in raw
              else raw.lower().strip())
    ts = datetime.now(timezone.utc).isoformat()

    # Cache hit (skipped for realtime priority)
    if not realtime:
        cached = _cache_get(domain)
        if cached:
            return {**cached, "from_cache": True,
                    "cache_age_s": round(_cache_age(domain) or 0)}

    # ── Tier 1 ────────────────────────────────────────────────────────────────
    t1 = tier1_screen(domain)

    # ── Tier 2 ────────────────────────────────────────────────────────────────
    t2: dict | None = None
    if run_tier2:
        brand    = t1.get("brand_name") or domain.split(".")[0]
        # Skip WHOIS ownership check for confirmed legitimate subdomains
        # (control of a subdomain already proves ownership of the parent)
        official = ("" if t1.get("is_subdomain")
                    else (t1.get("matched_legit") or ""))
        t2 = tier2_research(domain, brand, official_domain=official)

    # ── Trust score ───────────────────────────────────────────────────────────
    score, verdict_key, reasoning = _compute_trust_score(t1, t2, domain)

    # Prefer Tier 1 display verdict for structural forgeries, BUT let the pipeline
    # override when ownership resolution changed the verdict (LEGITIMATE = confirmed alias,
    # BEC = ownership mismatch confirmed).
    if (not t1.get("passed") and t1.get("verdict")
            and verdict_key not in ("LEGITIMATE", "LIKELY_LEGITIMATE", "BEC")):
        display_verdict = t1["verdict"]
    else:
        display_verdict = _VERDICT_DISPLAY.get(verdict_key, verdict_key)

    # ── Mino AI Reasoning: synthesised by Claude ─────────────────────────────
    # For real-time (manual) lookups only — skip for background cache refresh
    # to avoid LiteLLM load on automated cycles.
    mino_reasoning = reasoning  # raw fallback
    if realtime and run_tier2 and t2:
        mino_reasoning = _synthesize_mino_reasoning(
            domain, t1, t2, score, display_verdict, reasoning)

    # ── Email forensics (optional — when headers/body provided) ──────────────
    forensic_result: dict | None = None
    if headers or email_body:
        forensic_result = _analyze_email_forensics(headers or {}, email_body)
        # Apply forensic score penalty to the domain trust score
        if forensic_result and forensic_result.get("forensic_score", 0) > 0:
            fscore = forensic_result["forensic_score"]
            penalty = int(fscore * 0.4)   # up to 40 points off trust score
            score   = max(0, min(100, score - penalty))

    # ── Subject-to-Domain Alignment (optional — when subject provided) ────────
    subject_alignment: dict | None = None
    if subject.strip():
        subject_alignment = _analyze_subject_alignment(
            subject.strip(), domain, t2, t1)
        # Forced score overrides all previous scoring
        if subject_alignment.get("forced_score") is not None:
            score = subject_alignment["forced_score"]
        elif subject_alignment.get("alignment_status") == "HIGH_RISK_BILLING":
            score = max(0, score - 35)
        # Escalate verdict if subject analysis demands it
        sa_status = subject_alignment.get("alignment_status", "")
        if sa_status in ("MISALIGNED", "IDENTITY_THEFT"):
            display_verdict = subject_alignment["alignment_badge"]
        elif sa_status == "HIGH_RISK_BILLING" and score < 30:
            display_verdict = "HIGH RISK: UNVERIFIED BILLING"

    # Mino compat shim (used by legacy frontend panel)
    mino_signals: dict[str, str] = {}
    if t2:
        gov = t2.get("google_overview", {})
        mino_signals = {
            "final_url":      t2.get("redirect", {}).get("final_url", ""),
            "final_domain":   t2.get("redirect", {}).get("final_domain", ""),
            "page_title":     t2.get("redirect", {}).get("page_title", ""),
            "ddg_abstract":   t2.get("anchor",   {}).get("snippet", ""),
            "ddg_source":     t2.get("anchor",   {}).get("anchor_domain", ""),
            "google_anchor":  gov.get("google_anchor", ""),
            "ai_overview":    gov.get("ai_overview", "")[:200],
            "whois_org":      t2.get("ownership", {}).get("input_org", ""),
            "whois_created":  t2.get("ownership", {}).get("input_created", ""),
        }

    result: dict[str, Any] = {
        # ── Core fields (backward compat with /api/email_domain_check) ─────────
        "input":         raw,
        "domain":        domain,
        "verdict":       display_verdict,
        "risk_level":    t1.get("risk_level", "UNKNOWN"),
        "matched_legit": t1.get("matched_legit"),
        "detail":        mino_reasoning,
        "dns":           t1.get("dns", {}),
        "checks":        t1.get("checks", []),
        # ── New pipeline fields ──────────────────────────────────────────────
        "trust_score":       score,
        "verdict_key":       verdict_key,
        "tier1":             t1,
        "tier2":             t2,
        "reasoning":         mino_reasoning,         # Claude-synthesised
        "reasoning_raw":     reasoning,              # concatenated signal parts
        # ── Forensic DNA tab (populated when headers/body provided) ──────────
        "forensic_dna":      forensic_result,
        # ── Business Audit tab ────────────────────────────────────────────────
        "business_audit":    (t2.get("business_audit") if t2 else None),
        # ── Subject-to-Domain Alignment ───────────────────────────────────────
        "subject_alignment": subject_alignment,
        # ── Mino compat shim ─────────────────────────────────────────────────
        "mino": {
            "verdict":    verdict_key,
            "confidence": round(score / 100, 2),
            "reason":     mino_reasoning,
            "source":     "pipeline",
            "signals":    mino_signals,
        },
        # ── Metadata ─────────────────────────────────────────────────────────
        "timestamp":     ts,
        "is_realtime":   realtime,
        "from_cache":    False,
    }

    _cache_set(domain, result)
    return result


# ── Identity Verification Gate ────────────────────────────────────────────────
#
# Status codes (order reflects decision-tree priority):
#   FAIL:GHOST         — domain does not exist in DNS
#   FAIL:UNAUTHORIZED  — structural forgery / BEC / SPF-DKIM failure / envelope mismatch
#   FAIL:MISALIGNED    — subject brand ≠ official anchor domain
#   SUCCESS:VERIFIED   — domain and subject both confirmed
#   SUCCESS:AMBIGUOUS  — domain confirmed; subject neutral or not provided

_STATUS_FAIL_GHOST        = "FAIL:GHOST"
_STATUS_FAIL_UNAUTHORIZED = "FAIL:UNAUTHORIZED"
_STATUS_FAIL_MISALIGNED   = "FAIL:MISALIGNED"
_STATUS_SUCCESS_VERIFIED  = "SUCCESS:VERIFIED"
_STATUS_SUCCESS_AMBIGUOUS = "SUCCESS:AMBIGUOUS"


def _build_verify_result(
    status: str,
    reason: str,
    checks: list[dict],
    inspect_result: dict,
) -> dict:
    """
    Assemble the final VerifyResult dict.

    Fields:
        status          str    — one of the five STATUS constants above
        code            str    — right-hand side of status (e.g. 'GHOST')
        passed          bool   — True only for SUCCESS:* statuses
        reason          str    — single human-readable sentence
        checks          list   — ordered step log [{step, result, detail, code?}]
        trust_score     int    — 0-100 from the full pipeline
        domain          str
        verdict         str    — display verdict from the pipeline
        inspect_result  dict   — full SecurityVerdict for drill-down
        timestamp       str
    """
    code   = status.split(":", 1)[-1]
    passed = status.startswith("SUCCESS")
    return {
        "status":         status,
        "code":           code,
        "passed":         passed,
        "reason":         reason,
        "checks":         checks,
        "trust_score":    inspect_result.get("trust_score", 0),
        "domain":         inspect_result.get("domain", ""),
        "verdict":        inspect_result.get("verdict", ""),
        "inspect_result": inspect_result,
        "timestamp":      inspect_result.get("timestamp", ""),
    }


def verify_identity(
    email_or_domain: str,
    *,
    subject: str = "",
    headers: dict | None = None,
    realtime: bool = True,
) -> dict:
    """
    Unified identity verification gate for NetWatch.

    Runs the full inspection pipeline then applies a deterministic decision tree.
    The first failing check wins — remaining steps are marked SKIP.

    Decision tree (in order):

    STEP 1 — Domain existence
        • DNS NXDOMAIN or no records at all → FAIL:GHOST

    STEP 2 — Domain structural integrity
        • Tier 1 detected typosquat / brand-embedding / BEC / homograph
          forgery → FAIL:UNAUTHORIZED
        • WHOIS confirms different owner on a known-brand domain → FAIL:UNAUTHORIZED

    STEP 3 — Email authentication (only when *headers* provided)
        • SPF=fail or DKIM=fail → FAIL:UNAUTHORIZED
        • From: domain ≠ Return-Path: domain (deceptive envelope) → FAIL:UNAUTHORIZED

    STEP 4 — Subject-to-Domain Alignment (only when *subject* provided)
        • Brand in subject AND domain ≠ Official Anchor → FAIL:MISALIGNED
        • Security-alert subject + domain age < 90 days → FAIL:MISALIGNED
        • Billing subject + free email provider → FAIL:MISALIGNED
        • Subject homograph impersonation → FAIL:MISALIGNED

    STEP 5 — Final verdict
        • All steps PASS + subject ALIGNED → SUCCESS:VERIFIED
        • Domain PASS + subject AMBIGUOUS or not provided → SUCCESS:AMBIGUOUS

    Args:
        email_or_domain   email address or bare domain
        subject           optional subject line for alignment analysis
        headers           optional email headers dict (enables SPF/DKIM/envelope checks)
        realtime          bypass cache (default True — verify_identity is always authoritative)

    Returns:
        VerifyResult dict — see _build_verify_result() for field descriptions.
    """
    raw    = email_or_domain.strip()
    domain = raw.split("@")[-1].lower().strip() if "@" in raw else raw.lower().strip()

    # Run full pipeline (one call — all results available for every check below)
    result = inspect(
        raw,
        realtime=realtime,
        run_tier2=True,
        headers=headers,
        subject=subject,
    )

    checks: list[dict] = []
    t1      = result.get("tier1") or {}
    dns     = t1.get("dns") or result.get("dns") or {}
    verdict = result.get("verdict", "")
    vkey    = result.get("verdict_key", "")

    # ── STEP 1: Domain existence ──────────────────────────────────────────────
    step_dns: dict = {"step": "domain_dns", "label": "Domain DNS", "result": "PASS", "detail": ""}

    if dns.get("nxdomain") or "GHOST DOMAIN" in verdict:
        step_dns.update({
            "result": "FAIL", "code": "GHOST",
            "detail": f"'{domain}' does not exist in DNS (NXDOMAIN — unregistered domain).",
        })
        checks.append(step_dns)
        _skip_remaining(checks, ["structural", "auth", "subject"])
        return _build_verify_result(
            _STATUS_FAIL_GHOST,
            f"Domain '{domain}' is unregistered (ghost domain) — no DNS records found.",
            checks, result,
        )

    dns_status = dns.get("status", "LIVE")
    if dns_status == "DEAD":
        step_dns.update({
            "result": "FAIL", "code": "GHOST",
            "detail": f"'{domain}' has no A or MX records (DEAD).",
        })
        checks.append(step_dns)
        _skip_remaining(checks, ["structural", "auth", "subject"])
        return _build_verify_result(
            _STATUS_FAIL_GHOST,
            f"Domain '{domain}' has no DNS records.",
            checks, result,
        )

    step_dns["detail"] = (
        f"'{domain}' resolves ({dns_status})"
        + (f" — A: {', '.join(dns.get('a_records', [])[:2]) or '—'}" if dns_status == "LIVE" else "")
    )
    checks.append(step_dns)

    # ── STEP 2: Structural integrity ──────────────────────────────────────────
    step_struct: dict = {"step": "structural", "label": "Structural Integrity", "result": "PASS", "detail": ""}

    structural_fail = (
        vkey in ("BEC", "FORGERY", "COMMUNITY_BLACKLISTED")
        or any(kw in verdict for kw in ("FORGERY", "CRITICAL", "BEC"))
    )

    # Also catch WHOIS-confirmed BEC when verdict was overridden to SUSPICIOUS
    own = (result.get("tier2") or {}).get("ownership", {})
    if own.get("verdict") == "DIFFERENT_OWNER" and result.get("trust_score", 100) < 20:
        structural_fail = True

    if structural_fail:
        raw_reason = (result.get("reasoning_raw") or t1.get("detail") or verdict)[:200]
        step_struct.update({"result": "FAIL", "code": "UNAUTHORIZED", "detail": raw_reason})
        checks.append(step_struct)
        _skip_remaining(checks, ["auth", "subject"])
        return _build_verify_result(
            _STATUS_FAIL_UNAUTHORIZED,
            f"Domain '{domain}' failed structural identity check: {verdict}.",
            checks, result,
        )

    step_struct["detail"] = "Passed all structural checks — no typosquat, BEC, or forgery detected."
    checks.append(step_struct)

    # ── STEP 3: Email authentication (headers path) ───────────────────────────
    step_auth: dict = {
        "step": "auth", "label": "SPF / DKIM / Envelope",
        "result": "SKIP", "detail": "No headers provided — auth check skipped.",
    }
    forensic = result.get("forensic_dna") or {}

    if forensic:
        auth = forensic.get("auth_audit", {})
        env  = forensic.get("envelope_audit", {})
        fail_parts: list[str] = []
        if auth.get("spf_fail"):
            fail_parts.append(f"SPF={auth.get('spf', 'fail').upper()}")
        if auth.get("dkim_fail"):
            fail_parts.append(f"DKIM={auth.get('dkim', 'fail').upper()}")
        if env.get("mismatch"):
            fail_parts.append(env.get("detail", "Deceptive envelope: From ≠ Return-Path"))

        if fail_parts:
            detail = "; ".join(fail_parts)
            step_auth.update({"result": "FAIL", "code": "UNAUTHORIZED", "detail": detail})
            checks.append(step_auth)
            _skip_remaining(checks, ["subject"])
            return _build_verify_result(
                _STATUS_FAIL_UNAUTHORIZED,
                detail,
                checks, result,
            )

        auth_summary = (
            f"SPF={auth.get('spf','unknown').upper()} · "
            f"DKIM={auth.get('dkim','unknown').upper()} · "
            f"DMARC={auth.get('dmarc','unknown').upper()}"
        )
        step_auth.update({"result": "PASS", "detail": auth_summary})

    checks.append(step_auth)

    # ── STEP 4: Subject alignment ─────────────────────────────────────────────
    step_subj: dict = {
        "step": "subject", "label": "Subject Alignment",
        "result": "SKIP", "detail": "No subject provided — alignment check skipped.",
    }
    sa = result.get("subject_alignment")

    if sa:
        a_status = sa.get("alignment_status", "AMBIGUOUS")
        a_detail = sa.get("detail", "")[:200]

        if a_status in ("MISALIGNED", "IDENTITY_THEFT", "HIGH_RISK_BILLING"):
            step_subj.update({"result": "FAIL", "code": "MISALIGNED", "detail": a_detail})
            checks.append(step_subj)
            return _build_verify_result(
                _STATUS_FAIL_MISALIGNED,
                a_detail or f"Subject-domain alignment failed for '{domain}'.",
                checks, result,
            )
        elif a_status == "ALIGNED":
            step_subj.update({"result": "PASS", "detail": a_detail})
        else:
            step_subj.update({"result": "AMBIGUOUS", "detail": a_detail})

    checks.append(step_subj)

    # ── STEP 5: Final verdict ─────────────────────────────────────────────────
    sa_status = (sa.get("alignment_status", "AMBIGUOUS") if sa else "NONE")

    if sa_status == "ALIGNED":
        status = _STATUS_SUCCESS_VERIFIED
        reason = (
            f"Domain '{domain}' passed all identity checks and subject alignment "
            f"is confirmed — sender is authorised for the brand referenced in the subject."
        )
    else:
        status = _STATUS_SUCCESS_AMBIGUOUS
        reason = (
            f"Domain '{domain}' passed all identity checks. "
            + ("No subject provided — full alignment cannot be assessed."
               if not sa else
               "No brand detected in subject — alignment is neutral.")
        )

    return _build_verify_result(status, reason, checks, result)


def _skip_remaining(checks: list[dict], step_names: list[str]) -> None:
    """Append SKIP entries for steps that were not reached due to an earlier failure."""
    _labels = {
        "structural": "Structural Integrity",
        "auth":       "SPF / DKIM / Envelope",
        "subject":    "Subject Alignment",
    }
    for name in step_names:
        checks.append({
            "step":   name,
            "label":  _labels.get(name, name),
            "result": "SKIP",
            "detail": "Skipped — earlier check failed.",
        })


# ── On-import: load persisted cache ───────────────────────────────────────────
_cache_load()


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "support@deltaairlines.com"
    print(f"\nInspecting: {target}")
    print("Running full pipeline (Tier 1 + Tier 2)...\n")
    r = inspect(target, realtime=True)

    ts_label = _score_to_verdict(r["trust_score"])
    bar_len  = r["trust_score"] // 5
    bar      = "█" * bar_len + "░" * (20 - bar_len)

    print(f"Domain       : {r['domain']}")
    print(f"Trust Score  : {r['trust_score']:3d}/100  [{bar}]  {ts_label}")
    print(f"Verdict      : {r['verdict']}")
    print(f"\nReasoning:\n  {r['reasoning']}\n")

    if r.get("tier2"):
        t2   = r["tier2"]
        anc   = t2.get("anchor",        {})
        redir = t2.get("redirect",      {})
        comm  = t2.get("community",     {})
        rep   = t2.get("reputation",    {})
        dna   = t2.get("site_dna",      {})
        own   = t2.get("ownership",     {})
        hunt  = t2.get("threat_hunt",   {})
        biz   = t2.get("business_audit",{})
        reg   = own.get("registration", {})
        print("── Tier 2 Signals ────────────────────────────────────────────────")
        print(f"  Anchor search  : {anc.get('query','—')} → {anc.get('anchor_domain','—')}")
        print(f"  HTTP redirect  : {redir.get('final_url','—')[:80]}")
        print(f"  Community      : {comm.get('detail','—')[:80]}")
        print(f"  Reputation     : {rep.get('detail','—')[:80]}")
        print(f"  Site DNA       : {dna.get('detail','—')[:80]}")
        print(f"  Threat Hunt    : [{hunt.get('threat_level','—')}] {hunt.get('detail','—')[:70]}")
        print(f"  Business Audit : {biz.get('detail','—')[:80]}")
        if reg.get("flags"):
            print(f"  Reg. Pattern   : {'; '.join(reg['flags'][:2])}")
