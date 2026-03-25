# NetWatch Email Protection System - Comprehensive Security Review

**Review Date:** March 18, 2026  
**Reviewer:** Verta (AI Security Analyst)  
**System:** NetWatch Email Protection Module  
**Purpose:** Real-time email scam detection and classification for family inboxes (Gmail + Outlook)

---

## Executive Summary

The NetWatch Email Protection system is a **security-critical application** designed to protect family members (Bing, Andy, and others) from email-based threats. The system scans Gmail (via IMAP) and Outlook (via Microsoft Graph API) inboxes and spam folders, classifying emails into 10 scam categories with risk scoring from LOW to CRITICAL.

### Overall Assessment: **GOOD with Improvements Needed**

| Category | Rating | Notes |
|----------|--------|-------|
| **Architecture** | ✅ Solid | Clean separation of concerns, modular design |
| **Security** | ⚠️ Moderate | Credential handling is good, but sandboxing is superficial |
| **Classification Logic** | ✅ Strong | 10 scam types with good false positive prevention |
| **Dashboard UX** | ✅ Excellent | Comprehensive stats, charts, and bulk actions |
| **Error Handling** | ⚠️ Weak | Silent failures, no retry logic, no user notifications |
| **Performance** | ⚠️ Unknown | No rate limiting, no caching beyond PhishTank |
| **Data Integrity** | ✅ Good | received_date preserved for charting, atomic writes |

### Critical Findings

1. **Sandboxing is cosmetic** - `email_scans_sandbox.sh` creates isolated temp dirs but doesn't actually restrict Python execution capabilities
2. **No input validation** on email bodies - potential DoS via extremely large emails
3. **Credential files are properly protected** (600 permissions) ✅
4. **PhishTank integration exists but cache may be stale** - no auto-refresh mechanism
5. **Bulk actions (report spam/delete) lack confirmation** in API layer
6. **No alerting mechanism** - flagged emails require manual dashboard check

---

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NetWatch Email Protection                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────────┐   │
│  │   Gmail     │    │   Outlook    │    │    PhishTank Cache      │   │
│  │   IMAP      │    │  Graph API   │    │  ~/.openclaw/           │   │
│  │  :993 SSL   │    │  Bearer Auth │    │  .phishtank_cache.json  │   │
│  └──────┬──────┘    └──────┬───────┘    └────────────┬────────────┘   │
│         │                  │                         │                  │
│         │                  │                         │                  │
│         ▼                  ▼                         ▼                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    email_scams.py (Classifier)                  │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │  SCAM_TYPES Config (10 types with weights + patterns)    │  │   │
│  │  │  - TYPOSQUATTING (weight: 3)                             │  │   │
│  │  │  - FORGERY (weight: 3)                                   │  │   │
│  │  │  - TOO_GOOD_TO_BE_TRUE (weight: 2)                       │  │   │
│  │  │  - GRAMMAR_RED_FLAGS (weight: 1)                         │  │   │
│  │  │  - URGENCY_SCARE_TACTICS (weight: 2)                     │  │   │
│  │  │  - CREDENTIAL_HARVESTING (weight: 4)                     │  │   │
│  │  │  - PAYMENT_FRAUD (weight: 3)                             │  │   │
│  │  │  - MALICIOUS_ATTACHMENT (weight: 5)                      │  │   │
│  │  │  - ADVANCE_FEE_FRAUD (weight: 4)                         │  │   │
│  │  │  - LINK_MANIPULATION (weight: 2)                         │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  │  Risk Scoring:                                                  │   │
│  │  - LOW: score < 3                                               │   │
│  │  - MEDIUM: 3 <= score < 6                                      │   │
│  │  - HIGH: 6 <= score < 8                                        │   │
│  │  - CRITICAL: score >= 8                                         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │              email_scans_sandbox.sh (Wrapper)                   │   │
│  │  - Creates sandbox/ dir (chmod 700)                             │   │
│  │  - Creates temp scan dir (mktemp)                               │   │
│  │  - Clears sensitive env vars                                    │   │
│  │  - Sets umask 077                                               │   │
│  │  - Runs isolated Python script                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   server.py (Flask API)                         │   │
│  │  - GET /api/email_scans        Latest scan results              │   │
│  │  - GET /api/email_scan         Trigger new scan                 │   │
│  │  - GET /api/email_scans_history Historical data for charts      │   │
│  │  - POST /api/email_bulk_action Report spam / Delete             │   │
│  │  - GET /api/email_view         View full email content          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  index.html (Dashboard UI)                      │   │
│  │  - Stats cards (Total, Clean, Flagged)                          │   │
│  │  - Weekly scam trends charts (Gmail + Outlook, 3-month)         │   │
│  │  - Legit vs Flagged email tables                                │   │
│  │  - Recommended Actions panel                                    │   │
│  │  - Bulk action buttons (Report Spam, Delete)                    │   │
│  │  - Email viewer modal                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Data Flow:
1. Credentials loaded from protected files (~/.verta_gmail_app_password, ~/.verta_outlook_token.json)
2. IMAP (Gmail) connects to imap.gmail.com:993 SSL
3. Graph API (Outlook) uses Bearer token from OAuth flow
4. Emails fetched from Inbox + Junk/Spam folders
5. Each email analyzed against 10 scam type patterns
6. Risk score calculated, classification assigned
7. Results saved to email_scans/scan_YYYYMMDD_HHMMSS.json (chmod 600)
8. Dashboard polls API, displays stats/charts/tables
9. User can view emails, report spam, or delete in bulk
```

---

## Security Assessment

### ✅ Strengths

| Component | Assessment | Details |
|-----------|------------|---------|
| **Credential Storage** | ✅ Good | Gmail password in `~/.verta_gmail_app_password` (600 perms), Outlook token in `~/.verta_outlook_token.json` (600 perms) |
| **File Permissions** | ✅ Good | Scripts: 700 (rwx------), Python files: 600 (rw-------) |
| **Sandbox Wrapper** | ⚠️ Partial | Creates isolated temp dirs, clears env vars, sets umask 077 - but doesn't use containers/VMs |
| **PhishTank Integration** | ✅ Good | URL cache loaded from `~/.openclaw/.phishtank_cache.json` |
| **Exclude Senders** | ✅ Good | Legitimate senders (google.com, microsoft.com, etc.) excluded from false positives |
| **Suspicious Link Detection** | ✅ Good | CREDENTIAL_HARVESTING requires non-official link to flag |
| **Output File Permissions** | ✅ Good | Scan results saved with chmod 600 |

### ⚠️ Vulnerabilities & Risks

| Risk | Severity | Description |
|------|----------|-------------|
| **Sandbox is cosmetic** | HIGH | `email_scans_sandbox.sh` creates temp dirs but Python can still access entire filesystem, make network calls, spawn processes |
| **No rate limiting** | MEDIUM | IMAP/Graph API calls have no rate limit handling - could hit 429 errors |
| **No input size limits** | MEDIUM | Email bodies read without size limits - potential DoS via large attachments |
| **Credential file paths hardcoded** | LOW | Paths like `~/.verta_gmail_app_password` are hardcoded - less flexible |
| **No TLS verification logging** | LOW | SSL connections made but cert validation not logged/audited |
| **PhishTank cache staleness** | MEDIUM | No mechanism to refresh cache - could miss new phishing URLs |
| **Bulk action no confirmation** | MEDIUM | API accepts bulk delete without user confirmation in code layer |
| **Error suppression** | LOW | Many try/except blocks silently fail - security issues may go unnoticed |

### Credential Handling Analysis

```python
# Gmail: App Password (stored in file with 600 perms)
password_file = os.path.expanduser("~/.verta_gmail_app_password")
if os.path.exists(password_file):
    with open(password_file) as f:
        password = f.read().strip().replace(" ", "")

# Outlook: OAuth Bearer Token (stored in file with 600 perms)
OUTLOOK_TOKEN_FILE = os.path.expanduser("~/.verta_outlook_token.json")
with open(OUTLOOK_TOKEN_FILE) as f:
    token_data = json.load(f)
access_token = token_data.get("access_token")
```

**Assessment:** Credentials are properly stored outside the project directory with restrictive permissions. However:
- No encryption at rest (plaintext in files)
- No key rotation mechanism
- No expiration checking for OAuth token

### Sandboxed Execution Analysis

The `email_scans_sandbox.sh` wrapper claims sandboxing but provides **limited isolation**:

```bash
# What it does:
mkdir -p "$SANDBOX_DIR"
chmod 700 "$SANDBOX_DIR"
umask 077
unset AWS_ACCESS_KEY_ID OPENCLAW_TOKEN DISCORD_TOKEN
mktemp -d "${SANDBOX_DIR}/scan_XXXXXX"

# What it DOESN'T do:
# - No container/VM isolation
# - No seccomp/AppArmor profiles
# - No network namespace isolation
# - No filesystem restrictions (Python can still read /etc, /Users, etc.)
# - No CPU/memory limits
# - No syscall filtering
```

**Recommendation:** For true isolation, consider:
- Running scanner in Docker container with read-only filesystem
- Using macOS Sandbox profiles (`sandbox-exec`)
- Implementing seccomp-bpf filters for Linux deployments

---

## Scam Classification Analysis

### 10 Scam Types Implemented

| Type | Weight | Description | Patterns | False Positive Prevention |
|------|--------|-------------|----------|--------------------------|
| **TYPOSQUATTING** | 3 | Fake domains mimicking brands | paypa1, micros0ft, amaz0n | Edit distance check, only flags unknown domains |
| **FORGERY** | 3 | Free email claiming corporate brand | @gmail.com for Microsoft claims | exclude_senders: google.com, microsoft.com, etc. |
| **TOO_GOOD_TO_BE_TRUE** | 2 | Unrealistic offers | congratulations, won, inheritance, prize | Generic patterns - may have FPs |
| **GRAMMAR_RED_FLAGS** | 1 | Poor language quality | dear customer, urgent!!!, need you verify | Low weight minimizes impact |
| **URGENCY_SCARE_TACTICS** | 2 | Artificial time pressure | 24 hours, suspended, final notice | Common in legitimate billing too |
| **CREDENTIAL_HARVESTING** | 4 | Steal login credentials | verify password, confirm identity | require_suspicious_link: True, exclude_senders |
| **PAYMENT_FRAUD** | 3 | Fraudulent invoices | invoice, refund, billing, charged | Common words - may have FPs |
| **MALICIOUS_ATTACHMENT** | 5 | Dangerous file extensions | .exe, .scr, .bat, .js, .docm | Extension-based - high accuracy |
| **ADVANCE_FEE_FRAUD** | 4 | Nigerian prince scams | dr., general, foreign, million | exclude_senders: discord.com, noreply@ |
| **LINK_MANIPULATION** | 2 | Deceptive URLs | bit.ly, tinyurl, ip address | exclude_senders, removed http:// (too many FPs) |

### Risk Scoring Logic

```python
if risk_score >= 8:  risk_level = "CRITICAL"
elif risk_score >= 6: risk_level = "HIGH"
elif risk_score >= 3: risk_level = "MEDIUM"
else:                 risk_level = "LOW"
```

**Assessment:** Scoring is reasonable but has edge cases:
- MALICIOUS_ATTACHMENT (weight 5) + any other detection = CRITICAL
- Three medium patterns (e.g., URGENCY + PAYMENT + FORGERY = 3+3+3=6) = HIGH
- Single CREDENTIAL_HARVESTING (weight 4) = MEDIUM (not flagged!)

### False Positive Prevention

The system implements several FP prevention mechanisms:

1. **Exclude Senders Lists:** Each scam type has `exclude_senders` array
   - google.com, microsoft.com, apple.com, amazon.com, discord.com, github.com
   - noreply@, no-reply@ patterns

2. **Brand Claim Detection (FORGERY):** Only flags free email domains if brand keywords detected in subject/body
   ```python
   brand_claimed = any(brand in subject.lower() or brand in body.lower() for brand in brand_keywords)
   if brand_claimed and not is_excluded:
       # Flag as FORGERY
   ```

3. **Suspicious Link Requirement (CREDENTIAL_HARVESTING):**
   ```python
   if scam_type == "CREDENTIAL_HARVESTING" and config.get("require_suspicious_link"):
       if not has_suspicious_link:
           continue  # Don't flag
   ```

4. **Typosquatting Only for Unknown Domains:**
   ```python
   if sender_domain not in legitimate_domains:
       # Only then check typosquatting
   ```

**Assessment:** False positive prevention is **well-designed** and should minimize legitimate email flagging.

---

## Dashboard Features Checklist

| Feature | Status | Implementation Quality |
|---------|--------|----------------------|
| **Stats Cards** | ✅ Implemented | Total, Clean, Flagged counts displayed |
| **Weekly Scam Trends Charts** | ✅ Implemented | Chart.js line charts, 3-month range, Gmail + Outlook separate |
| **Legit vs Flagged Tables** | ✅ Implemented | Separate tables with risk badges, view buttons |
| **Scam Type Breakdown** | ✅ Implemented | Table showing detected types, counts, weights |
| **Recommended Actions Panel** | ✅ Implemented | Dynamic generation based on flagged email types |
| **Bulk Actions** | ✅ Implemented | Report Spam, Delete buttons with confirmation dialogs |
| **Email Viewer Modal** | ✅ Implemented | Full content view with subject, sender, body |
| **Scan Trigger Button** | ✅ Implemented | "Run Email Scan" button calls /api/email_scan |
| **Last Scan Timestamp** | ✅ Implemented | Displayed at bottom of section |
| **Responsive Design** | ✅ Implemented | Grid layouts, mobile-friendly |

### Chart Implementation (Weekly Scam Trends)

```javascript
// 3-month range calculation
const today = new Date();
const threeMonthsAgo = new Date();
threeMonthsAgo.setMonth(today.getMonth() - 3);

// Generate all week start dates
const allWeeks = [];
let currentWeek = getWeekStartDate(threeMonthsAgo);
while (currentWeek <= today) {
    allWeeks.push({ date: formatDate(currentWeek), timestamp: currentWeek.getTime() });
    currentWeek = new Date(currentWeek.getTime() + 7 * 24 * 60 * 60 * 1000);
}

// Count from historical scans
history.forEach(scan => {
    scan.results?.forEach(email => {
        if (email.risk_level === 'HIGH' || email.risk_level === 'CRITICAL' || email.risk_level === 'MEDIUM') {
            const receivedDate = new Date(email.received_date || scan.timestamp);
            if (receivedDate >= threeMonthsAgo) {
                const weekStart = getWeekStartDate(receivedDate);
                const dateKey = formatDate(weekStart);
                weeklyData[dateKey][acc] += 1;
            }
        }
    });
});
```

**Assessment:** Chart implementation is **excellent** - uses `received_date` from emails for accurate weekly grouping, handles both Gmail and Outlook separately.

---

## Data Flow Analysis

### Email Fetching

```
Gmail (vertajxiao@gmail.com):
┌─────────────────────────────────────────────────────────────┐
│ IMAP Connection                                             │
│ Server: imap.gmail.com:993 SSL                              │
│ Auth: App Password from ~/.verta_gmail_app_password         │
│                                                             │
│ Folders Scanned:                                            │
│ - INBOX (ALL emails, not just unread)                       │
│ - Limit: 20 emails per scan                                 │
│                                                             │
│ Data Extracted:                                             │
│ - subject, sender (From header)                             │
│ - body (text/plain part)                                    │
│ - attachments (Content-Disposition filename)                │
│ - received_date (Date header, parsed with parsedate_to_datetime) │
│ - raw_email (full message object)                           │
└─────────────────────────────────────────────────────────────┘

Outlook (verta.xiao@outlook.com):
┌─────────────────────────────────────────────────────────────┐
│ Microsoft Graph API                                         │
│ Endpoint: https://graph.microsoft.com/v1.0/me/messages      │
│ Auth: Bearer Token from ~/.verta_outlook_token.json         │
│                                                             │
│ Folders Scanned:                                            │
│ - inbox (GET /me/mailfolders/inbox/messages)                │
│ - junkemailfolder (GET /me/mailfolders/junkemailfolder/messages) │
│ - Limit: 20 emails per folder                               │
│                                                             │
│ Data Extracted:                                             │
│ - subject, from.emailAddress.address                        │
│ - body.content                                              │
│ - attachments[].name                                        │
│ - receivedDateTime (ISO 8601)                               │
│ - id (for message_id)                                       │
└─────────────────────────────────────────────────────────────┘
```

### received_date Extraction

**Gmail:**
```python
received_date = raw_email.get("Date") or raw_email.get("date") or ""
from email.utils import parsedate_to_datetime
received_dt = parsedate_to_datetime(received_date).isoformat()
```

**Outlook:**
```python
received_date = msg.get("receivedDateTime", datetime.now().isoformat())
```

**Assessment:** Date extraction is **robust** for both providers, with fallback to current time if parsing fails.

### Weekly Aggregation

```python
def getWeekStartDate(date):
    d = new Date(date)
    day = d.getDay()
    diff = d.getDate() - day + (day === 0 ? -6 : 1)  # Adjust to Monday
    return new Date(d.setDate(diff))
```

**Assessment:** Weeks start on Monday (ISO 8601 standard), which is correct for international users.

---

## Identified Issues

### 1. Error Handling Weaknesses

| Location | Issue | Impact |
|----------|-------|--------|
| `email_scams.py` fetch_unread_emails_imap | Silent return [] on error | User doesn't know scan failed |
| `email_scams.py` fetch_unread_emails_outlook | Silent return [] on error | Same as above |
| `server.py` run_email_scan | Returns {"error": "..."} but UI doesn't display | User sees stale data |
| `server.py` email_bulk_action | try/except prints error but continues | Partial success not reported clearly |
| `email_scams.py` analyze_email | No validation of input sizes | Potential DoS |

**Example:**
```python
except Exception as e:
    print(f"  IMAP error for {account}: {e}")
    return []  # Silent failure - dashboard shows 0 emails
```

### 2. Performance Concerns

| Issue | Location | Recommendation |
|-------|----------|----------------|
| No rate limit handling | email_scams.py | Add Retry-After handling for 429 responses |
| No connection pooling | email_scams.py | Reuse IMAP connection across accounts |
| No caching of scan results | server.py | Cache latest scan for 5 minutes to reduce API calls |
| Sequential account scanning | email_scams.py | Parallel scanning for Gmail + Outlook |
| No timeout on HTTP requests | email_scans.py | Add timeout=30 to all requests calls (already present in some places) |

### 3. Missing Features

| Feature | Priority | Description |
|---------|----------|-------------|
| **Real-time alerts** | HIGH | Push notification when CRITICAL scam detected |
| **Auto-quarantine** | HIGH | Move HIGH/CRITICAL emails to spam automatically |
| **Allowlist management** | MEDIUM | User can whitelist sender domains |
| **Blocklist management** | MEDIUM | User can block sender domains |
| **Scan scheduling** | MEDIUM | Cron job integration for periodic scans |
| **Multi-language support** | LOW | Pattern matching for non-English scams |
| **Attachment scanning** | HIGH | VirusTotal API integration for attachments |
| **URL expansion** | MEDIUM | Expand bit.ly/tinyurl before checking |
| ** SPF/DKIM validation** | MEDIUM | Check email authentication headers |
| **Export reports** | LOW | PDF/CSV export of scan results |

### 4. Security Hardening Needed

| Issue | Severity | Fix |
|-------|----------|-----|
| **Sandbox is cosmetic** | HIGH | Use Docker containers or macOS sandbox profiles |
| **No input validation** | MEDIUM | Limit email body size to 100KB, attachment count to 10 |
| **Credential plaintext** | MEDIUM | Encrypt credential files with master key |
| **No audit logging** | MEDIUM | Log all scan operations, bulk actions, credential access |
| **PhishTank cache staleness** | MEDIUM | Auto-refresh cache every 24 hours |
| **No CSRF protection** | LOW | Add CSRF tokens to bulk action forms |
| **No rate limiting on API** | LOW | Limit /api/email_scan to 1 call per minute |

---

## Recommendations

### Immediate Actions (Critical)

1. **Implement proper sandboxing**
   ```bash
   # Use macOS sandbox profiles
   sandbox-exec -f (profile (deny default) (allow process-exec (path "/usr/bin/python3")) ...) python3 email_scams.py
   ```
   Or use Docker:
   ```dockerfile
   FROM python:3.11-slim
   RUN useradd -m scanner
   USER scanner
   COPY --chroot=scanner:scanner . /app
   WORKDIR /app
   CMD ["python3", "email_scams.py", "all"]
   ```

2. **Add input validation**
   ```python
   MAX_BODY_SIZE = 100 * 1024  # 100KB
   if len(body) > MAX_BODY_SIZE:
       body = body[:MAX_BODY_SIZE] + "...[truncated]"
   ```

3. **Implement error notifications**
   ```python
   if scan_failed:
       send_discord_alert("⚠️ Email scan failed: {error}")
   ```

4. **Add PhishTank cache refresh**
   ```python
   def refresh_phishtank_cache():
       # Fetch from PhishTank API
       # Update ~/.openclaw/.phishtank_cache.json
       pass
   ```

### Short-term Improvements (1-2 weeks)

1. **Add rate limit handling**
   ```python
   from tenacity import retry, stop_after_attempt, wait_exponential
   
   @retry(stop=stop_after_attempt(3), wait=wait_exponential())
   def fetch_emails_graph_api(...):
       response = requests.get(...)
       if response.status_code == 429:
           retry_after = response.headers.get('Retry-After')
           time.sleep(int(retry_after))
   ```

2. **Implement auto-quarantine**
   ```python
   def auto_quarantine_flagged_emails(flagged):
       for email in flagged:
           if email['risk_level'] in ['HIGH', 'CRITICAL']:
               move_to_spam(email['account'], email['message_id'])
   ```

3. **Add allowlist/blocklist management**
   ```python
   # New config file: ~/.openclaw/email_allowlist.json
   ALLOWLIST = ["google.com", "microsoft.com", "amazon.com", ...]
   BLOCKLIST = ["lottery-winner.net", "amaz0n.net", ...]
   ```

4. **Implement scan scheduling**
   ```bash
   # Add to crontab
   0 */4 * * * cd /Users/verta/.openclaw/workspace/projects/netwatch && python3 email_scams.py all
   ```

### Long-term Enhancements (1-3 months)

1. **VirusTotal attachment scanning**
   ```python
   def scan_attachment_virustotal(filename, file_hash):
       # Check VirusTotal API
       # Return verdict: clean, suspicious, malicious
       pass
   ```

2. **URL expansion service**
   ```python
   def expand_short_url(url):
       # Follow redirects to get final destination
       # Check final URL against PhishTank
       pass
   ```

3. **SPF/DKIM validation**
   ```python
   def validate_email_auth(headers):
       # Check Authentication-Results header
       # Parse SPF, DKIM, DMARC results
       # Return: pass, fail, neutral, none
       pass
   ```

4. **Real-time alerting**
   ```python
   def send_critical_alert(email):
       # Send Discord webhook
       # Send push notification (if configured)
       # Log to security audit file
       pass
   ```

---

## Conclusion

The NetWatch Email Protection system is **well-architected** with solid scam classification logic and comprehensive dashboard features. However, the **sandboxing is superficial** and should be strengthened before production use. The system effectively protects family inboxes from common scam types but lacks real-time alerting and auto-quarantine capabilities.

### Priority Fixes

1. **HIGH:** Implement proper sandboxing (Docker or macOS sandbox profiles)
2. **HIGH:** Add input validation (body size limits, attachment count)
3. **HIGH:** Implement error notifications (Discord alerts on scan failure)
4. **MEDIUM:** Add PhishTank cache auto-refresh
5. **MEDIUM:** Implement rate limit handling for API calls

### Security Score: 7/10

- **Credential handling:** 9/10 ✅
- **Sandboxing:** 4/10 ⚠️
- **Classification accuracy:** 8/10 ✅
- **Error handling:** 5/10 ⚠️
- **Audit logging:** 3/10 ⚠️
- **Input validation:** 5/10 ⚠️

**Overall:** Good foundation, needs hardening before handling truly adversarial threats.

---

*Report generated by Verta AI Security Analyst*  
*For questions or follow-up audits, contact via Discord*
