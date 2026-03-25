#!/usr/bin/env python3
"""
Email Scam Scanner - Scans inbox and classifies scam emails

Integrates with NetWatch to provide email security monitoring alongside network device tracking.
Uses IMAP for Gmail/Outlook (more reliable than gog CLI).
"""

import json
import os
import re
import subprocess
import sys
import imaplib
import email
import requests
from datetime import datetime
from pathlib import Path

# Configuration
EMAIL_ACCOUNTS = [
    "verta.xiao@outlook.com",
    "vertajxiao@gmail.com"
]

# IMAP credentials (Gmail only - Outlook uses Microsoft Graph API)
IMAP_CREDENTIALS = {
    "vertajxiao@gmail.com": {
        "server": "imap.gmail.com",
        "password_file": os.path.expanduser("~/.verta_gmail_app_password")
    }
}

# Outlook Graph API token
OUTLOOK_TOKEN_FILE = os.path.expanduser("~/.verta_outlook_token.json")

# Scam classification types
SCAM_TYPES = {
    "TYPOSQUATTING": {
        "weight": 3,
        "description": "Fake domains mimicking legitimate brands",
        "patterns": ["paypa1", "micros0ft", "amaz0n", "gooogle", "facebok"]
    },
    "FORGERY": {
        "weight": 3,
        "description": "Impersonating legitimate organizations",
        "patterns": ["@gmail.com", "@yahoo.com", "@hotmail.com"],  # Free email for corporate claims
        "exclude_senders": ["google.com", "microsoft.com", "apple.com", "amazon.com", "discord.com", "noreply@", "no-reply@"],
        "brand_keywords": ["microsoft", "amazon", "paypal", "apple", "google", "netflix", "facebook", "instagram", "support", "security", "billing"]  # Only flag if claiming to be these brands
    },
    "TOO_GOOD_TO_BE_TRUE": {
        "weight": 2,
        "description": "Unrealistic offers",
        "patterns": ["congratulations", "won", "inheritance", "claim", "prize", "lottery"]
    },
    "GRAMMAR_RED_FLAGS": {
        "weight": 1,
        "description": "Poor language quality",
        "patterns": ["dear customer", "urgent!!!", "need you verify", "action required immediately"]
    },
    "URGENCY_SCARE_TACTICS": {
        "weight": 2,
        "description": "Artificial time pressure",
        "patterns": ["24 hours", "suspended", "terminated", "final notice", "act now", "last warning"]
    },
    "CREDENTIAL_HARVESTING": {
        "weight": 4,
        "description": "Attempts to steal login credentials",
        "patterns": ["verify your password", "confirm identity", "login required", "update your password", "reset your password"],
        "exclude_senders": ["google.com", "microsoft.com", "apple.com", "amazon.com", "discord.com", "noreply@", "no-reply@", "github.com"],
        "require_suspicious_link": True  # Only flag if there's a non-official link
    },
    "PAYMENT_FRAUD": {
        "weight": 3,
        "description": "Fraudulent invoices or billing",
        "patterns": ["invoice", "refund", "billing", "charged", "payment", "update card"],
        "exclude_senders": ["apple.com", "microsoft.com", "amazon.com", "google.com", "noreply@", "no-reply@"]
    },
    "MALICIOUS_ATTACHMENT": {
        "weight": 5,
        "description": "Potentially dangerous file attachments",
        "extensions": [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".docm", ".xlsm"]
    },
    "ADVANCE_FEE_FRAUD": {
        "weight": 4,
        "description": "Nigerian prince / inheritance scams",
        "patterns": ["dr.", "general", "foreign", "assistance", "transfer", "million"],
        "exclude_senders": ["discord.com", "noreply@", "no-reply@", "apple.com", "microsoft.com", "amazon.com", "tailscale.com", "github.com", "google.com"],  # Legitimate senders to exclude
        "require_multiple_patterns": True  # Only flag if 2+ patterns match
    },
    "LINK_MANIPULATION": {
        "weight": 2,
        "description": "Deceptive links",
        "patterns": ["bit.ly", "tinyurl", "ip address"],  # Removed "http://" - too many false positives
        "exclude_senders": ["discord.com", "noreply@", "no-reply@", "github.com", "microsoft.com", "google.com", "apple.com", "tailscale.com"]
    }
}

def load_phishtank_cache():
    """Load PhishTank URL cache if available"""
    cache_path = Path.home() / ".openclaw" / ".phishtank_cache.json"
    if cache_path.exists():
        with open(cache_path) as f:
            return json.load(f).get("phishing_urls", [])
    return []

def get_imap_password(account):
    """Load IMAP password from file"""
    if account not in IMAP_CREDENTIALS:
        return None
    password_file = IMAP_CREDENTIALS[account]["password_file"]
    if os.path.exists(password_file):
        with open(password_file) as f:
            return f.read().strip().replace(" ", "")
    return None

def fetch_unread_emails_outlook(account, limit=20):
    """Fetch emails from both Inbox and Junk folders using Microsoft Graph API"""
    if not os.path.exists(OUTLOOK_TOKEN_FILE):
        print(f"  Warning: No Outlook token found for {account}")
        return []
    
    try:
        with open(OUTLOOK_TOKEN_FILE) as f:
            token_data = json.load(f)
        
        access_token = token_data.get("access_token")
        if not access_token:
            print(f"  Warning: No access token in Outlook token file")
            return []
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        all_results = []
        
        # Scan Inbox
        print(f"  Scanning folder: inbox")
        inbox_url = "https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages"
        inbox_params = {"$top": limit, "$select": "subject,from,body,attachments,receivedDateTime"}
        
        response = requests.get(inbox_url, headers=headers, params=inbox_params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            inbox_count = len(data.get("value", []))
            print(f"    Found {inbox_count} emails in inbox")
            for msg in data.get("value", []):
                all_results.append({
                    "subject": msg.get("subject", ""),
                    "sender": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                    "body": msg.get("body", {}).get("content", ""),
                    "attachments": [att.get("name", "") for att in msg.get("attachments", [])],
                    "message_id": msg.get("id", ""),
                    "account": account,
                    "received_date": msg.get("receivedDateTime", datetime.now().isoformat()),
                    "folder": "inbox"
                })
        else:
            print(f"    Inbox error: {response.status_code}")
        
        # Get mail folders to find Junk folder ID
        print(f"  Scanning folder: junk")
        folders_url = "https://graph.microsoft.com/v1.0/me/mailfolders"
        folders_response = requests.get(folders_url, headers=headers, timeout=30)
        
        junk_folder_id = None
        if folders_response.status_code == 200:
            folders_data = folders_response.json()
            for folder in folders_data.get("value", []):
                if "junk" in folder.get("displayName", "").lower():
                    junk_folder_id = folder.get("id")
                    break
        
        if junk_folder_id:
            # Fetch messages from Junk folder using actual ID
            junk_url = f"https://graph.microsoft.com/v1.0/me/mailfolders/{junk_folder_id}/messages"
            junk_params = {"$top": limit, "$select": "subject,from,body,attachments,receivedDateTime"}
            
            response = requests.get(junk_url, headers=headers, params=junk_params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                junk_count = len(data.get("value", []))
                print(f"    Found {junk_count} emails in junk")
                for msg in data.get("value", []):
                    all_results.append({
                        "subject": msg.get("subject", ""),
                        "sender": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                        "body": msg.get("body", {}).get("content", ""),
                        "attachments": [att.get("name", "") for att in msg.get("attachments", [])],
                        "message_id": msg.get("id", ""),
                        "account": account,
                        "received_date": msg.get("receivedDateTime", datetime.now().isoformat()),
                        "folder": "junk"
                    })
            else:
                print(f"    Junk error: {response.status_code}")
        else:
            print(f"    Junk folder not found")
        
        return all_results
    
    except Exception as e:
        print(f"  Outlook API error: {e}")
        return []

def fetch_unread_emails_imap(account, limit=20):
    """Fetch emails from Inbox AND Spam folders using IMAP (Gmail only)"""
    if account not in IMAP_CREDENTIALS:
        return []
    
    password = get_imap_password(account)
    if not password:
        print(f"  Warning: No IMAP password found for {account}")
        return []
    
    server = IMAP_CREDENTIALS[account]["server"]
    
    all_results = []
    
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(account, password)
        
        # Scan INBOX
        print(f"  Scanning folder: inbox")
        try:
            mail.select("inbox")
            status, data = mail.search(None, "ALL")
            if status == "OK":
                email_ids = data[0].split()
                for eid in email_ids[:limit]:
                    status, msg_data = mail.fetch(eid, "(RFC822)")
                    if status == "OK" and msg_data[0][1]:
                        raw_email = email.message_from_bytes(msg_data[0][1])
                        all_results.append({
                            "subject": raw_email.get("Subject", ""),
                            "sender": raw_email.get("From", ""),
                            "body": extract_email_body(raw_email),
                            "attachments": extract_attachments(raw_email),
                            "message_id": eid.decode() if isinstance(eid, bytes) else str(eid),
                            "account": account,
                            "received_date": parse_email_date(raw_email),
                            "folder": "inbox"
                        })
                print(f"    Found {len(all_results)} emails in inbox")
            else:
                print(f"    Error searching inbox: {data}")
        except Exception as e:
            print(f"    Inbox scan error: {e}")
        
        # Scan SPAM folder (Gmail)
        print(f"  Scanning folder: spam")
        try:
            status, folders = mail.list()
            spam_folder = None
            if status == "OK":
                for f in folders:
                    folder_str = f.decode() if isinstance(f, bytes) else f
                    if "spam" in folder_str.lower() or "[Gmail]/Spam" in folder_str:
                        spam_folder = folder_str
                        break
                
                if spam_folder:
                    status, data = mail.select(spam_folder)
                    if status == "OK":
                        status, data = mail.search(None, "ALL")
                        if status == "OK":
                            email_ids = data[0].split()
                            spam_count = 0
                            for eid in email_ids[:limit]:
                                status, msg_data = mail.fetch(eid, "(RFC822)")
                                if status == "OK" and msg_data[0][1]:
                                    raw_email = email.message_from_bytes(msg_data[0][1])
                                    all_results.append({
                                        "subject": raw_email.get("Subject", ""),
                                        "sender": raw_email.get("From", ""),
                                        "body": extract_email_body(raw_email),
                                        "attachments": extract_attachments(raw_email),
                                        "message_id": eid.decode() if isinstance(eid, bytes) else str(eid),
                                        "account": account,
                                        "received_date": parse_email_date(raw_email),
                                        "folder": "spam"
                                    })
                                    spam_count += 1
                            print(f"    Found {spam_count} emails in spam")
                        else:
                            print(f"    Error searching spam folder: {data}")
                    else:
                        print(f"    Spam folder not accessible: {data}")
                else:
                    print(f"    Spam folder not found")
        except Exception as e:
            print(f"    Spam scan error: {e}")
        
        mail.logout()
        return all_results
    
    except Exception as e:
        print(f"  IMAP error for {account}: {e}")
        return []

def extract_email_body(raw_email):
    """Extract plain text body from email"""
    body = ""
    if raw_email.is_multipart():
        for part in raw_email.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode(errors="ignore")
                except:
                    pass
                break
    else:
        try:
            body = raw_email.get_payload(decode=True).decode(errors="ignore")
        except:
            pass
    return body

def extract_attachments(raw_email):
    """Extract attachment filenames from email"""
    attachments = []
    for part in raw_email.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
    return attachments

def parse_email_date(raw_email):
    """Parse email date from headers"""
    received_date = raw_email.get("Date") or raw_email.get("date") or ""
    try:
        from email.utils import parsedate_to_datetime
        if received_date:
            return parsedate_to_datetime(received_date).isoformat()
    except:
        pass
    return datetime.now().isoformat()

def fetch_emails(account, limit=20):
    """Fetch emails from Inbox + Junk/Spam folders using appropriate method"""
    if "gmail" in account.lower():
        return fetch_unread_emails_imap(account, limit=limit)
    elif "outlook" in account.lower() or "live" in account.lower() or "hotmail" in account.lower():
        return fetch_unread_emails_outlook(account, limit=limit)
    else:
        print(f"  Unknown account type: {account}")
        return []

def check_domain_typosquatting(domain, legitimate_domains):
    """Check if domain is typosquatting a legitimate brand"""
    domain = domain.lower()
    for legit in legitimate_domains:
        legit = legit.lower()
        # Simple edit distance check
        if domain != legit and len(domain) == len(legit):
            diff = sum(1 for a, b in zip(domain, legit) if a != b)
            if diff <= 2:
                return True, legit
        # Check for common substitutions
        if domain.replace("0", "o").replace("1", "l").replace("3", "e") == legit:
            return True, legit
    return False, None

def extract_urls(text):
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def analyze_email(subject, sender, body, attachments=None):
    """Analyze email and classify scam types"""
    classifications = []
    risk_score = 0
    
    # Parse sender
    sender_email = sender.split("<")[-1].strip(">").strip().lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    
    # Check attachments
    if attachments:
        for att in attachments:
            for ext in SCAM_TYPES["MALICIOUS_ATTACHMENT"]["extensions"]:
                if att.lower().endswith(ext):
                    classifications.append({
                        "type": "MALICIOUS_ATTACHMENT",
                        "confidence": 0.95,
                        "detail": f"Suspicious attachment: {att}"
                    })
                    risk_score += SCAM_TYPES["MALICIOUS_ATTACHMENT"]["weight"]
    
    # Check subject and body for patterns
    content = (subject + " " + body).lower()
    
    # Check if sender is from a legitimate/excluded domain
    def is_excluded_sender(scam_type):
        config = SCAM_TYPES.get(scam_type, {})
        excluded = config.get("exclude_senders", [])
        sender_lower = sender.lower()
        return any(excl in sender_lower for excl in excluded)
    
    # Extract URLs to check for suspicious links
    extracted_urls = extract_urls(body)
    has_suspicious_link = False
    for url in extracted_urls:
        # Check if URL is not from a legitimate domain
        if not any(legit in url for legit in ["google.com", "microsoft.com", "apple.com", "amazon.com", "discord.com", "github.com"]):
            has_suspicious_link = True
            break
    
    for scam_type, config in SCAM_TYPES.items():
        if scam_type == "MALICIOUS_ATTACHMENT":
            continue  # Already handled
        
        # Skip if sender is excluded for this scam type
        if is_excluded_sender(scam_type):
            continue
        
        # Special handling for CREDENTIAL_HARVESTING - require suspicious link
        if scam_type == "CREDENTIAL_HARVESTING" and config.get("require_suspicious_link"):
            if not has_suspicious_link:
                continue
        
        matches = 0
        for pattern in config["patterns"]:
            if pattern.lower() in content:
                matches += 1
        
        # Skip if requires multiple patterns but only 1 matched
        if config.get("require_multiple_patterns") and matches < 2:
            continue
        
        if matches > 0:
            confidence = min(0.95, 0.3 + (matches * 0.15))
            classifications.append({
                "type": scam_type,
                "confidence": confidence,
                "detail": f"Matched {matches} pattern(s): {[p for p in config['patterns'] if p.lower() in content]}"
            })
            risk_score += config["weight"]
    
    # Check sender domain
    if sender_domain:
        # Free email for corporate claim (only if claiming to be a brand)
        if sender_domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]:
            brand_keywords = SCAM_TYPES["FORGERY"].get("brand_keywords", [])
            brand_claimed = any(brand in subject.lower() or brand in body.lower() for brand in brand_keywords)
            
            # Also check if sender is excluded
            excluded = SCAM_TYPES["FORGERY"].get("exclude_senders", [])
            is_excluded = any(excl in sender.lower() for excl in excluded)
            
            if brand_claimed and not is_excluded:
                classifications.append({
                    "type": "FORGERY",
                    "confidence": 0.85,
                    "detail": f"Corporate brand claimed from free email: {sender_domain}"
                })
                risk_score += SCAM_TYPES["FORGERY"]["weight"]
        
        # Typosquatting check (only for unknown domains, not legitimate ones)
        legitimate_domains = ["microsoft.com", "amazon.com", "paypal.com", "apple.com", 
                            "google.com", "netflix.com", "facebook.com", "instagram.com",
                            "discord.com", "github.com", "google.com"]
        
        # Only check if domain is NOT exactly a legitimate domain
        if sender_domain not in legitimate_domains:
            is_typo, legit = check_domain_typosquatting(sender_domain, legitimate_domains)
            if is_typo:
                classifications.append({
                    "type": "TYPOSQUATTING",
                    "confidence": 0.9,
                    "detail": f"Lookalike domain: {sender_domain} (mimicking {legit})"
                })
                risk_score += SCAM_TYPES["TYPOSQUATTING"]["weight"]
    
    # Check URLs in body
    urls = extract_urls(body)
    phishtank = load_phishtank_cache()
    for url in urls:
        if url in phishtank:
            classifications.append({
                "type": "CREDENTIAL_HARVESTING",
                "confidence": 1.0,
                "detail": f"PhishTank match: {url}"
            })
            risk_score += 5  # Critical
    
    # Determine risk level
    if risk_score >= 8:
        risk_level = "CRITICAL"
    elif risk_score >= 6:
        risk_level = "HIGH"
    elif risk_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "timestamp": datetime.now().isoformat(),
        "subject": subject,
        "sender": sender,
        "classifications": classifications,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "primary_type": classifications[0]["type"] if classifications else None
    }

def scan_inbox(account, limit=20):
    """Scan inbox - routes to correct fetch function based on account"""
    try:
        # Route to correct fetch function
        if "outlook" in account.lower():
            messages = fetch_unread_emails_outlook(account, limit=limit)
        else:
            messages = fetch_unread_emails_imap(account, limit=limit)
        
        results = []
        for msg in messages:
            analysis = analyze_email(
                subject=msg.get("subject", ""),
                sender=msg.get("sender", ""),
                body=msg.get("body", ""),
                attachments=msg.get("attachments", [])
            )
            # Preserve message_id, account, and received_date for viewing and charting
            analysis["message_id"] = msg.get("message_id", "")
            analysis["account"] = msg.get("account", "")
            analysis["raw_body"] = msg.get("body", "")
            analysis["received_date"] = msg.get("received_date", "")
            results.append(analysis)
        
        return results
    except Exception as e:
        print(f"  Scan error for {account}: {e}")
        return {"error": str(e)}

def save_results(results, output_path):
    """Save scan results to JSON file"""
    clean_count = len([r for r in results if r.get("risk_level") == "LOW"])
    junk_count = len([r for r in results if r.get("risk_level") == "MEDIUM"])
    flagged_count = len([r for r in results if r.get("risk_level") in ["HIGH", "CRITICAL"]])
    
    with open(output_path, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "total_scanned": len(results),
            "clean_count": clean_count,
            "junk_count": junk_count,
            "flagged_count": flagged_count,
            "flagged": flagged_count,
            "accounts_scanned": list(set(r.get("account", "") for r in results if r.get("account"))),
            "clean_emails": [r for r in results if r.get("risk_level") == "LOW"],
            "junk_emails": [r for r in results if r.get("risk_level") == "MEDIUM"],
            "flagged_emails": [r for r in results if r.get("risk_level") in ["HIGH", "CRITICAL"]],
            "results": results
        }, f, indent=2)
    print(f"Results saved to: {output_path}")
    print(f"  Clean: {clean_count}, Junk: {junk_count}, Flagged: {flagged_count}")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python email_scams.py <account|all>")
        print("  account: Scan specific email account")
        print("  all: Scan all configured accounts")
        sys.exit(1)
    
    account = sys.argv[1]
    output_dir = Path(__file__).parent / "email_scans"
    output_dir.mkdir(exist_ok=True)
    
    if account.lower() == "all":
        accounts = EMAIL_ACCOUNTS
    else:
        accounts = [account]
    
    all_results = []
    for acc in accounts:
        print(f"Scanning {acc}...")
        results = scan_inbox(acc, limit=20)
        if isinstance(results, list):
            all_results.extend(results)
        elif "error" in results:
            print(f"  Error: {results['error']}")
    
    # Save combined results
    output_path = output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_results(all_results, output_path)
    
    # Summary
    flagged = len([r for r in all_results if r.get("risk_level") in ["HIGH", "CRITICAL"]])
    print(f"\nScan complete: {len(all_results)} emails analyzed, {flagged} flagged")
    
    # Output JSON for NetWatch integration
    print("\n--- JSON Output ---")
    junk = len([r for r in all_results if r.get("risk_level") == "MEDIUM"])
    legit = len([r for r in all_results if r.get("risk_level") == "LOW"])
    print(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "accounts_scanned": accounts,
        "total_emails": len(all_results),
        "clean_count": legit,
        "junk_count": junk,
        "flagged_count": flagged,
        "legit_emails": [r for r in all_results if r.get("risk_level") == "LOW"],
        "junk_emails": [r for r in all_results if r.get("risk_level") == "MEDIUM"],
        "flagged_emails": [r for r in all_results if r.get("risk_level") in ["HIGH", "CRITICAL"]]
    }, indent=2))

if __name__ == "__main__":
    main()
