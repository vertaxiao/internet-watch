#!/usr/bin/env python3
import json
import glob

# Get latest scan
scans = sorted(glob.glob('/Users/verta/.openclaw/workspace/projects/netwatch/email_scans/scan_*.json'), reverse=True)
if not scans:
    print('No scan files found')
    exit()

with open(scans[0]) as f:
    data = json.load(f)

# Get spam emails
spam = [e for e in data.get('results', []) if e.get('folder') == '[Gmail]/Spam']

print('=' * 70)
print('🗑️  YOUR GMAIL SPAM FOLDER')
print('=' * 70)
print(f'Total: {len(spam)} emails')
print()

if not spam:
    print('No emails in Spam folder')
else:
    for i, e in enumerate(spam[:15], 1):
        print(f'{i}. {e.get("subject", "No Subject")}')
        print(f'   From: {e.get("sender", "Unknown")}')
        print(f'   Risk: {e.get("risk_level")}')
        print(f'   Received: {e.get("received_date", "")[:16] if e.get("received_date") else "Unknown"}')
        print()
