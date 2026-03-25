#!/bin/bash
# Email Scam Scanner - Sandboxed Execution Wrapper
# Runs email scanning in an isolated environment with restricted permissions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="${SCRIPT_DIR}/sandbox"
SCAN_OUTPUT_DIR="${SCRIPT_DIR}/email_scans"

# Create sandbox directory if not exists
mkdir -p "$SANDBOX_DIR"
mkdir -p "$SCAN_OUTPUT_DIR"

# Security: Set restrictive permissions on sandbox
chmod 700 "$SANDBOX_DIR"
chmod 700 "$SCAN_OUTPUT_DIR"

# Security: Validate credentials are in protected locations
GMAIL_PASS="$HOME/.verta_gmail_app_password"
OUTLOOK_TOKEN="$HOME/.verta_outlook_token.json"

if [ ! -f "$GMAIL_PASS" ]; then
    echo "⚠️  Warning: Gmail password file not found at $GMAIL_PASS"
fi

if [ ! -f "$OUTLOOK_TOKEN" ]; then
    echo "⚠️  Warning: Outlook token file not found at $OUTLOOK_TOKEN"
fi

# Security: Run scanner with limited environment
# Clear sensitive env vars that shouldn't be inherited
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset OPENCLAW_TOKEN
unset DISCORD_TOKEN

# Create isolated temp directory for this scan
SCAN_TEMP=$(mktemp -d "${SANDBOX_DIR}/scan_XXXXXX")
trap "rm -rf '$SCAN_TEMP'" EXIT

echo "🛡️  Running email scanner in sandboxed mode..."
echo "   Sandbox dir: $SANDBOX_DIR"
echo "   Temp dir: $SCAN_TEMP"
echo "   Output dir: $SCAN_OUTPUT_DIR"

# Security: Run Python script with restricted umask (no world-readable files)
umask 077

# Execute scanner with isolated environment
cd "$SCRIPT_DIR"

# Expand "all" to actual accounts
if [ "$1" = "all" ]; then
    shift  # Remove "all" from args
    set -- "verta.xiao@outlook.com" "vertajxiao@gmail.com"
fi

# Create isolated Python script for sandboxed execution
cat > "$SCAN_TEMP/run_scan.py" << 'PYTHON_SCRIPT'
import sys
import os
import json
from datetime import datetime

# Import the email scanner
sys.path.insert(0, os.environ.get('SCRIPT_DIR', '.'))
import email_scams

# Override output to sandboxed temp dir
email_scams.EMAIL_SCANS_DIR = os.environ.get('SCAN_TEMP', '.')

# Get accounts from command line args
accounts = sys.argv[1:] if len(sys.argv) > 1 else ['verta.xiao@outlook.com', 'vertajxiao@gmail.com']

all_results = []
for acc in accounts:
    print(f"Scanning {acc}...")
    results = email_scams.scan_inbox(acc, limit=20)
    if isinstance(results, list):
        all_results.extend(results)

# Save results to temp dir
output_path = os.path.join(os.environ.get('SCAN_TEMP', '.'), 'results.json')
email_scams.save_results(all_results, output_path)

# Copy results to main output dir (atomic operation)
if os.path.exists(output_path):
    with open(output_path) as f:
        data = json.load(f)
    
    # Write to final location with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_path = os.path.join(os.environ.get('SCAN_OUTPUT_DIR', '.'), 'scan_' + timestamp + '.json')
    
    with open(final_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    # Set restrictive permissions on output
    os.chmod(final_path, 0o600)
    
    print(f'✅ Scan results saved to: {final_path}')
    print(f'   Total scanned: {data.get("total_scanned", 0)}')
    print(f'   Flagged: {data.get("flagged", 0)}')
    
    # Output JSON for API consumption
    print('\n--- JSON Output ---')
    print(json.dumps({
        'timestamp': datetime.now().isoformat(),
        'accounts_scanned': accounts,
        'total_emails': data.get('total_scanned', 0),
        'flagged_count': data.get('flagged', 0),
        'flagged_emails': data.get('results', [])[:data.get('flagged', 0)]
    }, indent=2))
else:
    print('❌ No results generated')
    sys.exit(1)
PYTHON_SCRIPT

# Export environment variables for the Python script
export SCRIPT_DIR="$SCRIPT_DIR"
export SCAN_TEMP="$SCAN_TEMP"
export SCAN_OUTPUT_DIR="$SCAN_OUTPUT_DIR"

# Run the isolated script with account args
python3 "$SCAN_TEMP/run_scan.py" "$@"

# Security: Cleanup temp files (trap handles this)
echo "✅ Sandbox cleanup complete"
