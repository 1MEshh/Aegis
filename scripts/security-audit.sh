#!/usr/bin/env bash
# ==============================================================================
# Aegis: Zero-Leak, Hardening & DevSecOps Verification Gate
# Enforces zero filesystem paths, zero OS username leaks, zero hostname leaks,
# zero literal credentials, zero emojis, path remapping, and 100% test pass.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[security-audit] Starting Aegis zero-leak and DevSecOps verification..."

# 1. Verify git repository and tracked files
TRACKED_FILES="$(git ls-files)"
if [ -z "$TRACKED_FILES" ]; then
    echo "[security-audit] FAIL: No git-tracked files found." >&2
    exit 1
fi
echo "[security-audit] PASS: Git tracked files verified."

# 2. Check for hardcoded machine-specific paths (/home/<user>, /Users/<user>, C:\Users\<user>)
PATH_LEAKS="$(grep -rnE '(/home/[a-zA-Z0-9_-]+|/Users/[a-zA-Z0-9_-]+|C:\\\\Users\\\\[a-zA-Z0-9_-]+)' \
    include/ src/ tests/ fixtures/ Makefile README.md 2>/dev/null | \
    grep -vE '(/home/<user>|/Users/<user>|C:\\Users\\<user>)' || true)"

if [ -n "$PATH_LEAKS" ]; then
    echo "[security-audit] FAIL: Machine-specific filesystem path leak detected:" >&2
    echo "$PATH_LEAKS" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero machine-specific filesystem paths detected."

# 3. Check for current OS username leak in tracked repository files
CURRENT_USER="$(whoami 2>/dev/null || echo "")"
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "runner" ]; then
    USER_LEAKS="$(grep -rnF "$CURRENT_USER" include/ src/ tests/ fixtures/ scripts/ Makefile README.md 2>/dev/null || true)"
    if [ -n "$USER_LEAKS" ]; then
        echo "[security-audit] FAIL: Local OS username leak detected in repository:" >&2
        echo "$USER_LEAKS" >&2
        exit 1
    fi
fi
echo "[security-audit] PASS: Zero OS username leaks detected."

# 4. Check for current hostname leak in repository files
CURRENT_HOST="$(hostname 2>/dev/null || echo "")"
if [ -n "$CURRENT_HOST" ] && [ "$CURRENT_HOST" != "localhost" ]; then
    HOST_LEAKS="$(grep -rnF "$CURRENT_HOST" include/ src/ tests/ fixtures/ scripts/ Makefile README.md 2>/dev/null || true)"
    if [ -n "$HOST_LEAKS" ]; then
        echo "[security-audit] FAIL: Local hostname leak detected in repository:" >&2
        echo "$HOST_LEAKS" >&2
        exit 1
    fi
fi
echo "[security-audit] PASS: Zero hostname leaks detected."

# 5. Check for hardcoded credentials or private keys
CRED_LEAKS="$(grep -rnE '(BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})' \
    include/ src/ tests/ fixtures/ scripts/ Makefile README.md 2>/dev/null || true)"
if [ -n "$CRED_LEAKS" ]; then
    echo "[security-audit] FAIL: Credential leak detected:" >&2
    echo "$CRED_LEAKS" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero literal credentials detected."

# 6. Verify zero emojis across repository code, scripts, and documentation
TEXT_FILES="$(git ls-files | grep -vE '\.(png|gif|jpg|jpeg|ico|bin|mem|o|a|so)$')"
python3 -c '
import sys, re

# Range covers emoji blocks: emoticons, misc symbols/pictographs, transport/map, supplemental, etc.
emoji_pattern = re.compile(r"[\U0001F300-\U0001F64F\U0001F680-\U0001F6FF\U0001F700-\U0001F77F\U0001F780-\U0001F7FF\U0001F800-\U0001F8FF\U0001F900-\U0001F9FF\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF\U00002600-\U000026FF\U00002700-\U000027BF]")

leaks = 0
for filepath in sys.argv[1:]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                if emoji_pattern.search(line):
                    print(f"[security-audit] FAIL: Emoji detected in {filepath}:{line_no}: {line.strip()}")
                    leaks += 1
    except Exception:
        pass
if leaks > 0:
    sys.exit(1)
' $TEXT_FILES
echo "[security-audit] PASS: Zero emojis detected in code, comments, and documentation."

# 7. Verify Git configuration
GIT_USER="$(git config user.name || echo "")"
GIT_EMAIL="$(git config user.email || echo "")"
EXPECTED_USER="1MEshh"
EXPECTED_EMAIL="152591660+1MEshh@users.noreply.github.com"

if [ "$GIT_USER" != "$EXPECTED_USER" ]; then
    echo "[security-audit] FAIL: Git user.name is '$GIT_USER', expected '$EXPECTED_USER'." >&2
    exit 1
fi

if [ "$GIT_EMAIL" != "$EXPECTED_EMAIL" ]; then
    echo "[security-audit] FAIL: Git user.email is '$GIT_EMAIL', expected '$EXPECTED_EMAIL'." >&2
    exit 1
fi
echo "[security-audit] PASS: Git committer configuration matches verified identity."

# 8. Verify compiler path remapping in Makefile
if ! grep -q "\-ffile-prefix-map" Makefile; then
    echo "[security-audit] FAIL: Missing -ffile-prefix-map flag in Makefile." >&2
    exit 1
fi
echo "[security-audit] PASS: Compiler path remapping flag present."

# 9. Execute test suite and self-scan
echo "[security-audit] Building and running automated test suite..."
make clean
make test

echo "[security-audit] Verifying Aegis executable and running mock self-scan..."
make aegis
./bin/aegis scan --proc fixtures/mock_proc --format table

# 10. Verify compiled binary has no /home/<user> leaks
strings bin/aegis | grep -E '^/home/[a-zA-Z0-9_-]+' && {
    echo "[security-audit] FAIL: Machine path leak in compiled binary." >&2
    exit 1
} || true
echo "[security-audit] PASS: Binary symbol inspection verified zero machine path leaks."

echo "[security-audit] ALL AUDIT CHECKS PASSED SUCCESSFULLY."
