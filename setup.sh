#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-leaky-repo}"
AUTHOR_NAME="Dev User"
AUTHOR_EMAIL="dev@example.com"

# 任意: 日付を見やすく固定（コミットタイムスタンプ）
T0="2025-09-30T10:00:00"
T1="2025-10-01T11:00:00"
T2="2025-10-01T11:30:00"
T3="2025-10-02T09:15:00"
T4="2025-10-03T16:40:00"

rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"
git init -q
git config user.name "$AUTHOR_NAME"
git config user.email "$AUTHOR_EMAIL"

write_and_commit () {
  local when="$1"; shift
  local msg="$1"; shift
  # shellcheck disable=SC2016
  GIT_AUTHOR_DATE="$when" GIT_COMMITTER_DATE="$when" git add -A
  GIT_AUTHOR_DATE="$when" GIT_COMMITTER_DATE="$when" git commit -q -m "$msg"
}

# --- Commit 1: initial scaffold ---
cat > app.py <<'PY'
#!/usr/bin/env python3
import os
from storage import Storage

def main():
    s = Storage()
    print("OK: app scaffold. STORAGE_BACKEND=", s.backend)

if __name__ == "__main__":
    main()
PY

cat > storage.py <<'PY'
# IMPLEMETATION: without s3 logics
class Storage:
    def __init__(self):
        self.backend = "local"
    def put(self, key: str, data: bytes):
        # no-op
        return {"ok": True, "key": key, "bytes": len(data)}
PY

cat > requirements.txt <<'TXT'
boto3==1.35.0
TXT

cat > README.md <<'MD'
# Leaky Repo (CTF Dummy)
Small demo repo. Explore Git history with `git log -p`.
MD

write_and_commit "$T0" "chore: initial scaffold"

# --- Commit 2: add simple uploader (HARD-CODED CREDS) ---
cat > storage.py <<'PY'
import base64

# NOTE: fix before staging release
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION = "us-east-1"

class Storage:
    def __init__(self):
        self.backend = "s3"
        self.ak = AWS_ACCESS_KEY_ID
        self.sk = AWS_SECRET_ACCESS_KEY
        self.region = AWS_DEFAULT_REGION

    def put(self, key: str, data: bytes):
        digest = base64.b64encode(data).decode("utf-8")[:16]
        return {
            "ok": True,
            "backend": self.backend,
            "region": self.region,
            "key": key,
            "preview": digest
        }
PY

write_and_commit "$T1" "feat: add simple S3 uploader"

# --- Commit 3: delete hardcoded token (use env) ---
cat > storage.py <<'PY'
import base64
import os

# IMPLEMETATION: change to env
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

class Storage:
    def __init__(self):
        self.backend = "s3"
        self.ak = AWS_ACCESS_KEY_ID
        self.sk = AWS_SECRET_ACCESS_KEY
        self.region = AWS_DEFAULT_REGION

    def put(self, key: str, data: bytes):
        digest = base64.b64encode(data).decode("utf-8")[:16]
        return {
            "ok": True,
            "backend": self.backend,
            "region": self.region,
            "key": key,
            "preview": digest
        }
PY

cat > .env.example <<'ENV'
AWS_ACCESS_KEY_ID=CHANGE_ME
AWS_SECRET_ACCESS_KEY=CHANGE_ME
AWS_DEFAULT_REGION=us-east-1
ENV

cat > .gitignore <<'GI'
.env
__pycache__/
*.pyc
GI

write_and_commit "$T2" "refactor: delete hardcoded token (use env)"

# --- Commit 4: docs ---
cat > README.md <<'MD'
# Leaky Repo (CTF Dummy)

This tiny repo simulates a realistic mistake:
- An earlier commit accidentally added hard-coded AWS credentials.
- A later commit removed them and switched to environment variables.

## Explore
git log --oneline
git log -p
git show HEAD~3:storage.py # old version with hard-coded creds


> All values are *dummy*. No real AWS calls happen in this project.
MD

write_and_commit "$T3" "docs: add usage to README"

# --- Commit 5: small fix ---
applypatch () {
  # 一行だけ軽い修正
  sed -i.bak 's/OK: app scaffold/OK: app ready/g' app.py && rm -f app.py.bak
}
applypatch
write_and_commit "$T4" "fix: better error handling"

# オプション: 配布用に bundle/tar も作成
git bundle create ../leaky-repo.bundle --all >/dev/null 2>&1 || true
cd ..
tar -czf leaky-repo.tar.gz leaky-repo >/dev/null 2>&1 || true

echo "Done."
echo "Repo:      $(pwd)/leaky-repo"
echo "Bundle:    $(pwd)/leaky-repo.bundle  (optional)"
echo "Archive:   $(pwd)/leaky-repo.tar.gz  (optional)"
