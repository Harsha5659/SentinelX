<div align="center">

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**Personal Cyber Defense System**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Version](https://img.shields.io/badge/Version-2.0-00d4aa?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

*Real-time intrusion detection, automated threat response, and live alerting — built from scratch in Python.*

</div>

---

## What Is SentinelX?

SentinelX is a **real-time Linux intrusion detection system** built entirely in Python. It monitors live SSH logs via `journalctl`, correlates events into threat levels, sends email alerts, and auto-blocks malicious IPs using UFW — all from a single script with zero external dependencies beyond the Python standard library.

Built as a hands-on cybersecurity project to demonstrate practical skills in **log analysis, threat detection, incident response, and secure Python development**.

---

## Live Demo

```
  🛡  SENTINELX  —  SECURITY SUMMARY
  2026-05-22  12:19:52
  ──────────────────────────────────────────────────────────
  IP ADDRESS             EVENTS    STATUS
  ────────────────────────────────────────────────────────
  203.0.113.42               12    🚫 BLOCKED
  198.51.100.7                5    ⚠  ACTIVE
  ──────────────────────────────────────────────────────────
  Total IPs tracked : 2    Events : 17    Blocked : 1
```

**Alert output (colour-coded in terminal):**
```
12:19:47  [HIGH ALERT]    203.0.113.42  →  19 attempts, 3 users tried
12:19:52  [CRITICAL]      203.0.113.42  →  Login succeeded after brute-force
12:20:47  [FILE ALERT]    /home/user/Downloads  →  New file: payload.sh
12:21:03  [PORT_SCAN]     198.51.100.7  →  5 hits in 4.0s
```

---

## Features

| Feature | Description |
|--------|-------------|
| 🔴 **Brute Force Detection** | Detects rapid failed SSH logins within a configurable time window |
| 👤 **User Enumeration Detection** | Flags attempts across multiple distinct usernames from a single IP |
| 🧠 **Smart Alert Correlation** | Combines speed + enumeration to classify threats: LOW / MEDIUM / HIGH |
| 💀 **Account Compromise Detection** | CRITICAL alert when a login succeeds after a brute-force history |
| 🌐 **Port Scan Detection** | Identifies rapid connection bursts indicative of port sweeps |
| 📂 **File System Monitoring** | Background thread watches a folder for new file drops |
| 📧 **Email Alerts (Gmail SMTP)** | Rate-limited email notifications for confirmed threats |
| 🚫 **Automatic IP Blocking** | UFW-based auto-block on HIGH/CRITICAL detections |
| 📊 **Live CLI Dashboard** | Colour-coded threat summary with event counts and block status |
| 🔧 **Fully Configurable** | All thresholds and settings controlled via environment variables |

---

## How It Works

```
journalctl (live SSH logs)
        │
        ▼
  Log Parser  ──── timestamp + IP + username extracted
        │
        ▼
  Detection Engine
  ├── smart_detect()       →  brute force + enumeration correlation
  ├── detect_port_scan()   →  burst timing analysis
  └── detect_suspicious_login()  →  compromise detection
        │
        ▼
  Alert Writer  ──── colour-coded terminal + alerts.log
        │
        ├──▶  Email Alert (Gmail SMTP, rate-limited per IP)
        └──▶  IP Block (UFW deny rule)

  Background Thread:
  └── File Monitor  ──── watches ~/Downloads every 5 seconds
```

---

## Tech Stack

- **Language:** Python 3.8+ (standard library only — no pip installs required)
- **Log Source:** `journalctl` — systemd's native SSH service journal
- **Firewall:** UFW (Uncomplicated Firewall)
- **Alerting:** Gmail SMTP via `smtplib`
- **Concurrency:** `threading` — file monitor runs independently
- **Logging:** Python `logging` module — structured, timestamped output

---

## Setup

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install ufw openssh-server -y
sudo systemctl enable --now ssh
```

### 1. Clone the Repository

```bash
git clone https://github.com/Harsha5659/SentinelX.git
cd SentinelX
```

### 2. Configure Environment Variables

```bash
# Required for email alerts (optional — tool works without it)
export SENTINELX_FROM_EMAIL="you@gmail.com"
export SENTINELX_TO_EMAIL="you@gmail.com"
export EMAIL_PASS="your_gmail_app_password"

# Optional — tune detection thresholds
export SENTINELX_BRUTE_THRESHOLD=3    # failed attempts to trigger
export SENTINELX_BRUTE_WINDOW=10      # seconds
export SENTINELX_ENUM_THRESHOLD=3     # distinct usernames
export SENTINELX_COOLDOWN=60          # seconds between emails per IP
```

> **Gmail App Password:** Go to Google Account → Security → 2-Step Verification → App Passwords. Use that 16-character password, not your Gmail password.

### 3. Fix Log File Permissions (first run)

```bash
# If you previously ran with sudo, fix ownership once:
sudo chown $USER:$USER sentinelx.log alerts.log 2>/dev/null || true
```

### 4. Run

```bash
# Live monitoring (requires sudo for journalctl access)
sudo -E python3 log_detector.py --mode live

# Analyse existing logs
python3 log_detector.py --mode static

# View threat dashboard at any time
python3 log_detector.py --dashboard
```

---

## Testing

Run SentinelX in Terminal 1, then fire these in Terminal 2:

```bash
# Brute force — triggers MEDIUM alert
for i in {1..4}; do ssh fakeuser@localhost; done

# User enumeration — triggers LOW alert
ssh admin@localhost; ssh root@localhost; ssh test@localhost

# Combined attack — triggers HIGH alert + email + block
ssh admin@localhost; ssh root@localhost; ssh test@localhost; ssh harsha@localhost; ssh ubuntu@localhost

# Port scan — triggers PORT_SCAN alert
nmap -p 1-200 localhost

# File drop — triggers FILE alert
touch ~/Downloads/suspicious_file.txt

# On-demand dashboard (separate terminal, no sudo)
python3 log_detector.py --dashboard
```

**Expected alert progression:**

```
[LOW ALERT]      →  Enumeration only
[MEDIUM ALERT]   →  Speed-based brute force
[HIGH ALERT]     →  Brute force + enumeration combined  →  email sent + IP blocked
[CRITICAL]       →  Successful login after brute-force history
[PORT_SCAN]      →  Rapid connection burst
[FILE ALERT]     →  New file detected in monitored path
```

---

## Security Considerations

- **No credentials in code** — all sensitive config via environment variables
- **Loopback never blocked** — `127.0.0.1` is explicitly protected to prevent self-lockout
- **Rate-limited alerts** — email cooldown per IP prevents alert flooding
- **Graceful error handling** — no crashes on malformed log lines, missing tools, or SMTP failures
- **`shell=False` everywhere** — subprocess calls use argument lists to prevent injection

---

## Project Structure

```
SentinelX/
├── log_detector.py     # Core detection engine
├── requirements.txt    # No external deps (stdlib only)
├── .gitignore          # Excludes *.log and credentials
└── README.md
```

Log files created at runtime (gitignored):
```
sentinelx.log   # Internal structured log with timestamps
alerts.log      # Plain-text threat event log
```

---

## Roadmap

- [ ] Web dashboard (Flask + live WebSocket feed)
- [ ] GeoIP lookup — show attacker country on alerts
- [ ] AbuseIPDB integration — cross-reference attacking IPs against threat intel
- [ ] Multi-log support — nginx, Apache, `/var/log/auth.log`
- [ ] SQLite alert history — persistent, queryable event store
- [ ] Docker container — one-command deployment

---

## Skills Demonstrated

This project was built to apply and demonstrate real cybersecurity and development skills:

`Log Analysis` · `Intrusion Detection` · `Incident Response` · `Threat Correlation` · `Linux Security` · `Python` · `Secure Coding` · `Network Security` · `UFW / Firewall Management` · `SMTP / Email Alerting` · `Multithreading` · `systemd / journalctl`

---

## Author

**Harsha Potharaj**
Cybersecurity Student — Network Security · SOC Analysis · Threat Intelligence

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/your-profile)
[![GitHub](https://img.shields.io/badge/GitHub-Harsha5659-181717?style=flat-square&logo=github)](https://github.com/Harsha5659)

---

> ⚠️ **Legal Disclaimer:** SentinelX is built for educational purposes and authorized use on systems you own or have explicit permission to monitor. Do not use against systems without consent.
