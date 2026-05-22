#!/usr/bin/env python3
"""
SentinelX — Real-Time Linux Intrusion Detection System
Author: Harsha Potharaj
Version: 2.0
"""

import subprocess
import re
import os
import sys
import time
import logging
import argparse
import smtplib
import threading
from datetime import datetime
from collections import defaultdict
from email.mime.text import MIMEText

# ─────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("sentinelx.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("SentinelX")

# ─────────────────────────────────────────
#  CONFIG  (all from environment variables)
# ─────────────────────────────────────────
SENDER_EMAIL    = os.getenv("SENTINELX_FROM_EMAIL", "")
RECEIVER_EMAIL  = os.getenv("SENTINELX_TO_EMAIL", SENDER_EMAIL)
APP_PASSWORD    = os.getenv("EMAIL_PASS", "")
EMAIL_COOLDOWN  = int(os.getenv("SENTINELX_COOLDOWN", "60"))   # seconds between alerts per IP
BRUTE_THRESHOLD = int(os.getenv("SENTINELX_BRUTE_THRESHOLD", "3"))   # attempts in window
BRUTE_WINDOW    = int(os.getenv("SENTINELX_BRUTE_WINDOW", "10"))      # seconds
ENUM_THRESHOLD  = int(os.getenv("SENTINELX_ENUM_THRESHOLD", "3"))     # distinct users
SCAN_THRESHOLD  = int(os.getenv("SENTINELX_SCAN_THRESHOLD", "5"))     # events in scan window
SCAN_WINDOW     = int(os.getenv("SENTINELX_SCAN_WINDOW", "5"))        # seconds
MONITOR_PATH    = os.path.expanduser(os.getenv("SENTINELX_MONITOR_PATH", "~/Downloads"))
FILE_CHECK_INTERVAL = 5  # seconds between file-system checks

# ─────────────────────────────────────────
#  GLOBAL STATE
# ─────────────────────────────────────────
ip_attempts      = defaultdict(list)   # ip → [(datetime, username), ...]
successful_logins = defaultdict(list)  # ip → [(datetime, username), ...]
port_scan_times  = defaultdict(list)   # ip → [datetime, ...]
attack_summary   = defaultdict(int)    # ip → total alert count
blocked_ips      = set()
last_email_time  = {}
known_files      = set()

# ─────────────────────────────────────────
#  TERMINAL COLOURS
# ─────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    BG_RED = "\033[41m"

# ─────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────
def dashboard():
    """Prints a clean, colour-coded security summary to the terminal."""
    width = 58
    border = "─" * width

    print(f"\n{C.BOLD}{C.CYAN}┌{border}┐{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}│{'  🛡  SENTINELX  —  SECURITY SUMMARY':^{width}}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}│  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S'):<{width-2}}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}├{border}┤{C.RESET}")

    if not attack_summary:
        print(f"{C.CYAN}│{C.GREEN}  ✅  No threats detected yet.{'':<{width-30}}│{C.RESET}")
    else:
        # Header row
        print(f"{C.CYAN}│{C.BOLD}  {'IP ADDRESS':<20} {'EVENTS':>8}  {'STATUS':<14}  │{C.RESET}")
        print(f"{C.CYAN}│{'  ' + '─'*54}│{C.RESET}")
        for ip, count in sorted(attack_summary.items(), key=lambda x: -x[1]):
            status = f"{C.RED}🚫 BLOCKED{C.CYAN}" if ip in blocked_ips else f"{C.YELLOW}⚠  ACTIVE{C.CYAN}"
            bar = "█" * min(count, 10)
            print(f"{C.CYAN}│  {ip:<20} {count:>8}  {status:<22}  │{C.RESET}")

    print(f"{C.BOLD}{C.CYAN}├{border}┤{C.RESET}")

    # Stats footer
    total_events  = sum(attack_summary.values())
    total_blocked = len(blocked_ips)
    total_ips     = len(attack_summary)
    print(f"{C.CYAN}│  {C.DIM}Total IPs tracked : {total_ips:<5}  "
          f"Events : {total_events:<6}  Blocked : {total_blocked:<4}{C.CYAN}│{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}└{border}┘{C.RESET}\n")

# ─────────────────────────────────────────
#  EMAIL ALERT
# ─────────────────────────────────────────
def send_email_alert(message: str):
    """Send an email alert via Gmail SMTP.  Silently skips if not configured."""
    if not APP_PASSWORD or not SENDER_EMAIL:
        logger.warning("Email not configured — set SENTINELX_FROM_EMAIL and EMAIL_PASS env vars.")
        return

    msg = MIMEText(message)
    msg["Subject"] = "🚨 SentinelX — SECURITY ALERT"
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = RECEIVER_EMAIL

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        logger.info("📧 Email alert sent.")
    except smtplib.SMTPAuthenticationError:
        logger.error("Email auth failed — check your Gmail App Password.")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
    except Exception as e:
        logger.error(f"Email send failed: {e}")

# ─────────────────────────────────────────
#  IP BLOCKING
# ─────────────────────────────────────────
def block_ip(ip: str):
    """Block an IP via UFW.  Localhost is always skipped to avoid self-lockout."""
    if ip in blocked_ips:
        return
    if ip == "127.0.0.1" or ip.startswith("127."):
        # Never block loopback — would break local services and testing
        logger.debug(f"Skipping block for loopback address {ip}")
        return

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            blocked_ips.add(ip)
            logger.warning(f"🚫 BLOCKED: {ip}")
        else:
            logger.error(f"UFW block failed for {ip}: {result.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("UFW not found — IP blocking unavailable.")
    except subprocess.TimeoutExpired:
        logger.error(f"UFW timed out trying to block {ip}")

# ─────────────────────────────────────────
#  ALERT WRITER
# ─────────────────────────────────────────
def write_alert(level: str, ip: str, detail: str = ""):
    """Print a colour-coded alert and append it to alerts.log."""
    colours = {"LOW": C.YELLOW, "MEDIUM": C.YELLOW + C.BOLD,
                "HIGH": C.RED + C.BOLD, "CRITICAL": C.BG_RED + C.BOLD,
                "PORT_SCAN": C.CYAN + C.BOLD, "FILE": C.GREEN + C.BOLD}
    colour = colours.get(level, C.RESET)
    ts = datetime.now().strftime("%H:%M:%S")

    label = f"[{level} ALERT]" if level not in ("CRITICAL", "FILE") else f"[{level}]"
    msg = f"{label} {ip}"
    if detail:
        msg += f"  →  {detail}"

    print(f"{colour}{ts}  {msg}{C.RESET}")

    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now().isoformat()}  {msg}\n")

    return msg  # returned so trigger_response can use it for email

# ─────────────────────────────────────────
#  RESPONSE
# ─────────────────────────────────────────
def trigger_response(ip: str, alert_msg: str):
    """Rate-limited email + UFW block for a confirmed threat."""
    now = time.time()
    if now - last_email_time.get(ip, 0) > EMAIL_COOLDOWN:
        send_email_alert(alert_msg)
        last_email_time[ip] = now
    block_ip(ip)

# ─────────────────────────────────────────
#  DETECTION — BRUTE FORCE / ENUM
# ─────────────────────────────────────────
def smart_detect(ip: str):
    """Correlate failed login events into LOW / MEDIUM / HIGH alerts."""
    entries = ip_attempts[ip]
    if len(entries) < BRUTE_THRESHOLD:
        return

    recent = entries[-BRUTE_THRESHOLD:]
    t_first, t_last = recent[0][0], recent[-1][0]
    diff = (t_last - t_first).total_seconds()

    brute = diff <= BRUTE_WINDOW
    users = {u for _, u in entries[-10:]}
    enum  = len(users) >= ENUM_THRESHOLD

    if brute and enum:
        level = "HIGH"
    elif brute:
        level = "MEDIUM"
    elif enum:
        level = "LOW"
    else:
        return

    detail = f"{len(entries)} attempts, {len(users)} users tried"
    msg = write_alert(level, ip, detail)
    attack_summary[ip] += 1

    if attack_summary[ip] % 5 == 0:
        dashboard()

    if level == "HIGH":
        trigger_response(ip, msg)

# ─────────────────────────────────────────
#  DETECTION — PORT SCAN
# ─────────────────────────────────────────
def detect_port_scan(ip: str):
    """Detect rapid connection bursts that suggest a port scan."""
    times = port_scan_times[ip]
    if len(times) < SCAN_THRESHOLD:
        return
    diff = (times[-1] - times[0]).total_seconds()
    if diff < SCAN_WINDOW:
        msg = write_alert("PORT_SCAN", ip, f"{len(times)} hits in {diff:.1f}s")
        attack_summary[ip] += 1
        trigger_response(ip, msg)

# ─────────────────────────────────────────
#  DETECTION — SUSPICIOUS LOGIN
# ─────────────────────────────────────────
def detect_suspicious_login(ip: str):
    """Flag a successful login from an IP with a prior brute-force history."""
    if len(ip_attempts[ip]) >= BRUTE_THRESHOLD:
        logins = successful_logins[ip]
        users  = ", ".join({u for _, u in logins})
        msg = write_alert("CRITICAL", ip, f"Login succeeded after brute-force (users: {users})")
        attack_summary[ip] += 1
        trigger_response(ip, msg)

# ─────────────────────────────────────────
#  LOG LINE PARSER
# ─────────────────────────────────────────
def _parse_timestamp(line: str):
    """Try syslog format first, then ISO-8601."""
    parts = line.split()
    if len(parts) >= 3:
        try:
            parsed = datetime.strptime(" ".join(parts[:3]), "%b %d %H:%M:%S")
            return parsed.replace(year=datetime.now().year)
        except ValueError:
            pass
    iso = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
    if iso:
        try:
            return datetime.strptime(iso.group(), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    return None


def process_log_line(line: str):
    """Parse a single SSH log line and feed the detection engine."""
    if not line:
        return

    is_fail    = "Failed password" in line
    is_success = "Accepted password" in line or "Accepted publickey" in line

    if not (is_fail or is_success):
        return

    timestamp = _parse_timestamp(line)
    if not timestamp:
        return

    ip_match = re.search(r'from (\d{1,3}(?:\.\d{1,3}){3})', line)
    if not ip_match:
        return
    ip = ip_match.group(1)

    if is_success:
        user_match = re.search(r'for (?:invalid user )?(\w+)', line)
        user = user_match.group(1) if user_match else "unknown"
        successful_logins[ip].append((timestamp, user))
        detect_suspicious_login(ip)
        return

    # Failed login
    user_match = re.search(r'invalid user (\w+)', line)
    user = user_match.group(1) if user_match else "unknown"

    ip_attempts[ip].append((timestamp, user))
    ip_attempts[ip] = ip_attempts[ip][-20:]          # keep last 20 per IP

    port_scan_times[ip].append(timestamp)
    port_scan_times[ip] = port_scan_times[ip][-20:]  # keep last 20

    smart_detect(ip)
    detect_port_scan(ip)

# ─────────────────────────────────────────
#  FILE MONITOR  (runs in its own thread)
# ─────────────────────────────────────────
def _file_monitor_loop():
    """Background thread — checks the monitored folder every FILE_CHECK_INTERVAL seconds."""
    global known_files
    if not os.path.isdir(MONITOR_PATH):
        logger.warning(f"Monitor path not found: {MONITOR_PATH}")
        return

    known_files = set(os.listdir(MONITOR_PATH))
    logger.info(f"📂 File monitor active on: {MONITOR_PATH}")

    while True:
        time.sleep(FILE_CHECK_INTERVAL)
        try:
            current = set(os.listdir(MONITOR_PATH))
            new_files = current - known_files
            for f in sorted(new_files):
                write_alert("FILE", MONITOR_PATH, f"New file: {f}")
            known_files = current
        except PermissionError:
            pass
        except Exception as e:
            logger.debug(f"File monitor error: {e}")

# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
def print_banner():
    print(f"""
{C.BOLD}{C.CYAN}
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}           Personal Cyber Defense System  v2.0  |  by Harsha Potharaj{C.RESET}
""")

# ─────────────────────────────────────────
#  LIVE MODE
# ─────────────────────────────────────────
def run_live():
    print_banner()
    logger.info("🟢 Live monitoring started. Press Ctrl+C to stop.\n")

    # Start file monitor in background
    t = threading.Thread(target=_file_monitor_loop, daemon=True)
    t.start()

    # Check journalctl is available
    if subprocess.run(["which", "journalctl"], capture_output=True).returncode != 0:
        logger.error("journalctl not found. Are you on a systemd system?")
        sys.exit(1)

    process = subprocess.Popen(
        ["stdbuf", "-oL", "journalctl", "-u", "ssh", "-f", "--no-pager",
         "--output=short-iso"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        while True:
            line = process.stdout.readline()
            if not line:
                # journalctl died — try to detect why
                err = process.stderr.readline()
                if err:
                    logger.error(f"journalctl error: {err.strip()}")
                time.sleep(0.5)
                continue
            process_log_line(line.strip())

    except KeyboardInterrupt:
        print(f"\n{C.BOLD}🛑  Monitoring stopped.{C.RESET}")
        dashboard()
        process.terminate()

# ─────────────────────────────────────────
#  STATIC MODE
# ─────────────────────────────────────────
def run_static():
    print_banner()
    logger.info("📋 Static analysis mode — reading existing SSH logs...")

    try:
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "--no-pager", "--output=short-iso"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"journalctl error: {result.stderr.strip()}")
            sys.exit(1)

        lines = result.stdout.split("\n")
        logger.info(f"Processing {len(lines)} log lines...")

        for line in lines:
            process_log_line(line)

        dashboard()
        logger.info("✅ Static analysis complete.")

    except subprocess.TimeoutExpired:
        logger.error("journalctl timed out during static analysis.")
    except FileNotFoundError:
        logger.error("journalctl not found.")

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SentinelX — Real-Time Linux Intrusion Detection System"
    )
    parser.add_argument(
        "--mode",
        choices=["static", "live"],
        default="live",
        help="live = stream logs in real time (default)  |  static = analyse existing logs"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Print the current threat summary and exit"
    )
    args = parser.parse_args()

    if args.dashboard:
        dashboard()
        return

    if args.mode == "live":
        run_live()
    else:
        run_static()


if __name__ == "__main__":
    main()
