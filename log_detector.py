import subprocess
import re
from datetime import datetime
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText
import time
import argparse
import os

# ---------------- EMAIL ---------------- #
def send_email_alert(message):
    sender_email = "harshapotharaj@gmail.com"
    receiver_email = "harsha.secure56@gmail.com"

    app_password = os.getenv("EMAIL_PASS")

    print("DEBUG → Email:", sender_email)
    print("DEBUG → Password length:", len(app_password) if app_password else "None")

    if not app_password:
        print("❌ Email password not set")
        return

    msg = MIMEText(message)
    msg["Subject"] = "🚨 SECURITY ALERT"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        print("DEBUG → Connecting to SMTP...")
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.set_debuglevel(1)  # 🔥 VERY IMPORTANT

        server.starttls()
        print("DEBUG → Logging in...")

        server.login(sender_email, app_password)

        print("DEBUG → Sending email...")
        server.send_message(msg)

        server.quit()
        print("📧 Email sent!")

    except Exception as e:
        print("❌ FULL ERROR:", e)
# ---------------- GLOBAL STORAGE ---------------- #

ip_attempts = defaultdict(list)
user_enum_attempts = defaultdict(list)
successful_logins = defaultdict(list)
port_scan_attempts = defaultdict(list)
attack_summary = defaultdict(int)

blocked_ips = set()
last_email_time = {}
cooldown = 60

# ---------------- BLOCK IP ---------------- #

def block_ip(ip):
    if ip in blocked_ips or ip == "127.0.0.1":
        return

    subprocess.run(f"sudo ufw deny from {ip}", shell=True)
    blocked_ips.add(ip)
    print(f"🚫 BLOCKED: {ip}")

# ---------------- DASHBOARD (NON-INTRUSIVE) ---------------- #

def dashboard():
    print("\n===== 🚨 SECURITY SUMMARY =====")
    for ip, count in attack_summary.items():
        print(f"{ip} → {count} events")
    print("===============================\n")

# ---------------- FILE MONITOR ---------------- #

known_files = set()

def monitor_files():
    path = os.path.expanduser("~/Downloads")

    try:
        files = set(os.listdir(path))
        new_files = files - known_files

        for f in new_files:
            alert = f"[FILE ALERT] New file detected: {f}"
            print(alert)

            with open("alerts.log", "a") as log:
                log.write(alert + "\n")

        known_files.update(files)

    except:
        pass

# ---------------- PROCESS LOG ---------------- #

def process_log_line(line):
    if not ("Failed password" in line or "Accepted password" in line):
        return

    timestamp = None

    parts = line.split()
    if len(parts) >= 3:
        try:
            parsed = datetime.strptime(" ".join(parts[:3]), "%b %d %H:%M:%S")
            timestamp = parsed.replace(year=datetime.now().year)
        except:
            pass

    if not timestamp:
        iso = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line)
        if iso:
            timestamp = datetime.strptime(iso.group(), "%Y-%m-%dT%H:%M:%S")

    if not timestamp:
        return

    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    if not ip_match:
        return
    ip = ip_match.group(1)

    # -------- SUCCESS LOGIN -------- #
    if "Accepted password" in line:
        user = re.search(r'for (\w+)', line).group(1)
        successful_logins[ip].append((timestamp, user))
        detect_suspicious_login(ip)
        return

    # -------- FAILED LOGIN -------- #
    user_match = re.search(r'invalid user (\w+)', line)
    user = user_match.group(1) if user_match else "unknown"

    ip_attempts[ip].append((timestamp, user))
    ip_attempts[ip] = ip_attempts[ip][-10:]

    user_enum_attempts[ip].append((timestamp, user))
    user_enum_attempts[ip] = user_enum_attempts[ip][-10:]

    port_scan_attempts[ip].append(timestamp)
    port_scan_attempts[ip] = port_scan_attempts[ip][-20:]

    smart_detect(ip)
    detect_port_scan(ip)

# ---------------- SMART DETECTION ---------------- #

def smart_detect(ip):
    entries = ip_attempts[ip]
    enum_entries = user_enum_attempts[ip]

    if len(entries) < 3:
        return

    t1 = entries[-3][0]
    t3 = entries[-1][0]
    diff = (t3 - t1).total_seconds()

    brute = diff <= 10
    users = set([u for _, u in enum_entries[-10:]])
    enum = len(users) >= 3

    if brute and enum:
        level = "HIGH"
    elif brute:
        level = "MEDIUM"
    elif enum:
        level = "LOW"
    else:
        return

    alert = f"[{level} ALERT] {ip}"
    print(alert)

    attack_summary[ip] += 1

    # show summary occasionally
    if attack_summary[ip] % 3 == 0:
        dashboard()

    with open("alerts.log", "a") as f:
        f.write(alert + "\n")

    if level == "HIGH":
        trigger_response(ip, alert)

# ---------------- PORT SCAN ---------------- #

def detect_port_scan(ip):
    times = port_scan_attempts[ip]

    if len(times) < 5:
        return

    diff = (times[-1] - times[0]).total_seconds()

    if diff < 5:
        alert = f"[PORT SCAN ALERT] {ip}"
        print(alert)

        with open("alerts.log", "a") as f:
            f.write(alert + "\n")

# ---------------- SUSPICIOUS LOGIN ---------------- #

def detect_suspicious_login(ip):
    if len(ip_attempts[ip]) >= 3:
        alert = f"🚨 [CRITICAL] Account compromised from {ip}"
        print(alert)

        with open("alerts.log", "a") as f:
            f.write(alert + "\n")

        trigger_response(ip, alert)

# ---------------- RESPONSE ---------------- #

def trigger_response(ip, alert):
    now = time.time()
    last = last_email_time.get(ip, 0)

    if now - last > cooldown:
        send_email_alert(alert)
        last_email_time[ip] = now

    block_ip(ip)

# ---------------- LIVE MODE ---------------- #

def run_live():
    print("🟢 Monitoring started... Press Ctrl+C to stop\n")

    process = subprocess.Popen(
        ["stdbuf", "-oL", "journalctl", "-u", "ssh", "-f", "--no-pager"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        while True:
            line = process.stdout.readline()

            if line:
                process_log_line(line.strip())

            monitor_files()

    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")
        process.terminate()

# ---------------- STATIC MODE ---------------- #

def run_static():
    logs = subprocess.check_output(
        "journalctl -u ssh --no-pager", shell=True
    ).decode()

    for line in logs.split("\n"):
        process_log_line(line)

# ---------------- MAIN ---------------- #

parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["static", "live"], default="live")

args = parser.parse_args()

if args.mode == "live":
    run_live()
else:
    run_static()
