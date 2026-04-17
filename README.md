# 🛡️ SentinelX – Personal Cyber Defense System

## 📌 Overview

SentinelX is a real-time cybersecurity monitoring system built in Python.
It detects suspicious activities from system logs and responds automatically.

---

## 🚀 Features

* 🔐 Brute Force Detection
* 👤 User Enumeration Detection
* 🧠 Smart Alert Correlation (LOW / MEDIUM / HIGH)
* 🚨 Suspicious Login Detection (Account Compromise)
* 🌐 Port Scan Detection
* 📂 File Monitoring (Downloads folder)
* 📧 Email Alerts (Gmail SMTP)
* 🚫 Automatic IP Blocking (UFW)
* 📊 Live Security Summary Dashboard

---

## 🧠 How It Works

```
System Logs → Detection Engine → Smart Alerts →
    → Email Notification
    → IP Blocking
    → Dashboard Update
```

---

## ⚙️ Setup

### 1. Clone Repository

```
git clone https://github.com/YOUR_USERNAME/SentinelX.git
cd SentinelX
```

---

### 2. Set Email App Password

```
export EMAIL_PASS="your_app_password"
```

> ⚠️ Use Gmail App Password (not your Gmail password)

---

### 3. Run the System

```
sudo -E python3 log_detector.py --mode live
```

---

## 🧪 Testing

### Brute Force

```
ssh fakeuser@localhost
```

### Enumeration

```
ssh admin@localhost
ssh root@localhost
ssh test@localhost
```

### Port Scan

```
nmap -p 1-100 localhost
```

### File Monitoring

```
cd ~/Downloads
touch testfile.txt
```

---

## 📊 Sample Output

```
[LOW ALERT] 127.0.0.1
[MEDIUM ALERT] 127.0.0.1
[HIGH ALERT] 127.0.0.1

🚨 [CRITICAL] Account compromised from 127.0.0.1

[PORT SCAN ALERT] 127.0.0.1
[FILE ALERT] New file detected: testfile.txt
```

---

## 🛠️ Tech Stack

* Python
* Linux (journalctl, ssh logs)
* SMTP (Gmail)
* UFW Firewall

---

## 📌 Future Improvements

* Web dashboard
* Multi-log support (nginx, system logs)
* Threat intelligence integration
* ML-based anomaly detection

---

## 👨‍💻 Author

Harsha Potharaj
Cybersecurity Enthusiast
