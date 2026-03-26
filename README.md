# 🛡️ Lightweight Vulnerability Scanner using Python

## 📌 Overview

This project is a **lightweight vulnerability scanner** designed to perform basic reconnaissance and security checks on a given domain. It identifies potential security risks by analyzing **network availability, open ports, and SSL certificate validity**.

---

## 🎯 Objectives

* Check host availability using ICMP (Ping)
* Scan commonly used ports for open services
* Validate SSL certificate status and expiration
* Identify potential security risks
* Generate structured scan reports

---

## 🚀 Features

* 🌐 Domain to IP resolution
* 📡 ICMP (Ping) connectivity check
* 🔎 Multi-port scanning (Top common ports)
* ⚡ Fast scanning using multithreading
* 🔐 SSL certificate validation
* 🚨 Basic risk detection (FTP, RDP, etc.)
* 📄 Report generation (JSON + TXT)
* 📸 Screenshot-based output visualization

---

## 🛠️ Tech Stack

* Python
* socket (network connections)
* ssl (certificate validation)
* subprocess (ping execution)
* concurrent.futures (multithreading)
* json (report generation)

---

## 📂 Project Structure

```id="5kq2on"
vuln-scanner/
│── src/
│   └── scanner.py
│
│── reports/
│   ├── report.json
│   └── report.txt
│
│── images/
│   └── output.png
│
│── README.md
```

---

## ▶️ How to Run

### 1️⃣ Navigate to project directory

```bash id="m6l2fr"
cd vuln-scanner/src
```

### 2️⃣ Run the scanner

#### Option 1 (with argument)

```bash id="ux1o4l"
python scanner.py google.com
```

#### Option 2 (manual input)

```bash id="rr1k1o"
python scanner.py
```

---

## 📊 Sample Output

```id="r2zxtt"
🔍 Scanning: google.com

🌐 Resolved IP: 142.250.183.14
📡 Ping: Reachable

🔎 Scanning Ports...
Port 80: Open
Port 443: Open
Port 21: Closed

🔐 SSL Info:
Valid (expires in 85 days)

🚨 Risk Analysis:
No major risks detected
```

---

## 📁 Output Reports

Reports are saved in:

```id="z7f1lc"
reports/report.json
reports/report.txt
```

---

## 📸 Output Screenshot

![Scanner Output](images/output.png)

---

## 🧠 How It Works

1. Resolves domain to IP address
2. Checks connectivity using ICMP
3. Scans multiple ports using TCP sockets
4. Validates SSL certificate expiration
5. Performs basic risk analysis
6. Generates structured reports

---

## 🔍 Risk Detection Logic

The scanner flags potential risks such as:

* Open FTP port (21) → insecure protocol
* Open RDP port (3389) → brute-force risk
* SSL certificate expiring soon

---

## 🛡️ Use Case

This project simulates real-world cybersecurity tasks such as:

* Basic reconnaissance
* Vulnerability assessment
* Network service identification
* Security posture evaluation

---


## ⚠️ Disclaimer

This tool is intended for **educational purposes only**.
Only scan systems that you own or have explicit permission to test.

---

## 👤 Author

**Tanushka**
