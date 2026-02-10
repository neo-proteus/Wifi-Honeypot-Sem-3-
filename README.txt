# 🛡️ Windows Honeypot with LAN Discovery & Dashboard

## 📌 Project Overview

This project is a **Windows‑friendly, low‑interaction honeypot** designed for educational and defensive cybersecurity research.

It simulates common network services (FTP, Telnet, HTTP) and logs **real connection attempts** and **LAN devices** within an **isolated or consent‑based network**. A built‑in Flask dashboard visualizes activity in real time.

⚠️ **This project is intended strictly for educational and ethical use.**

---

## 🎯 Features

* Low‑interaction honeypot (ports: 21, 23, 80, 8080)
* Captures **real IP addresses** of interacting devices
* LAN discovery using ping sweep + ARP table (Windows)
* MAC address vendor lookup (optional)
* SQLite database for logs and devices
* Flask‑based admin panel & dashboard
* Async + threaded architecture

---

## 🧠 How It Works (Concept)

* The honeypot listens on multiple ports and records incoming connections.
* Any device **on the same Wi‑Fi / LAN** that interacts with the honeypot will have its **real private IP address** logged.
* LAN discovery periodically identifies devices on the same network using ARP.
* All data is stored locally and visualized via a dashboard.

📌 **Scope limitation:**

* Devices must be on the **same network** or directly connect to the honeypot.
* The project does **not** spy on external or unrelated networks.

---

## 🖥️ System Requirements

* Windows 10 / 11
* Python 3.10+
* Administrator privileges (for LAN discovery)
* Network you own or have permission to test

---

## 📦 Dependencies

Install required Python packages:

* flask
* python-dotenv
* psutil
* mac-vendor-lookup (optional)

> ⚠️ `netifaces` is optional and **not required** on Windows. The program automatically falls back to `psutil`.

---

## ⚙️ Installation & Setup

### 1️⃣ Open Command Prompt as Administrator

Required for `ping` and `arp` commands.

```
Start → cmd → Right‑click → Run as administrator
```

---

### 2️⃣ Navigate to the project directory

Example:

```
cd /d E:\Python
```

Ensure the file exists:

```
honeypot_windows.py
```

---

### 3️⃣ (Recommended) Create a Virtual Environment

```
python.exe -m venv venv
venv\Scripts\activate
```

---

### 4️⃣ Install dependencies

```
python.exe -m pip install flask python-dotenv psutil mac-vendor-lookup
```

---

## ▶️ Running the Honeypot

```
python.exe honeypot_windows.py
```

Expected output:

* Honeypot listening on configured ports
* Discovery worker status
* Admin and dashboard URLs

---

## 🌐 Accessing the Dashboard

### Admin Panel

```
http://127.0.0.1:5000/admin?token=demo_token
```

### Dashboard

```
http://127.0.0.1:5000/dashboard?token=demo_token
```

Displays:

* Connections per hour
* Latest honeypot hits
* Known LAN devices

---

## 🧪 Testing the Honeypot

From another device **on the same Wi‑Fi**:

* Browser:

```
http://<honeypot-ip>
```

* Telnet:

```
telnet <honeypot-ip> 23
```

The connection will appear instantly in the dashboard.

---

## 🔐 Ethics & Safety Notice

* Run **only on networks you own or have permission to test**
* No credential harvesting is performed
* Designed for **defensive learning**, not surveillance
* Suitable for academic labs and demonstrations

---

## 📚 Academic Use Statement

This honeypot was deployed in an **isolated lab environment with dummy devices** to observe real IP‑level interactions and network behavior for cybersecurity learning purposes.

---

## 🏁 Conclusion

This project demonstrates practical concepts in:

* Network security
* Honeypot design
* Traffic logging
* LAN discovery
* Defensive cybersecurity monitoring

It is suitable for:

* College projects
* Cybersecurity labs
* Demonstrations and evaluations

---

🛡️ *Built for learning. Deployed responsibly.*
