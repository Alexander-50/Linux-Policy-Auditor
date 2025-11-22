---

# 🛡️ Linux Policy Auditor

### ⚡ A Python tool for auditing Linux authentication policies (PAM & login.defs)

---

## 📌 Tech & Status

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-Supported-brightgreen?logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Distros-Debian%20%7C%20RHEL-lightgrey" />
  <img src="https://img.shields.io/badge/Status-Active%20Development-blueviolet" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

---

## 🧠 Overview

**Linux Policy Auditor** is a Python-based security tool designed to evaluate the authentication policies of a Linux system.
It inspects PAM configuration files and `/etc/login.defs` to identify weak password settings and generate actionable, CIS-aligned recommendations.

The tool is lightweight, modular, and fully dependency-free. It automatically detects the correct configuration paths across Debian-based (Ubuntu, WSL) and RHEL-based (CentOS, Fedora) distributions.

---

## 🚀 How to Use

> **Note:** Requires **sudo** to read protected `/etc` configuration files.

### **1️⃣ Get Help**

```bash
python3 auditor.py --help
```

### **2️⃣ Run a Standard Console Audit**

```bash
sudo python3 auditor.py
```

### **3️⃣ Generate an HTML Report**

```bash
sudo python3 auditor.py --pam-file <path> --html report.html
```

### **4️⃣ Generate a JSON Report**

```bash
sudo python3 auditor.py --login-defs <path> --json audit.json
```

---

## 🧩 Data Sources

This tool directly inspects live system configuration—no external dataset needed.

### **Files Audited**

* `/etc/pam.d/common-password` (Debian)
* `/etc/pam.d/system-auth` (RHEL)
* `/etc/pam.d/password-auth` (RHEL)
* `/etc/login.defs` (All Linux)

**Goal:** Classify each policy as **Secure**, **Moderate**, or **Weak**.

---

## ⚙️ Project Workflow

### **Phase 1 — Parsing (`policy_parser.py`)**

* Detects active PAM file based on OS type
* Parses `login.defs` + PAM rules
* Extracts:

  * `pam_pwquality.so` → complexity
  * `pam_unix.so` → password history

**Output:** Raw policy dictionary

---

### **Phase 2 — Analysis (`policy_analyzer.py`)**

* Normalizes/cleans extracted values
* Applies defaults where missing
* Evaluates against CIS-like security baselines

**Output:** Object with findings + recommendations

---

### **Phase 3 — Reporting (`report.py`)**

* Supports console, JSON, HTML reporting
* Generates:

  * `report.html`
  * `audit.json`

**Output:** Full visual security audit

---

## 📊 Audit Checks

| Category   | Parameter        | Recommendation                 |
| ---------- | ---------------- | ------------------------------ |
| Complexity | pam_pwquality.so | Must be installed & configured |
| Complexity | minlen           | Set `minlen=14+`               |
| Complexity | dcredit          | Set `dcredit=-1`               |
| Complexity | ucredit          | Set `ucredit=-1`               |
| Complexity | lcredit          | Set `lcredit=-1`               |
| Complexity | ocredit          | Set `ocredit=-1`               |
| History    | remember         | Set `remember>=5`              |
| Lifetime   | PASS_MAX_DAYS    | ≤ 90 days                      |
| Lifetime   | PASS_MIN_DAYS    | ≥ 1 day                        |

---

## 🧰 Project Structure

```
Linux-Policy-Auditor/
│
├── auditor.py              # Main entry point (CLI controller)
├── policy_parser.py        # Extracts values from PAM + login.defs
├── policy_analyzer.py      # Evaluates policy & assigns security ratings
├── report.py               # Generates Console / JSON / HTML reports
│
├── report.html             # (Generated output)
├── audit.json              # (Generated output)
│
└── README.md               # Documentation
```

---

## 💡 Key Features

* 🔍 **Complete Authentication Policy Audit**
* 🧩 **Auto-Detects Debian/RHEL File Paths**
* 📤 **Exports Results as Console, JSON, HTML**
* 🟩 **Zero Dependencies — Pure Python**
* 🧱 **Modular Architecture (extend anytime)**
* 🛑 **Handles Missing Files Gracefully**

---

## 👨‍💻 Author

**Alexander P.B.**
Cybersecurity Researcher & Penetration Tester
IoT Security Specialist

📎 **GitHub:**
[https://github.com/Alexander-50](https://github.com/Alexander-50)

📧 *Open for research collaborations.*

---
