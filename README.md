# 🔍 IntelRecon Toolkit

<div align="center">

![IntelRecon Banner](https://img.shields.io/badge/IntelRecon-OSINT%20Toolkit-00ffe0?style=for-the-badge&logo=target&logoColor=black)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A professional-grade OSINT & Reconnaissance Investigation Dashboard**
*Built for SOC Analysts, Penetration Testers & Cybersecurity Researchers*

</div>

---

## 📌 About The Project

**IntelRecon** is a full-stack cybersecurity tool that performs deep intelligence gathering on any domain or IP address. It automates the reconnaissance phase of security investigations — providing Whois data, DNS records, SSL certificate analysis, IP geolocation, subdomain enumeration, and threat reputation scoring — all in one clean, dark-themed analyst dashboard.

> ⚠️ **Disclaimer:** This tool is built for **educational purposes** and **authorized security research only**. Do not use it against targets you don't have permission to investigate.

---

## 👩‍💻 Authors

| Name | GitHub |
|---|---|
| Bhavika Bhoir | [@BhavikaBhoir](https://github.com/BhavikaBhoir) |
| Samyak Jadhav | Co-Developer |

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **Whois Lookup** | Registrar, creation date, expiration date, domain status |
| 🔎 **DNS Analysis** | A, MX, NS, TXT, AAAA records |
| 🛡️ **SSL Inspector** | Certificate validity, issuer, subject, expiry countdown |
| 📍 **IP Geolocation** | Country, city, ISP, ASN, organization |
| ⚠️ **Threat Reputation** | Detects phishing, malware, scam, fraud domains |
| 🕵️ **Subdomain Enumeration** | Discover subdomains via OSINT APIs |
| 📊 **Risk Scoring** | Automated 0–100 threat score with visual doughnut chart |
| 📁 **Investigation History** | All past scans saved and reloadable per session |
| 📄 **PDF Report Generation** | Download full dark-themed intelligence report as PDF |
| 🔐 **Login Panel** | Secure analyst authentication with session management |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip
- Git

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/BhavikaBhoir/IntelRecon.git

# 2. Navigate into the folder
cd IntelRecon

# 3. Install dependencies
pip install flask reportlab

# 4. Run the application
python app.py
```

### Access

Open your browser and go to:
http://localhost:5000

---

## 🔑 Login Credentials

| Username | Password |
|---|---|
| `admin` | `admin123` |
| `analyst` | `analyst123` |

---

## 🧪 Testing the Tool

**Test with Safe Domains ✅**
google.com
github.com
cloudflare.com
python.org
8.8.8.8

**Test with Risky Domains ⚠️**
login-paypal-secure.tk
free-v-bucks-generator.xyz
amazon-security-alert.xyz
netflix-account-verify.tk
bitcoin-doubler-now.top

---

## 📁 Project Structure
IntelRecon/
│
├── app.py                  # Flask backend — all routes & intelligence logic
├── requirements.txt        # Python dependencies
│
├── templates/
│   ├── login.html          # Login page
│   └── dashboard.html      # Main investigation dashboard
│
└── static/
├── css/
│   ├── login.css       # Login page styles
│   └── dashboard.css   # Dashboard styles
└── js/
└── dashboard.js    # Frontend logic, API calls, rendering

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| PDF Engine | ReportLab |
| Charts | Chart.js |
| Whois / Registry | RDAP Protocol |
| IP Intelligence | ip-api.com |
| Subdomain OSINT | HackerTarget API |
| DNS Lookup | nslookup (system) |

---

## 🎯 Use Cases

- 🏢 **SOC (Security Operations Center)** — Rapid domain/IP triage
- 🔓 **Penetration Testing** — Reconnaissance phase automation
- 🕵️ **Threat Intelligence** — Identify malicious infrastructure
- 🎓 **Learning** — Understand OSINT techniques hands-on
- 🚩 **CTF Challenges** — Capture The Flag recon tasks

---

## ⚙️ Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: flask` | Run `pip install flask reportlab` |
| Port 5000 busy (Mac) | Change `port=5000` to `port=5001` in `app.py` |
| DNS results empty | Install nslookup: `sudo apt install dnsutils` |
| Subdomains not found | HackerTarget free API rate limit — wait 1 minute |
| PDF not downloading | Make sure `reportlab` is installed |

---

## 📜 License

This project is licensed under the **MIT License** — feel free to use, modify and distribute with attribution.

---

## 🙌 Acknowledgements

- [RDAP Protocol](https://rdap.org) — Domain registry data
- [ip-api.com](https://ip-api.com) — IP geolocation
- [HackerTarget](https://hackertarget.com) — Subdomain enumeration
- [Chart.js](https://chartjs.org) — Threat visualization
- [ReportLab](https://reportlab.com) — PDF generation

---

<div align="center">

Made by **Bhavika Bhoir** & **Samyak Jadhav**

⭐ Star this repo if you found it useful!

</div>
