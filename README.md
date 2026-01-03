# ProbeSafeBot 🔒⚡

ProbeSafeBot is a secure and feature‑rich **Telegram bot** built with Python and Nmap for ethical network diagnostics.  
It allows authorized users to run safe port scans, OS detection, and other Nmap features directly from Telegram.

---

## ✨ Features
- 🔒 **Authorization** → Only whitelisted Telegram IDs can run scans
- ⚡ **Scan types**
  - `/scan <target>` → Fast scan (common ports)
  - `/scanfull <target>` → Deep scan with service & OS detection
  - `/osdetect <target>` → OS fingerprinting
  - `/ping <target>` → Host discovery
  - `/traceroute <target>` → Trace network path
  - `/servicedetect <target>` → Service version detection
  - `/vulnscan <target>` → Vulnerability script scan
- 📊 **Output formatting** → Results in Markdown tables, large outputs exported as `.txt`
- 🛡️ **Rate limiting** → Prevents abuse (default: one scan every 30 seconds per user)
- 👋 **Welcome guide** → `/start` shows usage instructions
- 🔧 **/whoami** → Quickly get your Telegram ID for authorization setup

---

## 🚀 Deployment
ProbeSafeBot can run:
- Locally on your PC (Windows Task Scheduler or NSSM service)
- On a VPS / cloud server (AWS, DigitalOcean, Hetzner, etc.)
- On free hosting platforms (Render, Railway, Heroku with worker dyno)
- Inside a Docker container for portability

---

## ⚠️ Usage Notes
- **Ethical scanning only** → Use ProbeSafeBot on systems you own or have explicit permission to test.
- **Authorization required** → Set your Telegram ID in `scan_bot.py`:
  ```python
  ALLOWED_USER_ID = 123456789
