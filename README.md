<div align="center">

# 🔍 MWAVS

### Modular Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg?style=for-the-badge)]()
[![GitHub stars](https://img.shields.io/github/stars/r0zx/mwavs?style=for-the-badge)](https://github.com/r0zx/mwavs/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/r0zx/mwavs?style=for-the-badge)](https://github.com/r0zx/mwavs/network)
[![GitHub issues](https://img.shields.io/github/issues/r0zx/mwavs?style=for-the-badge)](https://github.com/r0zx/mwavs/issues)

**A production-grade, plugin-driven web application security scanner built for penetration testers, bug bounty hunters, and security professionals.**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔌 **Plugin Architecture** | Modular design with auto-discovery and hot-reload |
| 🎭 **XSS Detection** | Reflected, DOM-based hints, context-aware payloads |
| 💉 **SQL Injection** | Error-based, Boolean-blind, Time-based detection |
| 📁 **Directory Enumeration** | Wordlist-based with extension fuzzing |
| 🔗 **SSRF Detection** | Localhost, cloud metadata, internal network probing |
| 🌐 **CORS Misconfiguration** | Wildcard, reflected origin, null origin detection |
| ↗️ **Open Redirect** | URL parameter, JavaScript, meta refresh detection |
| 🖥️ **Interactive Mode** | Manual testing with request/response inspection |
| 📊 **Professional Reports** | JSON, HTML, TXT formats with evidence |
| 🛡️ **WAF Detection** | Cloudflare, Akamai, AWS WAF identification |
| 🔧 **Proxy Support** | Burp Suite and other proxy integration |

---

## 🎯 Vulnerability Coverage

| Vulnerability | Methods | Severity | Status |
|:-------------|:--------|:---------|:-------|
| Cross-Site Scripting (XSS) | Reflected, DOM-based, Context-aware | 🟠 High | ✅ Stable |
| SQL Injection | Error, Boolean, Time-based | 🔴 Critical | ✅ Stable |
| Directory Enumeration | Wordlist, Extensions | 🔵 Info-Medium | ✅ Stable |
| Server-Side Request Forgery | Localhost, Cloud, Internal | 🔴 Critical | ✅ Stable |
| CORS Misconfiguration | Wildcard, Reflected, Null | 🟡 Medium | ✅ Stable |
| Open Redirect | URL, JavaScript, Meta | 🟡 Medium | ✅ Stable |

---

## 📦 Installation

### Requirements
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
<<<<<<< HEAD
git clone https://github.com/r0zx/mwavs
pip install -e .

=======
# Clone the repository
git clone https://github.com/r0zx/mwavs.git
cd mwavs

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install MWAVS
pip install -e .

# Verify installation
mwavs --version
>>>>>>> e25a1df (Add documentation, scripts, tests, and base config files)
