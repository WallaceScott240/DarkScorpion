![Fox Logo](https://i.postimg.cc/43HbQ6tH/Screenshot-2025-06-24-191151.png) ![Fox Logo]([https://example.com/image.png](https://i.postimg.cc/c4Nxx0Tp/Screenshot-2025-06-24-191650.png))


# 🦂 DarkScorpion - Advanced Web Vulnerability Scanner

**DarkScorpion** is a powerful GUI-based Python tool for scanning websites for common security vulnerabilities. With a modern dark-themed interface, it provides detailed analysis of XSS, SQL Injection, open redirects, security header misconfigurations, and SSL/TLS issues — all in one convenient application.

---

## 🧰 Features

- 🔍 **Scan Options**
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - Open Redirects
  - Missing Security Headers
  - SSL/TLS Misconfigurations

- 💡 **Interactive Interface**
  - Built with `Tkinter` and `ttk` themes
  - Clean dark UI with a dual-tabbed output: `Scan Report` and `Vulnerabilities`
  - Live progress updates and scan timing

- 🧠 **Smart Detection**
  - Includes advanced XSS and SQLi payloads
  - SSL certificate expiration and protocol checks
  - Detects cookie misconfigurations (e.g., missing Secure/HttpOnly flags)

- 📤 **Reporting**
  - Save scan results to `.txt` or `.html`
  - Color-coded severity levels: Critical, High, Medium, Low, Info

---

## 🖥️ Requirements

- **Python 3.7+**
- Required Python libraries:

```bash
pip install requests beautifulsoup4
```

---

## 🛠️ How to Use

1. **Run the Application**

```bash
python darkscorpion.py
```

2. **Enter Target URL**  
   Example: `https://www.example.com`

3. **Select Scan Options**  
   ✅ XSS, SQLi, Redirects, Headers, SSL (toggle as needed)

4. **Click "Start Scan"**  
   - Scan progress will update in real-time
   - Results appear in the `Scan Report` tab
   - Detected vulnerabilities are listed in the `Vulnerabilities` tab

5. **Save or Clear Results**
   - Click "Save Report" to export your findings
   - Click "Clear Results" to reset the session

---

## 📄 Sample Output

![Scan Output](Screenshot%202025-06-24%20191151.png)

---

## 🔐 Security Checks

- **SSL/TLS**  
  - Verifies certificate validity and expiry
  - Detects outdated protocols (TLS 1.0/1.1)

- **Cookies**  
  - Detects missing `Secure` and `HttpOnly` flags

- **HTTP Headers**  
  - Reports missing:
    - `Content-Security-Policy`
    - `X-Frame-Options`
    - `Strict-Transport-Security`
    - `X-Content-Type-Options`
    - `Referrer-Policy`

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**. Do **not scan websites** without **explicit permission**. Unauthorized use may be illegal and unethical.

---

## 💻 Developer Notes

- Built using:
  - `Tkinter`, `ttk`, `requests`, `BeautifulSoup`, `ssl`, `socket`, and `re`
- Payloads included for real-world vulnerability testing
- Progress bar and status indicators help track scanning activity

---

## 📬 Feedback & Contributions

Feel free to fork, open issues, or suggest improvements.

---

© 2025 DarkScorpion — Stay Secure 🛡️
