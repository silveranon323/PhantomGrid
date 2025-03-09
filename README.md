# 🕵️‍♂️ PhantomGrid – Advanced Cyber Threat Intelligence Honeypot

**PhantomGrid** is an advanced **SSH/Telnet honeypot** powered by **Cowrie**, designed to detect, log, and analyze malicious cyber activities in real-time. It features **AI-driven threat scoring, geolocation tracking, and automated threat intelligence reporting**, making it an essential tool for **cybersecurity professionals, SOC teams, and ethical hackers**.

## 🚀 Features

✅ **Real-Time Attack Monitoring** – Logs unauthorized SSH/Telnet access attempts.  
✅ **Brute Force Protection** – Detects multiple failed login attempts.  
✅ **IP Geolocation & Risk Analysis** – Tracks attacker location and ISP details.  
✅ **Threat Scoring System** – Assigns risk scores based on attacker behavior.  
✅ **Malicious Command Detection** – Identifies harmful commands like `rm -rf /*`.  
✅ **Threat Intelligence Integration** – Auto-reports malicious IPs to AbuseIPDB.  
✅ **Automated Reports & Heatmaps** – Generates visual attack summaries.  
✅ **SOC & SIEM Ready** – Easily integrates with security monitoring solutions.  

---

## 📂 Project Structure

```
PhantomGrid/
│── logs/               # Captured attack logs and reports
│── scripts/            # Automation scripts for analysis
│── dashboard/          # UI for monitoring attacks
│── config/             # Custom honeypot configuration files
│── requirements.txt    # Dependencies
│── honeypot.py         # Main script to run the honeypot
│── analyze_logs.py     # Log analysis and threat intelligence
```

---

## ⚡ Getting Started

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/silveranon323/phantomgrid.git
cd phantomgrid
```

### 2️⃣ Set Up the Environment
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Honeypot
```bash
python honeypot.py
```

### 4️⃣ Analyze Logs & Threats
```bash
python analyze_logs.py
```

---

## 🛡️ Use Cases

- **Cybersecurity Research** – Study real-world attack behaviors.  
- **SOC & Threat Intelligence** – Enhance security operations.  
- **Penetration Testing** – Simulate cyber threats in a controlled environment.  
- **Ethical Hacking Practice** – Improve skills in threat detection and response.  

---

## 📜 License

🔒 This project is released under the **MIT License**.

---

## 💬 Contribute & Support

🙌 Contributions are welcome! If you have feature suggestions or bug reports, feel free to open an **Issue** or submit a **Pull Request**.  

🔥 **Stay ahead of cyber threats with PhantomGrid!** 🚀
