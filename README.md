# Hive Guard 🛡️
### Registry Persistence Monitor for Windows

---

## 📌 Abstract
Hive Guard is a Windows-based security monitoring solution designed to detect and analyze persistence mechanisms commonly used by malware and advanced persistent threats (APTs). The system operates as a background service, continuously monitoring critical Windows registry hives and startup locations for suspicious modifications.

By combining real-time monitoring, event correlation, and risk-based analysis, Hive Guard enables early detection of stealthy persistence techniques such as registry autoruns and startup manipulation. The tool provides immediate alerts and structured logs to support incident response and forensic investigation.

---

## 📖 Introduction
Persistence is one of the most critical phases in modern cyber attacks. Threat actors often modify Windows registry keys and startup folders to maintain access to compromised systems even after reboots.

These techniques are widely used in:
- Malware infections  
- Advanced Persistent Threats (APTs)  
- Insider threats  

Traditional antivirus solutions may fail to detect such changes when they appear legitimate or blend with normal system behavior.

Hive Guard addresses this gap by continuously monitoring key persistence locations and detecting unauthorized modifications in real time.

---

## 🎯 Objectives
- Detect registry-based persistence mechanisms  
- Monitor startup folder modifications  
- Provide real-time alerts for suspicious activity  
- Enable forensic analysis through structured logs  
- Map detected behavior to known attack techniques  

---

## 🚀 Features
- 🔍 Real-time monitoring of critical registry hives  
- 🧠 Detection of persistence techniques  
- 📂 Startup folder change tracking  
- 📊 Risk scoring based on MITRE ATT&CK  
- 📝 Structured logging system  
- 🔔 Multi-channel alerting (notifications/logs)  
- ⚡ Lightweight background service  

---

## 🛠️ Technologies Used
- Python  
- Windows Registry APIs (`win32api`, `win32con`)  
- Windows Event Logs  
- SQLite (for baseline & alerts storage)  
- FastAPI (for backend APIs)  
- WebSockets (real-time communication)  

---

## ⚙️ How It Works
1. The system initializes a baseline of registry values  
2. Continuously monitors **11 critical registry locations**  
3. Watches startup folders for file changes  
4. Detects any modification, addition, or deletion  
5. Correlates events with system logs for attribution  
6. Assigns a risk score based on behavior  
7. Generates alerts and logs for analysis  

---

## 📂 Monitored Locations
- Run / RunOnce registry keys  
- Startup folders  
- User and system hives  
- Other persistence-related registry paths  

---

## 📸 Screenshots
<img width="975" height="492" alt="image" src="https://github.com/user-attachments/assets/10c9ead9-0ce2-4f74-928d-3d3459e129e2" />

