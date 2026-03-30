#  SecurePulse-SIEM

A real-time Security Information and Event Management (SIEM) system built using Wazuh and Flask for monitoring, detecting, and analyzing security threats.

---

##  Features

-  Real-time log monitoring using Wazuh  
-  Alert detection and visualization  
-  AI-powered alert analysis  
-  Interactive dashboard  
-  Secure configuration using environment variables  

---

##  Architecture

```
Wazuh Agent
     ↓
Wazuh Manager (API)
     ↓
Elasticsearch (Indexer)
     ↓
Flask Backend (Services Layer)
     ↓
Web Dashboard (UI)
```
---

##  Tech Stack

<p> <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" /> <img src="https://img.shields.io/badge/Flask-Web_Framework-black?logo=flask" /> <img src="https://img.shields.io/badge/Wazuh-SIEM-red" /> <img src="https://img.shields.io/badge/Elasticsearch-Search-yellow?logo=elasticsearch" /> <img src="https://img.shields.io/badge/Frontend-HTML/CSS/JS-orange" /> </p>

---

##  Screenshots

```markdown
![Dashboard](docs/dashboard.png)
![Alerts](docs/alerts.png)
![AI Analysis](docs/ai.png)
