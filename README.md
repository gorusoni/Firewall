PyFireSOC – Python Firewall & SOC Project
About the Project

PyFireSOC is a Python-based Firewall and Security Operations Center (SOC) project developed as part of my Cyber Security learning. The main objective of this project is to monitor network traffic, detect common cyber attacks, log security events, and generate alerts.

The project uses packet sniffing to inspect network traffic and applies different detection techniques to identify suspicious activities such as port scanning, SYN flooding, SQL Injection, XSS, brute force attacks, and other common threats.

This project is developed for educational purposes to understand how firewalls and intrusion detection systems work.

Features
Real-time packet monitoring
Port Scan Detection
SYN Flood Detection
DDoS Detection
Brute Force Detection
SQL Injection Detection
Cross Site Scripting (XSS) Detection
Command Injection Detection
Path Traversal Detection
IP Reputation Tracking
Email Alerts
Slack Alerts
Telegram Alerts
SQLite Database Logging
JSON and CSV Report Generation
Security Operations Center (SOC) Dashboard
Technologies Used
Python 3
Scapy
SQLite
Requests
Colorama
Tabulate
Project Structure
PyFireSOC/
│
├── main.py
├── firewall.py
├── detectors.py
├── database.py
├── alerts.py
├── reporting.py
├── soc.py
├── config.py
│
├── logs/
│
├── reports/
│
├── firewall.db
│
├── requirements.txt
│
└── README.md
Installation
1. Clone the repository
git clone https://github.com/your-username/PyFireSOC.git
2. Open the project folder
cd PyFireSOC
3. Install the required packages
pip install -r requirements.txt
4. Run the project

Open Command Prompt or PowerShell as Administrator and run:

python main.py
Required Python Packages
scapy
requests
colorama
tabulate

Install them manually if required:

pip install scapy requests colorama tabulate
How the Project Works
The application starts packet sniffing using Scapy.
Captured packets are analyzed one by one.
The detector checks whether the traffic matches any known attack patterns.
If an attack is detected, the event is stored in the SQLite database.
An alert is generated and sent through the configured notification channels.
Security reports can be generated from the stored logs.
Attacks Detected
Port Scan
SYN Flood
DDoS
Brute Force
SQL Injection
Cross Site Scripting (XSS)
Command Injection
Path Traversal
Reports

The project can generate reports containing:

Total packets monitored
Number of alerts
Types of attacks detected
Blocked IP addresses
Event history

Reports can be exported in JSON and CSV formats.

Limitations

This project is intended for learning and demonstration purposes. It is not a replacement for commercial firewall or enterprise security products.

Some limitations include:

Signature-based detection only
Requires Administrator privileges for packet capture
SQLite database is suitable only for small-scale projects
Tested in a local lab environment
Future Improvements

Some features that can be added in the future are:

Machine Learning based attack detection
GeoIP lookup
Real-time web dashboard
PDF report generation
Integration with threat intelligence feeds
Automatic Windows Firewall rule creation
What I Learned

While developing this project, I learned about:

Packet sniffing using Scapy
Network protocols
Firewall and IDS concepts
SQLite database handling
Python multithreading
Logging and reporting
API integration for Email, Slack, and Telegram alerts
Author

Gourav Soni

B.Tech (Cyber Security)

Mini Project – Python Firewall & Security Operations Center (SOC)

Disclaimer

This project is developed only for educational and learning purposes.

It should be used only in environments where you have permission to monitor or test network traffic. The author is not responsible for any misuse of this project.
