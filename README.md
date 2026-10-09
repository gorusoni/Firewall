PyFireSOC – Python Network Monitor & SOC Project
About the Project

PyFireSOC is a Python-based network monitoring and Security Operations Center (SOC) project developed as part of my Cyber Security learning. The main objective of this project is to monitor network traffic, detect common cyber attacks, log security events, and generate alerts.

The project uses packet sniffing to inspect network traffic and applies different detection techniques to identify suspicious activities such as port scanning, SYN flooding, SQL Injection, XSS, brute force attacks, and other common threats.

This project is developed for educational purposes to understand how firewalls and intrusion detection systems work.

A note on the name: PyFireSOC detects and records attacks, but it does not drop packets. Scapy's sniffer is read-only, so a packet marked as blocked is logged, alerted on, and added to an internal block list — it still reaches the operating system. It is an IDS (detection), not an inline firewall (prevention). Adding real enforcement is listed under Future Improvements.

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
├── console.py
├── test_detectors.py
│
├── logs/            (created on first run)
│
├── reports/         (created on first run)
│
├── requirements.txt
│
├── .gitignore
│
└── README.md

The database (firewall.db), the log file and the generated reports are created at
runtime and are deliberately not tracked by git — they contain real captured
traffic from whatever network the tool was run on.

Installation
1. Clone the repository
git clone https://github.com/gorusoni/Firewall.git
2. Open the project folder
cd Firewall
3. Install the required packages
pip install -r requirements.txt
4. Run the project

Open Command Prompt or PowerShell as Administrator and run:

python main.py

Packet capture needs Administrator privileges on Windows (and root on Linux). On Windows, Npcap must be installed for Scapy to see an interface.

Required Python Packages
scapy
requests
colorama
tabulate

Install them manually if required:

pip install scapy requests colorama tabulate

Configuration

Defaults live in config.py and every setting that is environment-specific or
secret can be supplied through an environment variable instead, so nothing
sensitive has to be edited into the file:

PYFIRESOC_INTERFACE        capture interface; auto-detected when unset
PYFIRESOC_WHITELIST        extra comma-separated IPs that are never inspected
PYFIRESOC_LOG_PERMITTED    set to 1 to log permitted traffic as well
PYFIRESOC_ALL_TRAFFIC      set to 1 to also analyse established-connection
                           replies (noisy; see What Gets Analysed)

PYFIRESOC_EMAIL_ALERTS     set to 1 to enable email alerts
PYFIRESOC_SMTP_SERVER      SMTP host (default smtp.gmail.com)
PYFIRESOC_SMTP_PORT        SMTP port (default 587)
PYFIRESOC_SMTP_USERNAME    SMTP user
PYFIRESOC_SMTP_PASSWORD    SMTP password or app password
PYFIRESOC_ALERT_EMAIL      where alerts are sent

PYFIRESOC_SLACK_ALERTS     set to 1 to enable Slack alerts
PYFIRESOC_SLACK_WEBHOOK    Slack incoming webhook URL

PYFIRESOC_TELEGRAM_ALERTS      set to 1 to enable Telegram alerts
PYFIRESOC_TELEGRAM_BOT_TOKEN   bot token
PYFIRESOC_TELEGRAM_CHAT_ID     chat id

This machine's own addresses are detected and whitelisted automatically, so the
monitor does not score its own outbound traffic and block the host it runs on.
PYFIRESOC_WHITELIST adds others, such as the gateway or a known scanner. The
whitelist in use is printed at start-up.

If no interface is detected, the program lists the available interface names and
exits, so the right one can be set in PYFIRESOC_INTERFACE.

What Gets Analysed

Sniffing an interface shows traffic in both directions, and most of it is the
other half of connections this machine opened. Replies arrive on a random
high-numbered local port, so counting them produces nonsense: a file download
looks like a packet flood, and a few browser tabs look like a port sweep.

So behavioural detection (port scan, SYN flood, DDoS) only counts traffic aimed
at a service: connection attempts (TCP SYN), and packets to a port in
PROTECTED_PORTS. Payload signatures only run on the cleartext ports in
CLEARTEXT_HTTP_PORTS. Set PYFIRESOC_ALL_TRAFFIC=1 to examine everything, which
is useful to see the difference but noisy on a normal desktop.

The thresholds in config.py assume this narrower scope. Raise them if the lab
network is busy, and lower them for a demo where the attack traffic is light.

Running the Tests

The detection logic and the database layer are covered by unit tests that need
no network access and no Administrator privileges:

python -m unittest discover -v

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

Generate one on demand:

python main.py --generate-report --report-days 7

Limitations

This project is intended for learning and demonstration purposes. It is not a replacement for commercial firewall or enterprise security products.

Some limitations include:

Detection only — packets are logged and alerted on, never dropped
Only unsolicited, service-directed traffic is counted for behavioural
detection, so an attack that hides inside an established connection is missed
Signature-based detection, so novel attacks are missed and signatures can still
misfire on unusual but legitimate traffic
Payload inspection only works on cleartext ports (80 and 8080 by default);
traffic on 443 is encrypted and cannot be matched against signatures
Brute force is inferred from connection rate, not from actual failed logins
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
Automatic Windows Firewall rule creation, to make the blocking real
TLS-terminating proxy so HTTPS payloads can be inspected
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
