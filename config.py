import os
from pathlib import Path

# BASE PATHS 
BASE_DIR = Path(__file__).parent.absolute()
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH = os.path.join(BASE_DIR, "firewall.db")

# Create directories if they don't exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# FIREWALL SETTINGS 
from scapy.all import get_if_list
from scapy.all import get_working_if

INTERFACE = str(get_working_if())
# INTERFACE = r"\Device\NPF_{5F9CD09C-7B8B-4538-8B37-3AABFA526A5F}"
try:
    from scapy.all import get_working_if
    INTERFACE = str(get_working_if())
except:
    INTERFACE = r"\Device\NPF_..."

WHITELIST = ["192.168.1.12"]
BLACKLIST = []

PROTECTED_PORTS = [22, 23, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]

BLOCK_DURATION = 300  # 5 minutes

# ==================== ATTACK DETECTION THRESHOLDS ====================

PORT_SCAN_THRESHOLD = 5  # Number of different ports hit in X seconds
PORT_SCAN_WINDOW = 10     # Time window in seconds

# SYN Flood detection
SYN_FLOOD_THRESHOLD = 20  # SYN packets per second

# Brute Force detection
BRUTE_FORCE_THRESHOLD = 3  # Failed attempts per minute
BRUTE_FORCE_WINDOW = 60     # Time window in seconds

# DDoS detection
DDOS_THRESHOLD = 30       # Packets per second from single IP
DDOS_WINDOW = 10           # Time window in seconds

# ==================== ALERT SETTINGS ====================
# Console alerts
CONSOLE_ALERTS = True

# Email alerts
EMAIL_ALERTS = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password"
ALERT_EMAIL = "admin@yourcompany.com"

# Slack alerts
SLACK_ALERTS = False
SLACK_WEBHOOK = "https://hooks.slack.com/services/your/webhook/url"

# Telegram alerts
TELEGRAM_ALERTS = False
TELEGRAM_BOT_TOKEN = "your_bot_token"
TELEGRAM_CHAT_ID = "your_chat_id"

# ==================== LOGGING ====================
LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# ==================== DATABASE ====================
DB_PATH = DB_PATH

# ==================== REPORTING ====================
DAILY_REPORT_TIME = "23:59"  # 11:59 PM
AUTO_GENERATE_REPORT = True