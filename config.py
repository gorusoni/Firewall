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
# INTERFACE can be overridden with the PYFIRESOC_INTERFACE environment
# variable, e.g. "\Device\NPF_{5F9CD09C-...}" on Windows.
def _default_interface():
    """Best-effort guess at the capture interface"""
    try:
        from scapy.all import get_working_if
        return str(get_working_if())
    except Exception:
        return ""

INTERFACE = os.environ.get("PYFIRESOC_INTERFACE") or _default_interface()

# Hosts that are never inspected or blocked. Put this machine's own address
# here, otherwise its own outbound traffic gets scored as if it were an
# attacker. Comma-separated PYFIRESOC_WHITELIST overrides it.
WHITELIST = [ip for ip in os.environ.get("PYFIRESOC_WHITELIST", "").split(",") if ip]
BLACKLIST = []

PROTECTED_PORTS = [22, 23, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]

# Ports carrying cleartext HTTP. Payload signatures only make sense here - on
# 443/8443 they would be matched against encrypted bytes.
CLEARTEXT_HTTP_PORTS = [80, 8080]

# Services where a high rate of new connections suggests credential guessing
AUTH_PORTS = [22, 23, 3389, 5900]

BLOCK_DURATION = 300  # 5 minutes

# Reputation score at which an IP is blocked outright (0-100)
REPUTATION_BLOCK_SCORE = 70

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

# Email alerts. Secrets come from the environment so they never land in source
# control - export PYFIRESOC_SMTP_PASSWORD and friends in your shell.
EMAIL_ALERTS = os.environ.get("PYFIRESOC_EMAIL_ALERTS", "0") == "1"
SMTP_SERVER = os.environ.get("PYFIRESOC_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("PYFIRESOC_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("PYFIRESOC_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("PYFIRESOC_SMTP_PASSWORD", "")
ALERT_EMAIL = os.environ.get("PYFIRESOC_ALERT_EMAIL", "")

# Slack alerts
SLACK_ALERTS = os.environ.get("PYFIRESOC_SLACK_ALERTS", "0") == "1"
SLACK_WEBHOOK = os.environ.get("PYFIRESOC_SLACK_WEBHOOK", "")

# Telegram alerts
TELEGRAM_ALERTS = os.environ.get("PYFIRESOC_TELEGRAM_ALERTS", "0") == "1"
TELEGRAM_BOT_TOKEN = os.environ.get("PYFIRESOC_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("PYFIRESOC_TELEGRAM_CHAT_ID", "")

# ==================== EVENT LOGGING VOLUME ====================
# Writing a row per permitted packet fills the database with ordinary traffic
# and makes the sniffer the bottleneck. Off by default; attacks are always
# logged regardless of this setting.
LOG_PERMITTED_EVENTS = os.environ.get("PYFIRESOC_LOG_PERMITTED", "0") == "1"

# Buffered events are flushed once either limit is reached
EVENT_FLUSH_SIZE = 200
EVENT_FLUSH_SECONDS = 5

# ==================== LOGGING ====================
LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# ==================== REPORTING ====================
DAILY_REPORT_TIME = "23:59"  # 11:59 PM
AUTO_GENERATE_REPORT = True