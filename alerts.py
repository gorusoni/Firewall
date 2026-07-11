import smtplib
import requests
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Severity colors
SEVERITY_COLORS = {
    "info": Fore.BLUE,
    "low": Fore.GREEN,
    "medium": Fore.YELLOW,
    "high": Fore.RED,
    "critical": Fore.MAGENTA
}

class AlertSystem:
    """Multi-channel alerting system"""
    
    def __init__(self, db):
        self.db = db
        self.last_alerts = {}
        self.console_enabled = True
        
        # Load config
        from config import (
            CONSOLE_ALERTS, EMAIL_ALERTS, SLACK_ALERTS, TELEGRAM_ALERTS
        )
        
        self.console_enabled = CONSOLE_ALERTS
        self.email_enabled = EMAIL_ALERTS
        self.slack_enabled = SLACK_ALERTS
        self.telegram_enabled = TELEGRAM_ALERTS
        
        # Email config
        if self.email_enabled:
            from config import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, ALERT_EMAIL
            self.smtp_server = SMTP_SERVER
            self.smtp_port = SMTP_PORT
            self.smtp_username = SMTP_USERNAME
            self.smtp_password = SMTP_PASSWORD
            self.alert_email = ALERT_EMAIL
        
        # Slack config
        if self.slack_enabled:
            from config import SLACK_WEBHOOK
            self.slack_webhook = SLACK_WEBHOOK
        
        # Telegram config
        if self.telegram_enabled:
            from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
            self.telegram_bot = TELEGRAM_BOT_TOKEN
            self.telegram_chat = TELEGRAM_CHAT_ID
    
    def send_alert(self, severity: str, title: str, description: str,
                   src_ip: str = "", dst_ip: str = "") -> int:
        """Send alert through all configured channels"""
        
        # Deduplicate
        alert_key = f"{title}_{src_ip}_{severity}"
        if alert_key in self.last_alerts:
            last_time = self.last_alerts[alert_key]
            if (datetime.now() - last_time).seconds < 300:
                return 0  # Skip duplicate alert
        
        self.last_alerts[alert_key] = datetime.now()
        
        # Create alert in database
        alert_id = self.db.create_alert(severity, title, description, src_ip, dst_ip)
        
        # Send through channels
        if self.console_enabled:
            self._console_alert(severity, title, description, src_ip)
        
        if severity in ["high", "critical"]:
            if self.email_enabled:
                self._email_alert(severity, title, description, src_ip)
            if self.slack_enabled:
                self._slack_alert(severity, title, description, src_ip)
            if self.telegram_enabled:
                self._telegram_alert(severity, title, description, src_ip)
        
        return alert_id
    
    def _console_alert(self, severity: str, title: str, description: str, src_ip: str):
        """Send console alert"""
        color = SEVERITY_COLORS.get(severity, Fore.WHITE)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{color}{'='*60}{Style.RESET_ALL}")
        print(f"{color} ALERT - {severity.upper()}{Style.RESET_ALL}")
        print(f"{color} Time: {timestamp}{Style.RESET_ALL}")
        print(f"{color} Title: {title}{Style.RESET_ALL}")
        print(f"{color} Description: {description}{Style.RESET_ALL}")
        if src_ip:
            print(f"{color}🌐 Source IP: {src_ip}{Style.RESET_ALL}")
        print(f"{color}{'='*60}{Style.RESET_ALL}\n")
    
    def _email_alert(self, severity: str, title: str, description: str, src_ip: str):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = self.alert_email
            msg['Subject'] = f"[PyFireSOC] {severity.upper()} - {title}"
            
            body = f"""
            Security Alert - PyFireSOC
            
            Severity: {severity.upper()}
            Title: {title}
            Description: {description}
            Source IP: {src_ip}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Please investigate this security event.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent: {title}")
        except Exception as e:
            logging.error(f"Email alert failed: {e}")
    
    def _slack_alert(self, severity: str, title: str, description: str, src_ip: str):
        """Send Slack alert"""
        try:
            emoji = {
                "critical": ":rotating_light:",
                "high": ":fire:",
                "medium": ":warning:",
                "low": ":information_source:",
                "info": ":bell:"
            }.get(severity, ":bell:")
            
            message = f"""
            {emoji} *{severity.upper()} ALERT*
            *Title:* {title}
            *Description:* {description}
            *Source IP:* {src_ip}
            *Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            payload = {"text": message}
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            
            if response.status_code != 200:
                logging.error(f"Slack alert failed: {response.status_code}")
        except Exception as e:
            logging.error(f"Slack alert error: {e}")
    
    def _telegram_alert(self, severity: str, title: str, description: str, src_ip: str):
        """Send Telegram alert"""
        try:
            emoji = {
                "critical": "Critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info"
            }.get(severity, "info")
            
            message = f"""
            {emoji} *{severity.upper()} ALERT*
            
            *Title:* {title}
            *Description:* {description}
            *Source IP:* {src_ip}
            *Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            url = f"https://api.telegram.org/bot{self.telegram_bot}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code != 200:
                logging.error(f"Telegram alert failed: {response.status_code}")
        except Exception as e:
            logging.error(f"Telegram alert error: {e}")