import time
import logging
import threading
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional
from config import LOG_FILE
from database import Database
from detectors import AttackDetector, DetectionResult
from alerts import AlertSystem

class Firewall:
    """Core Firewall Engine"""
    
    def __init__(self, db: Database, detector: AttackDetector, alert_system: AlertSystem):
        self.db = db
        self.detector = detector
        self.alerts = alert_system
        self.running = True  # Added for stop control
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'alerts_triggered': 0,
            'attacks_detected': defaultdict(int)
        }
        
        # Load configuration
        from config import WHITELIST, BLACKLIST, BLOCK_DURATION
        self.whitelist = set(WHITELIST)
        self.blacklist = set(BLACKLIST)
        self.block_duration = BLOCK_DURATION
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('firewall.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def stop(self):
        """Stop the firewall (graceful shutdown)"""
        self.running = False
        self.logger.info("Firewall stopping...")
    
    def process_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: str, is_syn: bool = False) -> bool:
        """Process a packet; return True if allowed, False if blocked"""
        if not self.running:
            return False
        
        self.stats['total_packets'] += 1
        
        # Check whitelist
        if src_ip in self.whitelist:
            return True
        
        # Check blacklist
        if src_ip in self.blacklist or self.detector.is_blocked(src_ip):
            self.stats['blocked_packets'] += 1
            self.logger.info(f"Blocked packet from blacklisted IP: {src_ip}")
            return False
        
        # Get IP reputation
        reputation = self.db.get_ip_reputation(src_ip)
        if reputation and reputation['score'] >= 70:
            self._block_ip(src_ip)
            self.stats['blocked_packets'] += 1
            return False
        
        # Inspect payload for attacks
        if payload and dst_port in [80, 443, 8080, 8443]:
            results = self.detector.inspect_payload(payload, src_ip, dst_port)
            for result in results:
                if result.detected:
                    self._handle_attack_detection(src_ip, dst_ip, dst_port, result)
                    return False
        
        # Behavioral detection (SYN flood, port scan)
        if is_syn:
            result = self.detector.track_packet(src_ip, dst_port, is_syn=True)
            if result.detected:
                self._handle_attack_detection(src_ip, dst_ip, dst_port, result)
                return False
        
        # Track packet for DDoS detection
        result = self.detector.track_packet(src_ip, dst_port)
        if result.detected and result.category == "ddos":
            self._handle_attack_detection(src_ip, dst_ip, dst_port, result)
            return False
        
        # Track failed auth attempts (on port 22, etc.)
        if dst_port in [22, 3389] and "failed" in payload.lower():
            result = self.detector.track_failure(src_ip)
            if result.detected:
                self._handle_attack_detection(src_ip, dst_ip, dst_port, result)
                return False
        
        # Update IP reputation (positive)
        self.db.update_ip_reputation(src_ip, score_change=-1)
        
        # Log the event
        self._log_event(src_ip, dst_ip, dst_port, protocol, payload, "permit", "")
        
        return True
    
    def _handle_attack_detection(self, src_ip: str, dst_ip: str, dst_port: int,
                                 result: DetectionResult):
        """Handle detected attack"""
        self.stats['blocked_packets'] += 1
        self.stats['attacks_detected'][result.category] += 1
        
        # Block the IP
        self._block_ip(src_ip)
        
        # Log the event with category
        self._log_event(src_ip, dst_ip, dst_port, "TCP", result.payload, "blocked", result.category)
        
        # Trigger alert
        alert_id = self.alerts.send_alert(
            severity=result.severity,
            title=f"{result.category.upper()} Attack",
            description=result.description,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
        
        self.stats['alerts_triggered'] += 1
        self.logger.warning(
            f"Attack detected: {result.category} from {src_ip} -> {dst_ip}:{dst_port}"
        )
    
    def _block_ip(self, ip: str):
        """Block an IP"""
        self.detector.block_ip(ip, self.block_duration)
        self.db.update_ip_reputation(ip, score_change=10, category="malicious")
        self.logger.info(f"Blocked IP: {ip}")
    
    def _log_event(self, src_ip: str, dst_ip: str, dst_port: int,
                   protocol: str, payload: str, action: str, category: str = ""):
        """Log a security event"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'attack' if action == 'blocked' else 'connection',
            'severity': 'high' if action == 'blocked' else 'info',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            'category': category,
            'description': f"Packet from {src_ip} to {dst_ip}:{dst_port} - {action}",
            'payload': payload[:500] if payload else '',
            'action_taken': action
        }
        self.db.log_event(event_data)
    
    def get_stats(self) -> Dict:
        """Get firewall statistics"""
        db_stats = self.db.get_stats()
        return {
            **self.stats,
            'db_stats': db_stats
        }