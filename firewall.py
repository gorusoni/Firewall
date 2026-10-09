import time
import logging
import threading
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional
from config import LOG_FILE, LOG_LEVEL
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
        # The sniffer thread writes these while the main thread reads them
        self.lock = threading.Lock()
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'alerts_triggered': 0,
            'attacks_detected': defaultdict(int)
        }
        
        # Load configuration
        from config import (WHITELIST, BLACKLIST, BLOCK_DURATION,
                            CLEARTEXT_HTTP_PORTS, AUTH_PORTS,
                            REPUTATION_BLOCK_SCORE, LOG_PERMITTED_EVENTS,
                            EVENT_FLUSH_SIZE, EVENT_FLUSH_SECONDS)
        self.whitelist = set(WHITELIST)
        self.blacklist = set(BLACKLIST)
        self.block_duration = BLOCK_DURATION
        self.cleartext_http_ports = set(CLEARTEXT_HTTP_PORTS)
        self.auth_ports = set(AUTH_PORTS)
        self.reputation_block_score = REPUTATION_BLOCK_SCORE
        self.log_permitted = LOG_PERMITTED_EVENTS
        self.flush_size = EVENT_FLUSH_SIZE
        self.flush_seconds = EVENT_FLUSH_SECONDS
        
        # Permitted traffic is buffered and written in batches; a commit per
        # packet cannot keep up with a live capture.
        self._event_buffer = []
        self._seen_ips = set()
        self._last_flush = time.time()
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, LOG_LEVEL, logging.INFO),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def stop(self):
        """Stop the firewall (graceful shutdown)"""
        self.running = False
        self._flush_buffer()
        self.logger.info("Firewall stopping...")
    
    def process_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: str, is_syn: bool = False) -> bool:
        """Process a packet; return True if allowed, False if blocked"""
        if not self.running:
            return False
        
        with self.lock:
            self.stats['total_packets'] += 1
        
        # Check whitelist
        if src_ip in self.whitelist:
            return True
        
        # Check blacklist
        if src_ip in self.blacklist or self.detector.is_blocked(src_ip):
            with self.lock:
                self.stats['blocked_packets'] += 1
            self.logger.info(f"Blocked packet from blacklisted IP: {src_ip}")
            return False
        
        # Get IP reputation
        reputation = self.db.get_ip_reputation(src_ip)
        if reputation and reputation['score'] >= self.reputation_block_score:
            self._block_ip(src_ip)
            with self.lock:
                self.stats['blocked_packets'] += 1
            return False
        
        # Inspect payload for attacks. Only cleartext ports: these signatures
        # over a TLS record just match random ciphertext bytes.
        if payload and dst_port in self.cleartext_http_ports:
            for result in self.detector.inspect_payload(payload, src_ip, dst_port):
                if result:
                    self._handle_attack_detection(src_ip, dst_ip, dst_port, result, protocol)
                    return False
        
        # Behavioural detection (SYN flood, port scan, DDoS) - one call per
        # packet, so a SYN is not counted twice.
        result = self.detector.track_packet(src_ip, dst_port, is_syn=is_syn)
        if result:
            self._handle_attack_detection(src_ip, dst_ip, dst_port, result, protocol)
            return False
        
        # Repeated connection attempts against an auth service. SSH and RDP are
        # encrypted, so there is no cleartext "failed" string to look for - the
        # signal is the rate of new connections.
        if is_syn and dst_port in self.auth_ports:
            result = self.detector.track_failure(src_ip)
            if result:
                self._handle_attack_detection(src_ip, dst_ip, dst_port, result, protocol)
                return False
        
        # Buffer the permitted packet; reputation decay and the event row are
        # applied in batches by _flush_buffer().
        self._buffer_permit(src_ip, dst_ip, dst_port, protocol, payload)
        
        return True
    
    def _buffer_permit(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: str):
        """Record permitted traffic for the next batch write"""
        with self.lock:
            self._seen_ips.add(src_ip)
            if self.log_permitted:
                self._event_buffer.append(self._build_event(
                    src_ip, dst_ip, dst_port, protocol, payload, "permit", ""
                ))
            
            due = (len(self._event_buffer) >= self.flush_size
                   or len(self._seen_ips) >= self.flush_size
                   or time.time() - self._last_flush >= self.flush_seconds)
        
        if due:
            self._flush_buffer()
    
    def _flush_buffer(self):
        """Write buffered events and reputation decay in one go"""
        with self.lock:
            events, ips = self._event_buffer, self._seen_ips
            self._event_buffer, self._seen_ips = [], set()
            self._last_flush = time.time()
        
        try:
            if events:
                self.db.log_events_batch(events)
            if ips:
                self.db.decay_reputation(ips)
        except Exception as e:
            self.logger.error(f"Failed to flush events: {e}")
    
    def _handle_attack_detection(self, src_ip: str, dst_ip: str, dst_port: int,
                                 result: DetectionResult, protocol: str = "TCP"):
        """Handle detected attack"""
        with self.lock:
            self.stats['blocked_packets'] += 1
            self.stats['attacks_detected'][result.category] += 1
        
        # Block the IP
        self._block_ip(src_ip)
        
        # Log the event with category
        self._log_event(src_ip, dst_ip, dst_port, protocol, result.payload, "blocked", result.category)
        
        # Trigger alert
        alert_id = self.alerts.send_alert(
            severity=result.severity,
            title=f"{result.category.upper()} Attack",
            description=result.description,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
        
        with self.lock:
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
        """Log a security event immediately"""
        self.db.log_event(self._build_event(
            src_ip, dst_ip, dst_port, protocol, payload, action, category
        ))
    
    def _build_event(self, src_ip: str, dst_ip: str, dst_port: int,
                     protocol: str, payload: str, action: str,
                     category: str = "") -> Dict:
        """Build an event row"""
        return {
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
    
    def get_stats(self) -> Dict:
        """Get firewall statistics"""
        db_stats = self.db.get_stats()
        with self.lock:
            snapshot = {
                'total_packets': self.stats['total_packets'],
                'blocked_packets': self.stats['blocked_packets'],
                'alerts_triggered': self.stats['alerts_triggered'],
                'attacks_detected': dict(self.stats['attacks_detected'])
            }
        return {
            **snapshot,
            'db_stats': db_stats
        }