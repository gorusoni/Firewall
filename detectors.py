import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

@dataclass
class DetectionResult:
    """Result of attack detection"""
    detected: bool
    category: str
    severity: str
    description: str
    payload: str

class AttackDetector:
    def __init__(self):
        self.scan_tracker = defaultdict(lambda: deque(maxlen=100))
        self.syn_tracker = defaultdict(lambda: deque(maxlen=100))
        self.bruteforce_tracker = defaultdict(lambda: deque(maxlen=100))
        self.ddos_tracker = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = {}
        
        # Compile regex patterns
        self._compile_patterns()
        
        # Load configuration
        from config import (
            PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
            SYN_FLOOD_THRESHOLD, BRUTE_FORCE_THRESHOLD,
            BRUTE_FORCE_WINDOW, DDOS_THRESHOLD, DDOS_WINDOW
        )
        
        self.PORT_SCAN_THRESHOLD = PORT_SCAN_THRESHOLD
        self.PORT_SCAN_WINDOW = PORT_SCAN_WINDOW
        self.SYN_FLOOD_THRESHOLD = SYN_FLOOD_THRESHOLD
        self.BRUTE_FORCE_THRESHOLD = BRUTE_FORCE_THRESHOLD
        self.BRUTE_FORCE_WINDOW = BRUTE_FORCE_WINDOW
        self.DDOS_THRESHOLD = DDOS_THRESHOLD
        self.DDOS_WINDOW = DDOS_WINDOW
    
    def _compile_patterns(self):
        """Compile attack detection patterns"""
        self.sql_patterns = [
            re.compile(r'(?i)\bUNION\b.*\bSELECT\b'),
            re.compile(r'(?i)\bOR\b.*=.*\bOR\b'),
            re.compile(r'(?i)\bDROP\b\s+\bTABLE\b'),
            re.compile(r'(?i)\bINSERT\b.*\bINTO\b'),
            re.compile(r'(?i)\bUPDATE\b.*\bSET\b'),
            re.compile(r'(?i)\bDELETE\b.*\bFROM\b'),
            re.compile(r'(?i)\bEXEC\b\s+\bXP_\w+'),
            re.compile(r'(?i)\bSLEEP\s*\('),
            re.compile(r'(?i)\bLOAD_FILE\s*\('),
            re.compile(r'(?i)\bINTO\s+OUTFILE\b'),
        ]
        
        self.xss_patterns = [
            re.compile(r'<\s*script\s*>', re.I),
            re.compile(r'<\s*img\s+.*\bonerror\s*=', re.I),
            re.compile(r'javascript\s*:', re.I),
            re.compile(r'<\s*iframe\s+.*\bsrc\s*=', re.I),
            re.compile(r'on\w+\s*=', re.I),
            re.compile(r'expression\s*\(', re.I),
            re.compile(r'vbscript\s*:', re.I),
            re.compile(r'<\s*svg\s+.*\bonload\s*=', re.I),
        ]
        
        self.command_patterns = [
            re.compile(r'(?i)\bcat\s+/etc/passwd'),
            re.compile(r'(?i)\bwhoami\s*;'),
            re.compile(r'(?i)\bwget\s+http'),
            re.compile(r'(?i)\bcurl\s+http'),
            re.compile(r'(?i)\bping\s+'),
            re.compile(r'(?i)\bnslookup\s+'),
            re.compile(r'(?i)\bnetstat\s+'),
            re.compile(r'(?i)\bifconfig\s+'),
        ]
        
        self.traversal_patterns = [
            re.compile(r'\.\./\.\./\.\./'),
            re.compile(r'\.\.\\\.\.\\\.\.\\'),
            re.compile(r'/etc/passwd'),
            re.compile(r'C:\\Windows\\System32'),
            re.compile(r'boot\.ini'),
        ]
    
    def detect_sql_injection(self, payload: str) -> DetectionResult:
        """Detect SQL Injection attacks"""
        for pattern in self.sql_patterns:
            if pattern.search(payload):
                return DetectionResult(
                    detected=True,
                    category="sql_injection",
                    severity="high",
                    description="SQL Injection detected",
                    payload=payload[:200]
                )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_xss(self, payload: str) -> DetectionResult:
        """Detect XSS attacks"""
        for pattern in self.xss_patterns:
            if pattern.search(payload):
                return DetectionResult(
                    detected=True,
                    category="xss",
                    severity="high",
                    description="Cross-Site Scripting detected",
                    payload=payload[:200]
                )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_command_injection(self, payload: str) -> DetectionResult:
        """Detect Command Injection attacks"""
        for pattern in self.command_patterns:
            if pattern.search(payload):
                return DetectionResult(
                    detected=True,
                    category="command_injection",
                    severity="critical",
                    description="Command Injection detected",
                    payload=payload[:200]
                )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_path_traversal(self, payload: str) -> DetectionResult:
        """Detect Path Traversal attacks"""
        for pattern in self.traversal_patterns:
            if pattern.search(payload):
                return DetectionResult(
                    detected=True,
                    category="path_traversal",
                    severity="medium",
                    description="Path Traversal detected",
                    payload=payload[:200]
                )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_port_scan(self, src_ip: str, dst_port: int) -> DetectionResult:
        """Detect Port Scan attempts"""
        now = time.time()
        self.scan_tracker[src_ip].append((now, dst_port))
        
        # Check for multiple ports in time window
        recent = [p for t, p in self.scan_tracker[src_ip] 
                 if now - t < self.PORT_SCAN_WINDOW]
        
        unique_ports = len(set(recent))
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            return DetectionResult(
                detected=True,
                category="port_scan",
                severity="medium",
                description=f"Port scan detected: {unique_ports} ports in {self.PORT_SCAN_WINDOW}s",
                payload=f"Ports: {set(recent)}"
            )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_syn_flood(self, src_ip: str) -> DetectionResult:
        """Detect SYN Flood attacks"""
        now = time.time()
        self.syn_tracker[src_ip].append(now)
        
        recent = [t for t in self.syn_tracker[src_ip] 
                 if now - t < 1.0]  # Last second
        
        if len(recent) > self.SYN_FLOOD_THRESHOLD:
            return DetectionResult(
                detected=True,
                category="syn_flood",
                severity="critical",
                description=f"SYN Flood detected: {len(recent)} SYN packets/sec",
                payload=f"Rate: {len(recent)} packets/sec"
            )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_bruteforce(self, src_ip: str) -> DetectionResult:
        """Detect Brute Force attempts"""
        now = time.time()
        self.bruteforce_tracker[src_ip].append(now)
        
        recent = [t for t in self.bruteforce_tracker[src_ip] 
                 if now - t < self.BRUTE_FORCE_WINDOW]
        
        if len(recent) >= self.BRUTE_FORCE_THRESHOLD:
            return DetectionResult(
                detected=True,
                category="brute_force",
                severity="high",
                description=f"Brute Force detected: {len(recent)} attempts in {self.BRUTE_FORCE_WINDOW}s",
                payload=f"Attempts: {len(recent)}"
            )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def detect_ddos(self, src_ip: str) -> DetectionResult:
        """Detect DDoS attacks"""
        now = time.time()
        self.ddos_tracker[src_ip].append(now)
        
        recent = [t for t in self.ddos_tracker[src_ip] 
                 if now - t < self.DDOS_WINDOW]
        
        if len(recent) >= self.DDOS_THRESHOLD:
            return DetectionResult(
                detected=True,
                category="ddos",
                severity="critical",
                description=f"DDoS detected: {len(recent)} packets in {self.DDOS_WINDOW}s",
                payload=f"Rate: {len(recent)/self.DDOS_WINDOW:.0f} packets/sec"
            )
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def inspect_payload(self, payload: str, src_ip: str, dst_port: int) -> List[DetectionResult]:
        """Inspect payload for all attack types"""
        results = []
        
        if not payload:
            return results
        
        # Web attacks (HTTP/S)
        if dst_port in [80, 443, 8080, 8443]:
            if result := self.detect_sql_injection(payload):
                results.append(result)
            if result := self.detect_xss(payload):
                results.append(result)
            if result := self.detect_command_injection(payload):
                results.append(result)
            if result := self.detect_path_traversal(payload):
                results.append(result)
        
        return results
    
    def track_packet(self, src_ip: str, dst_port: int, is_syn: bool = False) -> DetectionResult:
        """Track packet for behavioral detection"""
        # Check SYN flood
        if is_syn:
            if result := self.detect_syn_flood(src_ip):
                return result
        
        # Check port scan
        if result := self.detect_port_scan(src_ip, dst_port):
            return result
        
        # Check DDoS
        if result := self.detect_ddos(src_ip):
            return result
        
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def track_failure(self, src_ip: str) -> DetectionResult:
        """Track authentication failure"""
        if result := self.detect_bruteforce(src_ip):
            return result
        return DetectionResult(detected=False, category="", severity="", description="", payload="")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def block_ip(self, ip: str, duration: int = 300):
        """Block an IP address for specified duration"""
        self.blocked_ips[ip] = time.time() + duration