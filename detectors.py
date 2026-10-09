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

    def __bool__(self) -> bool:
        """A result is truthy only when something was actually detected.

        Without this, `if result := detect_x(...)` is always true because a
        dataclass instance is truthy by default.
        """
        return self.detected


def no_detection() -> DetectionResult:
    """A negative detection result"""
    return DetectionResult(detected=False, category="", severity="",
                           description="", payload="")


# Ordering used to report the most serious detection when several fire at once
SEVERITY_RANK = {"": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

class AttackDetector:
    # A deque that is too short silently caps the counters and hides floods,
    # so keep enough room for a burst well above any threshold.
    TRACKER_MAXLEN = 5000

    # Drop per-IP state that has not been touched for this long, otherwise the
    # trackers keep one entry per source IP seen since start-up.
    IDLE_EVICT_SECONDS = 600

    def __init__(self):
        self.scan_tracker = defaultdict(lambda: deque(maxlen=self.TRACKER_MAXLEN))
        self.syn_tracker = defaultdict(lambda: deque(maxlen=self.TRACKER_MAXLEN))
        self.bruteforce_tracker = defaultdict(lambda: deque(maxlen=self.TRACKER_MAXLEN))
        self.ddos_tracker = defaultdict(lambda: deque(maxlen=self.TRACKER_MAXLEN))
        self.blocked_ips = {}
        self._last_evict = time.time()
        
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
        # Keyword-only patterns (e.g. a bare `INSERT ... INTO`) match ordinary
        # API traffic and documentation, so each write statement here has to be
        # preceded by a quote break-out, a comment marker or statement stacking.
        self.sql_patterns = [
            re.compile(r'(?i)\bUNION\b[\s\S]*?\bSELECT\b'),
            # Classic tautology: ' OR '1'='1  /  " OR 1=1
            re.compile(r'''(?i)['"]\s*(?:OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+'''),
            re.compile(r'(?i)(?:;|--|/\*|\')\s*DROP\s+TABLE\b'),
            re.compile(r'(?i)(?:;|--|/\*|\')\s*TRUNCATE\s+TABLE\b'),
            re.compile(r'(?i)(?:;|--|/\*|\')\s*INSERT\s+INTO\b'),
            re.compile(r'(?i)(?:;|--|/\*|\')\s*UPDATE\s+\S+\s+SET\b'),
            re.compile(r'(?i)(?:;|--|/\*|\')\s*DELETE\s+FROM\b'),
            re.compile(r'(?i)\bEXEC\b\s+\bXP_\w+'),
            re.compile(r'(?i)\bSLEEP\s*\('),
            re.compile(r'(?i)\bLOAD_FILE\s*\('),
            re.compile(r'(?i)\bINTO\s+OUTFILE\b'),
        ]
        
        self.xss_patterns = [
            re.compile(r'<\s*script[\s>]', re.I),
            re.compile(r'<\s*img\s+.*\bonerror\s*=', re.I),
            re.compile(r'javascript\s*:', re.I),
            re.compile(r'<\s*iframe\s+.*\bsrc\s*=', re.I),
            # Event handlers have to sit inside a tag - a bare `on\w+=` also
            # matches ordinary query params such as ?version= or ?reason=
            re.compile(r'<[^>]+\son(?:error|load|click|mouseover|focus|submit|toggle)\s*=', re.I),
            re.compile(r'expression\s*\(', re.I),
            re.compile(r'vbscript\s*:', re.I),
            re.compile(r'<\s*svg\s+.*\bonload\s*=', re.I),
        ]
        
        # A command name on its own ("ping ", "netstat ") shows up in normal
        # traffic and prose, so require a shell metacharacter in front of it.
        shell_sep = r'(?:[;|&`]|\$\()\s*'
        self.command_patterns = [
            re.compile(r'(?i)\bcat\s+/etc/passwd'),
            re.compile(r'(?i)' + shell_sep + r'(?:whoami|id|uname)\b'),
            re.compile(r'(?i)\b(?:wget|curl)\s+(?:-\S+\s+)*https?://'),
            re.compile(r'(?i)' + shell_sep + r'(?:ping|nslookup|netstat|ifconfig|ipconfig)\s'),
            re.compile(r'(?i)' + shell_sep + r'(?:nc|bash|sh|powershell|cmd)\s'),
        ]
        
        self.traversal_patterns = [
            re.compile(r'(?:\.\./){2,}'),
            re.compile(r'(?:\.\.\\){2,}'),
            # URL-encoded traversal
            re.compile(r'(?i)(?:%2e%2e(?:%2f|%5c)){2,}'),
            re.compile(r'/etc/passwd'),
            re.compile(r'(?i)C:\\Windows\\System32'),
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
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
        return no_detection()
    
    def inspect_payload(self, payload: str, src_ip: str, dst_port: int) -> List[DetectionResult]:
        """Inspect a cleartext payload for all attack types.

        The caller is responsible for only passing cleartext; running these
        signatures over TLS bytes just produces noise.
        """
        results = []
        
        if not payload:
            return results
        
        for detect in (self.detect_sql_injection, self.detect_xss,
                       self.detect_command_injection, self.detect_path_traversal):
            if result := detect(payload):
                results.append(result)
        
        return results
    
    def track_packet(self, src_ip: str, dst_port: int, is_syn: bool = False) -> DetectionResult:
        """Track packet for behavioral detection.

        Every detector runs and updates its own counters; returning at the first
        one would starve the later ones. The most severe detection is reported.
        """
        self._evict_idle_trackers()
        
        detections = []
        
        # Check SYN flood
        if is_syn:
            if result := self.detect_syn_flood(src_ip):
                detections.append(result)
        
        # Check port scan
        if result := self.detect_port_scan(src_ip, dst_port):
            detections.append(result)
        
        # Check DDoS
        if result := self.detect_ddos(src_ip):
            detections.append(result)
        
        if not detections:
            return no_detection()
        
        return max(detections, key=lambda r: SEVERITY_RANK.get(r.severity, 0))
    
    def track_failure(self, src_ip: str) -> DetectionResult:
        """Track authentication failure"""
        if result := self.detect_bruteforce(src_ip):
            return result
        return no_detection()
    
    def _evict_idle_trackers(self):
        """Drop per-IP state for IPs that have gone quiet"""
        now = time.time()
        if now - self._last_evict < self.IDLE_EVICT_SECONDS:
            return
        self._last_evict = now
        
        cutoff = now - self.IDLE_EVICT_SECONDS
        # scan_tracker stores (timestamp, port); the others store bare timestamps
        for tracker, last_seen in (
            (self.scan_tracker, lambda entry: entry[0]),
            (self.syn_tracker, lambda entry: entry),
            (self.bruteforce_tracker, lambda entry: entry),
            (self.ddos_tracker, lambda entry: entry),
        ):
            for ip in [ip for ip, entries in tracker.items()
                       if not entries or last_seen(entries[-1]) < cutoff]:
                del tracker[ip]
        
        for ip in [ip for ip, until in self.blocked_ips.items() if until < now]:
            del self.blocked_ips[ip]
    
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