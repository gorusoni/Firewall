#!/usr/bin/env python3
"""
PyFireSOC - Database Module
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection = None
        # One connection is shared by the sniffer thread, the report scheduler
        # and the main thread, so every statement has to hold this lock.
        self.lock = threading.RLock()
        self.init_database()

    def get_connection(self):
        """Get database connection"""
        with self.lock:
            if self.connection is None:
                self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
                self.connection.row_factory = sqlite3.Row
                # WAL keeps readers from blocking the writer
                self.connection.execute("PRAGMA journal_mode=WAL")
            return self.connection

    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                category TEXT,
                description TEXT,
                payload TEXT,
                action_taken TEXT
            )
        ''')

        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                resolved INTEGER DEFAULT 0,
                resolution_notes TEXT
            )
        ''')

        # IP Reputation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                score INTEGER DEFAULT 0,
                category TEXT DEFAULT 'unknown',
                first_seen TEXT,
                last_seen TEXT,
                total_events INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
        ''')

        # Traffic Stats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                packets INTEGER,
                bytes_sent INTEGER
            )
        ''')

        # Every reporting query filters on these columns; without indexes they
        # are full table scans that grow with the capture.
        for stmt in (
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_category ON events(category)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved)",
        ):
            cursor.execute(stmt)

        conn.commit()
        print("[+] Database initialized successfully")

    def log_event(self, data: Dict[str, Any]) -> int:
        """Log a security event"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO events (
                    timestamp, event_type, severity, src_ip, dst_ip,
                    dst_port, protocol, category, description, payload, action_taken
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now().isoformat()),
                data.get('event_type', 'unknown'),
                data.get('severity', 'info'),
                data.get('src_ip', ''),
                data.get('dst_ip', ''),
                data.get('dst_port', 0),
                data.get('protocol', ''),
                data.get('category', ''),
                data.get('description', ''),
                data.get('payload', '')[:1000],
                data.get('action_taken', 'log')
            ))

            event_id = cursor.lastrowid
            conn.commit()
            return event_id

    def log_events_batch(self, events: List[Dict[str, Any]]) -> int:
        """Insert many events in one transaction.

        One INSERT + commit per packet cannot keep up with a live capture, so
        the firewall buffers permitted traffic and flushes it through here.
        """
        if not events:
            return 0

        with self.lock:
            conn = self.get_connection()
            rows = [(
                e.get('timestamp', datetime.now().isoformat()),
                e.get('event_type', 'unknown'),
                e.get('severity', 'info'),
                e.get('src_ip', ''),
                e.get('dst_ip', ''),
                e.get('dst_port', 0),
                e.get('protocol', ''),
                e.get('category', ''),
                e.get('description', ''),
                (e.get('payload') or '')[:1000],
                e.get('action_taken', 'log')
            ) for e in events]

            conn.executemany("""
                INSERT INTO events (
                    timestamp, event_type, severity, src_ip, dst_ip,
                    dst_port, protocol, category, description, payload, action_taken
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            return len(rows)

    def decay_reputation(self, ips) -> None:
        """Nudge a batch of quiet IPs back towards a clean score"""
        if not ips:
            return

        with self.lock:
            conn = self.get_connection()
            conn.executemany(
                "UPDATE ip_reputation SET score = MAX(0, score - 1) WHERE ip = ?",
                [(ip,) for ip in ips]
            )
            conn.commit()

    def create_alert(self, severity: str, title: str, description: str,
                     src_ip: str = "", dst_ip: str = "") -> int:
        """Create a security alert"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO alerts (timestamp, severity, title, description, src_ip, dst_ip)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                severity,
                title,
                description,
                src_ip,
                dst_ip
            ))

            alert_id = cursor.lastrowid
            conn.commit()
            return alert_id

    def update_ip_reputation(self, ip: str, score_change: int = 0,
                            category: str = None):
        """Update IP reputation score"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Check if IP exists
            cursor.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
            result = cursor.fetchone()

            now = datetime.now().isoformat()

            if result:
                new_score = max(0, min(100, result['score'] + score_change))
                new_total = result['total_events'] + 1
                new_alerts = result['alert_count'] + (1 if score_change > 0 else 0)

                cursor.execute('''
                    UPDATE ip_reputation
                    SET score = ?, category = ?, last_seen = ?,
                        total_events = ?, alert_count = ?
                    WHERE ip = ?
                ''', (new_score, category or result['category'], now,
                      new_total, new_alerts, ip))
            else:
                # Apply score_change on the first sighting too - hardcoding 0 here
                # meant an IP's first detected attack never cost it anything.
                new_score = max(0, min(100, score_change))
                cursor.execute('''
                    INSERT INTO ip_reputation (ip, score, category, first_seen, last_seen,
                                               total_events, alert_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip, new_score, category or 'unknown', now, now, 1,
                      1 if score_change > 0 else 0))

            conn.commit()

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Get IP reputation"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
            result = cursor.fetchone()

            return dict(result) if result else None

    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent events"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_alerts(self, resolved: Optional[bool] = None) -> List[Dict]:
        """Get alerts"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM alerts"
            params = []

            if resolved is not None:
                query += " WHERE resolved = ?"
                params.append(1 if resolved else 0)

            query += " ORDER BY timestamp DESC"

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def resolve_alert(self, alert_id: int, notes: str = ""):
        """Resolve an alert"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE alerts SET resolved = 1, resolution_notes = ?
                WHERE id = ?
            ''', (notes, alert_id))

            conn.commit()

    def get_stats(self) -> Dict:
        """Get statistics summary"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Total events
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            # Events by type
            cursor.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
            events_by_type = {row[0]: row[1] for row in cursor.fetchall()}

            # Alerts by severity
            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            # Top attack sources
            cursor.execute('''
                SELECT src_ip, COUNT(*) as count
                FROM events
                WHERE event_type = 'attack'
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 5
            ''')
            top_attackers = [dict(row) for row in cursor.fetchall()]

            # Last 24 hours events
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp > ?",
                (yesterday,)
            )
            events_24h = cursor.fetchone()[0]

            return {
                'total_events': total_events,
                'events_24h': events_24h,
                'events_by_type': events_by_type,
                'alerts_by_severity': alerts_by_severity,
                'top_attackers': top_attackers
            }

    def close(self):
        """Close database connection"""
        with self.lock:
            if self.connection:
                self.connection.close()
                self.connection = None
