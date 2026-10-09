import json
import csv
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class SecurityOperationsCenter:
    def __init__(self, db, alert_system):
        self.db = db
        self.alerts = alert_system
        self.running = False
        self.report_thread = None

        from config import AUTO_GENERATE_REPORT, DAILY_REPORT_TIME, REPORT_DIR
        self.auto_report = AUTO_GENERATE_REPORT
        self.report_time = DAILY_REPORT_TIME
        self.report_dir = REPORT_DIR

    def start(self):
        """Start SOC monitoring"""
        self.running = True
        print("[+] Security Operations Center started")

        if self.auto_report:
            self._start_report_scheduler()

    def stop(self):
        """Stop SOC monitoring"""
        self.running = False
        print("[*] Security Operations Center stopped")

    def _start_report_scheduler(self):
        """Start automated report generation"""
        def scheduler():
            while self.running:
                # Check if it's time to generate report
                now = datetime.now()
                target_time = datetime.strptime(self.report_time, "%H:%M")
                target_now = now.replace(
                    hour=target_time.hour,
                    minute=target_time.minute,
                    second=0, microsecond=0
                )

                # If time passed, schedule for next day
                if target_now <= now:
                    target_now += timedelta(days=1)

                sleep_time = (target_now - now).total_seconds()
                # Wake up regularly so stop() is noticed, instead of sleeping
                # for up to 24 hours
                while self.running and sleep_time > 0:
                    time.sleep(min(30, sleep_time))
                    sleep_time -= 30

                if self.running:
                    self.generate_daily_report()

        self.report_thread = threading.Thread(target=scheduler, daemon=True)
        self.report_thread.start()

    def generate_daily_report(self) -> Dict:
        """Generate daily security report"""
        print("[+] Generating daily report...")

        # Get today's events
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # Query database for today's events
        conn = self.db.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM events
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        """, (today.isoformat(),))
        events = [dict(row) for row in cursor.fetchall()]

        # Get today's alerts
        cursor.execute("""
            SELECT * FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        """, (today.isoformat(),))
        alerts = [dict(row) for row in cursor.fetchall()]

        # Generate summary
        summary = {
            'date': today.isoformat(),
            'total_events': len(events),
            'total_alerts': len(alerts),
            'alerts_by_severity': {},
            'attacks_detected': {},
            'top_attackers': [],
            'blocked_ips': []
        }

        for alert in alerts:
            severity = alert['severity']
            summary['alerts_by_severity'][severity] = summary['alerts_by_severity'].get(severity, 0) + 1

        for event in events:
            if event['category']:
                summary['attacks_detected'][event['category']] = summary['attacks_detected'].get(event['category'], 0) + 1

        # Save report as JSON
        report_file = os.path.join(self.report_dir, f"report_{today.strftime('%Y%m%d')}.json")
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        # Save report as CSV
        csv_file = os.path.join(self.report_dir, f"report_{today.strftime('%Y%m%d')}.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Date', 'Metric', 'Value'])
            writer.writerow([summary['date'], 'Total Events', summary['total_events']])
            writer.writerow([summary['date'], 'Total Alerts', summary['total_alerts']])
            for severity, count in summary['alerts_by_severity'].items():
                writer.writerow([summary['date'], f'Alert: {severity}', count])
            for attack, count in summary['attacks_detected'].items():
                writer.writerow([summary['date'], f'Attack: {attack}', count])

        print(f"[+] Daily report saved: {report_file}")
        return summary

    def get_dashboard_data(self) -> Dict:
        """Get dashboard statistics"""
        stats = self.db.get_stats()

        return {
            'total_events': stats['total_events'],
            'events_24h': stats['events_24h'],
            'alerts_pending': len([a for a in self.db.get_alerts(resolved=False) if a]),
            'alerts_count': len(self.db.get_alerts()),
            'events_by_type': stats['events_by_type'],
            'alerts_by_severity': stats['alerts_by_severity'],
            'top_attackers': stats['top_attackers'],
            'timestamp': datetime.now().isoformat()
        }

    def get_incidents(self, limit: int = 50) -> List[Dict]:
        """Get recent incidents"""
        return self.db.get_recent_events(limit)

    def resolve_alert(self, alert_id: int, notes: str = ""):
        """Resolve an alert"""
        self.db.resolve_alert(alert_id, notes)
        print(f"[+] Alert {alert_id} resolved")

    def search_events(self, query: str) -> List[Dict]:
        """Search for events"""
        conn = self.db.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM events
            WHERE src_ip LIKE ? OR dst_ip LIKE ? OR description LIKE ?
            ORDER BY timestamp DESC
            LIMIT 100
        """, (f'%{query}%', f'%{query}%', f'%{query}%'))

        return [dict(row) for row in cursor.fetchall()]

    def get_ip_details(self, ip: str) -> Optional[Dict]:
        """Get details for an IP"""
        return self.db.get_ip_reputation(ip)

    def blacklist_ip(self, ip: str, reason: str = "Manual"):
        """Manually blacklist an IP"""
        self.db.update_ip_reputation(ip, score_change=50, category="malicious")
        self.alerts.send_alert(
            severity="high",
            title="IP Manually Blacklisted",
            description=f"IP {ip} manually blacklisted. Reason: {reason}",
            src_ip=ip
        )
        print(f"[+] IP {ip} blacklisted")
