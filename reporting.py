#!/usr/bin/env python3
"""
PyFireSOC - Reporting Module
"""

import json
import csv
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from tabulate import tabulate

class ReportGenerator:
    """Generate security reports"""
    
    def __init__(self, db):
        self.db = db
    
    def generate_summary_report(self, days: int = 7) -> Dict:
        """Generate summary report for given days"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Total events
        cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp > ?", (since,))
        total_events = cursor.fetchone()[0]
        
        # Events by type
        cursor.execute("""
            SELECT event_type, COUNT(*) 
            FROM events 
            WHERE timestamp > ? 
            GROUP BY event_type
        """, (since,))
        events_by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM alerts 
            WHERE timestamp > ? 
            GROUP BY severity
        """, (since,))
        alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Top attackers
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count 
            FROM events 
            WHERE event_type = 'attack' AND timestamp > ?
            GROUP BY src_ip 
            ORDER BY count DESC 
            LIMIT 10
        """, (since,))
        top_attackers = [dict(row) for row in cursor.fetchall()]
        
        # Top attack types
        cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM events 
            WHERE category != '' AND timestamp > ?
            GROUP BY category 
            ORDER BY count DESC
        """, (since,))
        top_attacks = [dict(row) for row in cursor.fetchall()]
        
        return {
            'period_days': days,
            'total_events': total_events,
            'events_by_type': events_by_type,
            'alerts_by_severity': alerts_by_severity,
            'top_attackers': top_attackers,
            'top_attack_types': top_attacks,
            'generated_at': datetime.now().isoformat()
        }
    
    def generate_incident_report(self, limit: int = 100) -> List[Dict]:
        """Generate incident report"""
        return self.db.get_recent_events(limit)
    
    def export_to_csv(self, data: List[Dict], filename: str):
        """Export data to CSV"""
        if not data:
            return
        
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        print(f"[+] Report exported to {filepath}")
    
    def export_to_json(self, data: Dict, filename: str, ensure_ascii=False):
        """Export data to JSON"""
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
        
        print(f"[+] Report exported to {filepath}")
    
    def print_summary_report(self, report: Dict):
        """Print summary report to console"""
        print("\n" + "="*60)
        print("📊 SECURITY SUMMARY REPORT")
        print("="*60)
        print(f"📅 Period: Last {report['period_days']} days")
        print(f"📅 Generated: {report['generated_at']}")
        print("-"*60)
        print(f"📌 Total Events: {report['total_events']}")
        print("-"*60)
        
        print("\n📋 Events by Type:")
        events_table = [[k, v] for k, v in report['events_by_type'].items()]
        print(tabulate(events_table, headers=['Type', 'Count'], tablefmt='grid'))
        
        print("\n🔔 Alerts by Severity:")
        alerts_table = [[k, v] for k, v in report['alerts_by_severity'].items()]
        print(tabulate(alerts_table, headers=['Severity', 'Count'], tablefmt='grid'))
        
        print("\n🎯 Top Attackers:")
        if report['top_attackers']:
            attackers_table = [[a['src_ip'], a['count']] for a in report['top_attackers']]
            print(tabulate(attackers_table, headers=['IP', 'Attacks'], tablefmt='grid'))
        else:
            print("No attackers detected")
        
        print("\n⚔️ Top Attack Types:")
        if report['top_attack_types']:
            attacks_table = [[a['category'], a['count']] for a in report['top_attack_types']]
            print(tabulate(attacks_table, headers=['Type', 'Count'], tablefmt='grid'))
        else:
            print("No attacks detected")
        
        print("="*60)