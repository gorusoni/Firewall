import sys
import time
import signal
import argparse
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
from config import INTERFACE, LOG_FILE
from database import Database
from detectors import AttackDetector
from alerts import AlertSystem
from firewall import Firewall
from soc import SecurityOperationsCenter
from reporting import ReportGenerator

# Global reference for firewall instance
firewall_instance = None

def signal_handler(sig, frame):
    print("\n[*] Stopping PyFireSOC...")
    if firewall_instance:
        try:
            firewall_instance.stop()
        except Exception as e:
            print(f"[!] Error stopping firewall: {e}")
    sys.exit(0)

def print_banner():
    banner = """
         PyFireSOC - Firewall & SOC Platform    
                Author : Gourav Soni                    
   
    """
    print(banner)
    print(f"[*] Started At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Interface  : {INTERFACE}")
    print(f"[*] Log File   : {LOG_FILE}")
    print()

def packet_callback(packet):
    global firewall_instance
    if firewall_instance is None:
        return

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    dst_port = 0
    protocol = "IP"
    payload = ""
    is_syn = False

    if TCP in packet:
        protocol = "TCP"
        dst_port = packet[TCP].dport
        if packet[TCP].flags == "S":
            is_syn = True
    elif UDP in packet:
        protocol = "UDP"
        dst_port = packet[UDP].dport

    if Raw in packet:
        try:
            payload = bytes(packet[Raw]).decode("utf-8", errors="ignore")
        except:
            payload = ""

    firewall_instance.process_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        payload=payload,
        is_syn=is_syn
    )

def start_sniffer():
    print("[+] Packet sniffer started")
    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False
    )

def main():
    global firewall_instance

    parser = argparse.ArgumentParser(description="PyFireSOC")
    parser.add_argument("--no-firewall", action="store_true", help="Run SOC only")
    parser.add_argument("--generate-report", action="store_true", help="Generate report and exit")
    parser.add_argument("--report-days", type=int, default=7)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print_banner()
    print("[*] Initializing components...")

    db = Database("firewall.db")
    detector = AttackDetector()
    alerts = AlertSystem(db)
    soc = SecurityOperationsCenter(db, alerts)
    firewall_instance = Firewall(db, detector, alerts)
    reporter = ReportGenerator(db)

    if args.generate_report:
        report = reporter.generate_summary_report(args.report_days)
        reporter.print_summary_report(report)
        reporter.export_to_json(report, f"summary_report_{datetime.now().strftime('%Y%m%d')}.json")
        db.close()
        return

    soc.start()
    print("[+] Firewall Ready")
    print("[+] Press CTRL+C to stop\n")

    if args.no_firewall:
        print("[!] Running in SOC Only Mode\n")
    else:
        sniff_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniff_thread.start()

    try:
        while True:
            time.sleep(2)
            stats = firewall_instance.get_stats()
            print(
                f"\r📊 Packets: {stats['total_packets']} | "
                f"Blocked: {stats['blocked_packets']} | "
                f"Alerts: {stats['alerts_triggered']}",
                end=""
            )
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Shutting down...")
        soc.stop()
        db.close()
        print("[+] Goodbye")

if __name__ == "__main__":
    main()