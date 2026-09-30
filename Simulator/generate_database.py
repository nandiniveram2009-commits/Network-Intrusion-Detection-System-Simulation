import os
import csv
import random
from datetime import datetime, timedelta

def generate_synthetic_dataset(num_records=5500, output_path="data/network_traffic.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    protocols = ["TCP", "UDP", "ICMP", "DNS"]
    scenarios = [
        ("NORMAL_WEB", "NORMAL"),
        ("NORMAL_DNS", "NORMAL"),
        ("NORMAL_SSH", "NORMAL"),
        ("NORMAL_EMAIL", "NORMAL"),
        ("NORMAL_DATABASE", "NORMAL"),
        ("HIGH_CONNECTION_RATE", "SUSPICIOUS"),
        ("REPEATED_FAILED_CONNECTIONS", "SUSPICIOUS"),
        ("MULTI_PORT_PROBING_PATTERN", "SUSPICIOUS"),
        ("SYN_HEAVY_PATTERN", "SUSPICIOUS"),
        ("UNUSUAL_PORT_ACTIVITY", "SUSPICIOUS"),
        ("HIGH_TRAFFIC_VOLUME", "SUSPICIOUS")
    ]
    
    source_ips = [f"192.0.2.{i}" for i in range(1, 50)]
    dest_ips = [f"198.51.100.{i}" for i in range(1, 20)]
    
    start_time = datetime.now() - timedelta(days=7)
    
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "flow_id", "timestamp", "source_ip", "destination_ip", 
            "source_port", "destination_port", "protocol", "packet_count", 
            "byte_count", "duration_seconds", "connection_count", 
            "failed_connection_count", "syn_count", "rst_count", 
            "average_packet_size", "label", "scenario_type"
        ])
        
        for i in range(1, num_records + 1):
            flow_id = f"FLOW-{10000 + i}"
            timestamp = (start_time + timedelta(seconds=random.randint(1, 604800))).isoformat()
            src_ip = random.choice(source_ips)
            dst_ip = random.choice(dest_ips)
            
            scenario, label = random.choice(scenarios)
            
            # Default normal characteristics
            src_port = random.randint(1024, 65535)
            connection_count = random.randint(1, 5)
            failed_conn = 0
            syn_count = random.randint(1, 3)
            rst_count = 0
            duration = round(random.uniform(0.1, 45.0), 2)
            
            if scenario == "NORMAL_WEB":
                dst_port = random.choice([80, 443])
                proto = "TCP"
                pkt_count = random.randint(5, 50)
                byte_count = pkt_count * random.randint(500, 1450)
            elif scenario == "NORMAL_DNS":
                dst_port = 53
                proto = "DNS"
                pkt_count = random.randint(1, 4)
                byte_count = pkt_count * random.randint(60, 512)
            elif scenario == "NORMAL_SSH":
                dst_port = 22
                proto = "TCP"
                pkt_count = random.randint(10, 100)
                byte_count = pkt_count * random.randint(100, 300)
            elif scenario == "NORMAL_EMAIL":
                dst_port = random.choice([25, 465, 587, 993])
                proto = "TCP"
                pkt_count = random.randint(8, 60)
                byte_count = pkt_count * random.randint(200, 1000)
            elif scenario == "NORMAL_DATABASE":
                dst_port = random.choice([1433, 3306, 5432])
                proto = "TCP"
                pkt_count = random.randint(20, 200)
                byte_count = pkt_count * random.randint(300, 1500)
                
            # Suspicious synthetic scenarios
            elif scenario == "HIGH_CONNECTION_RATE":
                dst_port = random.choice([80, 443, 8080])
                proto = "TCP"
                connection_count = random.randint(50, 200)
                pkt_count = random.randint(100, 500)
                byte_count = pkt_count * random.randint(40, 200)
                duration = round(random.uniform(0.5, 5.0), 2)
            elif scenario == "REPEATED_FAILED_CONNECTIONS":
                dst_port = random.choice([22, 3389, 445])
                proto = "TCP"
                failed_conn = random.randint(15, 60)
                connection_count = failed_conn + random.randint(0, 3)
                syn_count = connection_count
                rst_count = failed_conn
                pkt_count = failed_conn * 3
                byte_count = pkt_count * 64
            elif scenario == "MULTI_PORT_PROBING_PATTERN":
                dst_port = random.randint(1, 1024)
                proto = "TCP"
                connection_count = random.randint(30, 100)
                syn_count = connection_count
                pkt_count = connection_count * 2
                byte_count = pkt_count * 40
            elif scenario == "SYN_HEAVY_PATTERN":
                dst_port = random.choice([80, 443, 8080])
                proto = "TCP"
                syn_count = random.randint(80, 300)
                connection_count = syn_count
                rst_count = random.randint(0, 10)
                pkt_count = syn_count
                byte_count = pkt_count * 40
            elif scenario == "UNUSUAL_PORT_ACTIVITY":
                dst_port = random.randint(30000, 65535)
                proto = random.choice(["TCP", "UDP"])
                pkt_count = random.randint(200, 800)
                byte_count = pkt_count * random.randint(1000, 5000)
            elif scenario == "HIGH_TRAFFIC_VOLUME":
                dst_port = random.choice([80, 443])
                proto = "TCP"
                pkt_count = random.randint(5000, 25000)
                byte_count = pkt_count * random.randint(1000, 1500)
                duration = round(random.uniform(10.0, 60.0), 2)
            else:
                dst_port = 80
                proto = "TCP"
                pkt_count = 10
                byte_count = 1000

            avg_pkt_size = round(byte_count / max(1, pkt_count), 2)
            
            writer.writerow([
                flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, 
                proto, pkt_count, byte_count, duration, connection_count, 
                failed_conn, syn_count, rst_count, avg_pkt_size, label, scenario
            ])
            
    print(f"[+] Successfully generated {num_records} synthetic records at {output_path}")

if __name__ == "__main__":
    generate_synthetic_dataset()
