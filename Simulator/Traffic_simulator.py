import time
import random
import json
import argparse
import requests

def generate_flow_record(mode="normal"):
    source_ips = [f"192.0.2.{i}" for i in range(10, 40)]
    destination_ips = [f"198.51.100.{i}" for i in range(1, 10)]
    
    if mode == "mixed" and random.random() < 0.35:
        # Suspicious pattern generation
        scenario = random.choice([
            "HIGH_CONNECTION_RATE",
            "REPEATED_FAILED_CONNECTIONS",
            "MULTI_PORT_PROBING",
            "SYN_HEAVY"
        ])
        
        if scenario == "HIGH_CONNECTION_RATE":
            flow = {
                "source_ip": random.choice(source_ips),
                "destination_ip": random.choice(destination_ips),
                "source_port": random.randint(49152, 65535),
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": random.randint(150, 400),
                "byte_count": random.randint(15000, 50000),
                "duration_seconds": round(random.uniform(0.5, 3.0), 2),
                "connection_count": random.randint(60, 150),
                "failed_connection_count": random.randint(0, 5),
                "syn_count": random.randint(60, 150),
                "rst_count": 0
            }
        elif scenario == "REPEATED_FAILED_CONNECTIONS":
            failed = random.randint(15, 50)
            flow = {
                "source_ip": random.choice(source_ips),
                "destination_ip": random.choice(destination_ips),
                "source_port": random.randint(49152, 65535),
                "destination_port": 22,
                "protocol": "TCP",
                "packet_count": failed * 3,
                "byte_count": failed * 120,
                "duration_seconds": round(random.uniform(1.0, 10.0), 2),
                "connection_count": failed,
                "failed_connection_count": failed,
                "syn_count": failed,
                "rst_count": failed
            }
        elif scenario == "MULTI_PORT_PROBING":
            flow = {
                "source_ip": random.choice(source_ips),
                "destination_ip": random.choice(destination_ips),
                "source_port": random.randint(49152, 65535),
                "destination_port": random.randint(1, 1024),
                "protocol": "TCP",
                "packet_count": random.randint(50, 120),
                "byte_count": random.randint(2000, 8000),
                "duration_seconds": round(random.uniform(0.2, 2.0), 2),
                "connection_count": random.randint(40, 90),
                "failed_connection_count": random.randint(10, 40),
                "syn_count": random.randint(40, 90),
                "rst_count": random.randint(10, 40)
            }
        else: # SYN_HEAVY
            syns = random.randint(100, 300)
            flow = {
                "source_ip": random.choice(source_ips),
                "destination_ip": random.choice(destination_ips),
                "source_port": random.randint(49152, 65535),
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": syns,
                "byte_count": syns * 40,
                "duration_seconds": round(random.uniform(0.1, 1.5), 2),
                "connection_count": syns,
                "failed_connection_count": 0,
                "syn_count": syns,
                "rst_count": 2
            }
    else:
        # Normal Traffic
        dst_port = random.choice([80, 443, 53, 22, 3306])
        proto = "DNS" if dst_port == 53 else "TCP"
        pkt_count = random.randint(2, 40)
        flow = {
            "source_ip": random.choice(source_ips),
            "destination_ip": random.choice(destination_ips),
            "source_port": random.randint(49152, 65535),
            "destination_port": dst_port,
            "protocol": proto,
            "packet_count": pkt_count,
            "byte_count": pkt_count * random.randint(200, 1200),
            "duration_seconds": round(random.uniform(0.1, 15.0), 2),
            "connection_count": random.randint(1, 4),
            "failed_connection_count": 0,
            "syn_count": random.randint(1, 2),
            "rst_count": 0
        }
    return flow

def run_simulator(mode="mixed", speed="slow", api_endpoint="http://localhost:5000/api/flows"):
    delay = 1.5 if speed == "slow" else 0.3
    print(f"[*] Starting Traffic Simulator | Mode: {mode} | Speed: {speed}")
    while True:
        flow = generate_flow_record(mode=mode)
        try:
            response = requests.post(api_endpoint, json=flow, timeout=2)
            print(f"[Sim] Sent Flow -> Src: {flow['source_ip']} Dst: {flow['destination_ip']}:{flow['destination_port']} | Status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("[Sim Warning] Backend API offline. Retrying in 3s...")
        except Exception as e:
            print(f"[Sim Error] {e}")
        time.sleep(delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="mixed", choices=["normal", "mixed"])
    parser.add_argument("--speed", default="slow", choices=["slow", "fast"])
    parser.add_argument("--endpoint", default="http://localhost:5000/api/flows")
    args = parser.parse_args()
    run_simulator(mode=args.mode, speed=args.speed, api_endpoint=args.endpoint)
