import sqlite3
import os

DB_PATH = "data/ids_security.db"

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_flows (
            flow_id TEXT PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_count INTEGER,
            byte_count INTEGER,
            duration REAL,
            risk_score REAL,
            classification TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            flow_id TEXT,
            rule_id TEXT,
            severity TEXT,
            alert_type TEXT,
            description TEXT,
            risk_score REAL,
            status TEXT,
            created_at TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            FOREIGN KEY (flow_id) REFERENCES network_flows (flow_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            note TEXT,
            created_at TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
        )
    ''')

    conn.commit()
    conn.close()
    print("[+] SQLite database initialized successfully.")

if __name__ == "__main__":
    init_db()
