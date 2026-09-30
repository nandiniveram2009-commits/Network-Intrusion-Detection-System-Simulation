from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import joblib
from datetime import datetime

from models.database import init_db, get_db_connection
from ids.feature_extractor import extract_network_features
from ids.rule_engine import SignatureRuleEngine
from ids.anomaly_detector import StatisticalAnomalyDetector
from ids.risk_engine import HybridRiskEngine
from ids.alert_engine import AlertEngine

app = Flask(__name__)
CORS(app)

init_db()

rule_engine = SignatureRuleEngine()
anomaly_detector = StatisticalAnomalyDetector()

# Optional ML loading
model_path = "models/random_forest_ids.pkl"
ml_model = None
if os.path.exists(model_path):
    try:
        ml_model = joblib.load(model_path)
        print("[+] Loaded trained ML model successfully.")
    except Exception as e:
        print(f"[!] Could not load ML model: {e}")

risk_engine = HybridRiskEngine(use_ml=(ml_model is not None))
alert_engine = AlertEngine()

@app.route("/api/flows", methods=["POST"])
def ingest_flow():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    try:
        features = extract_network_features(data)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 422

    # 1. Rule Analysis
    triggered_rules = rule_engine.evaluate_rules(data, features)

    # 2. Anomaly Detection
    anomaly_score = anomaly_detector.calculate_anomaly_score(features)

    # 3. Optional ML Prediction
    ml_prob = 0.0
    if ml_model is not None:
        feat_vector = [[
            features["packet_count"], features["byte_count"], features["duration"],
            features["bytes_per_second"], features["packets_per_second"], features["average_packet_size"],
            features["connection_count"], features["failed_connection_count"], features["failure_ratio"],
            features["syn_count"], features["rst_count"], features["syn_ratio"], features["connection_rate"]
        ]]
        ml_prob = float(ml_model.predict_proba(feat_vector)[0][1])

    # 4. Risk Scoring
    risk_score, classification = risk_engine.calculate_risk_score(triggered_rules, anomaly_score, ml_prob)

    flow_id = f"FLOW-{int(datetime.now().timestamp() * 1000)}"
    timestamp = datetime.now().isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO network_flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        flow_id, timestamp, data["source_ip"], data["destination_ip"],
        data.get("source_port", 0), data.get("destination_port", 0),
        data.get("protocol", "TCP"), features["packet_count"], features["byte_count"],
        features["duration"], risk_score, classification
    ))

    # 5. Alert Generation
    alert = None
    if classification != "NORMAL":
        alert = alert_engine.generate_alert(data, triggered_rules, risk_score, classification)
        if alert:
            cursor.execute('''
                INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert["alert_id"], flow_id, alert["rule_id"], alert["severity"],
                alert["alert_type"], alert["description"], alert["risk_score"],
                alert["status"], alert["timestamp"], alert["source_ip"],
                alert["destination_ip"], alert["protocol"]
            ))

    conn.commit()
    conn.close()

    return jsonify({
        "flow_id": flow_id,
        "classification": classification,
        "risk_score": risk_score,
        "anomaly_score": anomaly_score,
        "triggered_rules": triggered_rules,
        "alert": alert
    }), 201

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    total_flows = cursor.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0]
    normal_flows = cursor.execute("SELECT COUNT(*) FROM network_flows WHERE classification='NORMAL'").fetchone()[0]
    suspicious_flows = cursor.execute("SELECT COUNT(*) FROM network_flows WHERE classification!='NORMAL'").fetchone()[0]
    open_alerts = cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='NEW'").fetchone()[0]
    critical_alerts = cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    avg_risk = cursor.execute("SELECT AVG(risk_score) FROM network_flows").fetchone()[0] or 0.0

    conn.close()

    return jsonify({
        "total_flows": total_flows,
        "normal_flows": normal_flows,
        "suspicious_flows": suspicious_flows,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "average_risk_score": round(avg_risk, 2)
    })

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    conn = get_db_connection()
    cursor = conn.cursor()
    alerts = cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(row) for row in alerts])

@app.route("/api/alerts/<alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    data = request.get_json()
    new_status = data.get("status")
    if new_status not in ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]:
        return jsonify({"error": "Invalid status value"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "alert_id": alert_id, "status": new_status})

@app.route("/api/alerts/<alert_id>/notes", methods=["POST"])
def add_alert_note(alert_id):
    data = request.get_json()
    note = data.get("note")
    if not note:
        return jsonify({"error": "Note text is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO incident_notes (alert_id, note, created_at) VALUES (?, ?, ?)",
                   (alert_id, note, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "alert_id": alert_id, "note": note})

@app.route("/api/alerts/<alert_id>", methods=["GET"])
def get_alert_detail(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    alert = cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        return jsonify({"error": "Alert not found"}), 404
        
    notes = cursor.execute("SELECT * FROM incident_notes WHERE alert_id = ? ORDER BY created_at DESC", (alert_id,)).fetchall()
    conn.close()
    
    resp = dict(alert)
    resp["notes"] = [dict(n) for n in notes]
    return jsonify(resp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
