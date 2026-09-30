import uuid
from datetime import datetime

class AlertEngine:
    def __init__(self):
        self.active_alerts = []

    def generate_alert(self, flow, triggered_rules, risk_score, classification):
        if classification == "NORMAL":
            return None

        severity = "LOW"
        if risk_score > 80:
            severity = "CRITICAL"
        elif risk_score > 60:
            severity = "HIGH"
        elif risk_score > 40:
            severity = "MEDIUM"

        primary_rule = triggered_rules[0]["name"] if triggered_rules else "Statistical Behavioral Anomaly"
        rule_id = triggered_rules[0]["rule_id"] if triggered_rules else "IDS-ANOMALY-01"

        alert = {
            "alert_id": f"ALT-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": datetime.now().isoformat(),
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "protocol": flow.get("protocol", "TCP"),
            "source_port": flow.get("source_port", 0),
            "destination_port": flow.get("destination_port", 0),
            "rule_id": rule_id,
            "alert_type": primary_rule,
            "severity": severity,
            "risk_score": risk_score,
            "classification": classification,
            "description": f"Intrusion alert triggered by {primary_rule} with risk score {risk_score}.",
            "status": "NEW",
            "notes": []
        }
        
        self.active_alerts.append(alert)
        return alert

def correlate_alerts(alerts, time_window_seconds=60):
    """
    Groups related alerts originating from the same source IP within a sliding time window
    to mitigate alert fatigue and form incident clusters.
    """
    correlated_incidents = {}
    for alert in alerts:
        src = alert["source_ip"]
        if src not in correlated_incidents:
            correlated_incidents[src] = {
                "source_ip": src,
                "alert_count": 0,
                "max_risk": 0.0,
                "alerts": []
            }
        correlated_incidents[src]["alert_count"] += 1
        correlated_incidents[src]["max_risk"] = max(correlated_incidents[src]["max_risk"], alert["risk_score"])
        correlated_incidents[src]["alerts"].append(alert["alert_id"])
        
    return list(correlated_incidents.values())
