class HybridRiskEngine:
    def __init__(self, use_ml=False):
        self.use_ml = use_ml
        # Weight distribution
        self.weights = {
            "rules": 0.45,
            "anomaly": 0.35,
            "ml": 0.20
        } if use_ml else {
            "rules": 0.60,
            "anomaly": 0.40,
            "ml": 0.0
        }

    def calculate_risk_score(self, triggered_rules, anomaly_score, ml_probability=0.0):
        # 1. Calculate rule risk component (0-100 based on severity of triggered rules)
        rule_risk = 0.0
        if triggered_rules:
            severity_weights = {"INFO": 10, "LOW": 30, "MEDIUM": 60, "HIGH": 85, "CRITICAL": 100}
            max_rule_severity = max([severity_weights.get(r.get("severity", "LOW"), 30) for r in triggered_rules])
            rule_risk = float(max_rule_severity)

        # 2. Anomaly risk component (0-100)
        anomaly_risk = float(anomaly_score)

        # 3. ML risk component (0-100 probability converted)
        ml_risk = float(ml_probability) * 100.0

        # Weighted fusion
        combined_risk = (
            (rule_risk * self.weights["rules"]) +
            (anomaly_risk * self.weights["anomaly"]) +
            (ml_risk * self.weights["ml"])
        )

        final_score = min(100.0, max(0.0, round(combined_risk, 2)))

        # Classification mapping
        if final_score <= 20:
            classification = "NORMAL"
        elif final_score <= 50:
            classification = "SUSPICIOUS"
        else:
            classification = "POTENTIAL INTRUSION"

        return final_score, classification
