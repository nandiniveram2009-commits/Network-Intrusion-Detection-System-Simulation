class SignatureRuleEngine:
    def __init__(self, custom_thresholds=None):
        self.thresholds = custom_thresholds or {
            "max_connection_rate": 45.0,
            "max_failed_ratio": 0.5,
            "max_syn_ratio": 0.85,
            "max_traffic_bytes": 1000000,
            "port_probe_connection_min": 35
        }

    def evaluate_rules(self, flow, features):
        triggered_rules = []

        # RULE 1: Excessive Connection Rate
        if features["connection_rate"] > self.thresholds["max_connection_rate"]:
            triggered_rules.append({
                "rule_id": "IDS-001",
                "name": "High Connection Rate",
                "severity": "HIGH",
                "description": f"Connection rate ({features['connection_rate']} conn/s) exceeded baseline threshold."
            })

        # RULE 2: Repeated Failed Connections
        if features["failure_ratio"] > self.thresholds["max_failed_ratio"] and features["failed_connection_count"] > 10:
            triggered_rules.append({
                "rule_id": "IDS-002",
                "name": "Repeated Failed Connections",
                "severity": "MEDIUM",
                "description": f"High connection failure ratio detected ({features['failure_ratio']*100}%)."
            })

        # RULE 3: SYN-Heavy Connection Behavior
        if features["syn_ratio"] > self.thresholds["max_syn_ratio"] and features["packet_count"] > 50:
            triggered_rules.append({
                "rule_id": "IDS-004",
                "name": "SYN-Heavy Statistical Pattern",
                "severity": "HIGH",
                "description": f"Abnormally high SYN packet ratio ({features['syn_ratio']*100}%)."
            })

        # RULE 4: Abnormally High Traffic Volume
        if features["byte_count"] > self.thresholds["max_traffic_bytes"]:
            triggered_rules.append({
                "rule_id": "IDS-006",
                "name": "Abnormally High Traffic Volume",
                "severity": "MEDIUM",
                "description": f"Byte count ({features['byte_count']} bytes) exceeded standard volume limit."
            })

        # RULE 5: Suspicious Port Activity (e.g. Scanning indicators)
        if flow.get("destination_port", 0) < 1024 and features["connection_count"] > self.thresholds["port_probe_connection_min"]:
            triggered_rules.append({
                "rule_id": "IDS-003",
                "name": "Multi-Port Probing Pattern",
                "severity": "HIGH",
                "description": "Rapid connection attempts targeting low system service ports."
            })

        return triggered_rules
