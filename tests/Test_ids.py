import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ids.feature_extractor import extract_network_features
from ids.rule_engine import SignatureRuleEngine
from ids.anomaly_detector import StatisticalAnomalyDetector
from ids.risk_engine import HybridRiskEngine

class TestIDSEngine(unittest.TestCase):
    def setUp(self):
        self.rule_engine = SignatureRuleEngine()
        self.anomaly_detector = StatisticalAnomalyDetector()
        self.risk_engine = HybridRiskEngine(use_ml=False)

    def test_normal_tcp_flow_feature_extraction(self):
        flow = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 5000,
            "duration_seconds": 2.0,
            "connection_count": 1,
            "failed_connection_count": 0,
            "syn_count": 1,
            "rst_count": 0
        }
        features = extract_network_features(flow)
        self.assertEqual(features["packet_count"], 10)
        self.assertEqual(features["average_packet_size"], 500.0)

    def test_rule_detection_high_connection_rate(self):
        flow = {
            "source_ip": "192.0.2.15",
            "destination_ip": "198.51.100.5",
            "source_port": 12345,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 200,
            "byte_count": 10000,
            "duration_seconds": 1.0,
            "connection_count": 100,
            "failed_connection_count": 0,
            "syn_count": 100,
            "rst_count": 0
        }
        features = extract_network_features(flow)
        rules = self.rule_engine.evaluate_rules(flow, features)
        rule_ids = [r["rule_id"] for r in rules]
        self.assertIn("IDS-001", rule_ids)

    def test_anomaly_score_calculation(self):
        abnormal_features = {
            "bytes_per_second": 95000.0,
            "packets_per_second": 800.0,
            "connection_rate": 150.0,
            "failure_ratio": 0.9
        }
        score = self.anomaly_detector.calculate_anomaly_score(abnormal_features)
        self.assertGreater(score, 50.0)

    def test_hybrid_risk_scoring(self):
        rules = [{"rule_id": "IDS-001", "name": "High Connection Rate", "severity": "HIGH"}]
        risk, classification = self.risk_engine.calculate_risk_score(rules, anomaly_score=75.0, ml_probability=0.8)
        self.assertGreater(risk, 50.0)
        self.assertIn(classification, ["SUSPICIOUS", "POTENTIAL INTRUSION"])

if __name__ == "__main__":
    unittest.main()
