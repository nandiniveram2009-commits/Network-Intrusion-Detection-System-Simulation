import numpy as np

class StatisticalAnomalyDetector:
    def __init__(self):
        # Baseline statistical parameters (mean and standard deviation derived from normal traffic profiles)
        self.baselines = {
            "bytes_per_second": {"mean": 4500.0, "std": 1200.0},
            "packets_per_second": {"mean": 15.0, "std": 5.0},
            "connection_rate": {"mean": 2.5, "std": 1.2},
            "failure_ratio": {"mean": 0.02, "std": 0.05}
        }

    def calculate_z_score(self, value, mean, std):
        if std == 0:
            return 0.0
        return (value - mean) / std

    def calculate_anomaly_score(self, features):
        """
        Calculates a statistical anomaly score from 0 to 100 using Z-scores across key metrics.
        """
        scores = []
        
        metrics_to_check = ["bytes_per_second", "packets_per_second", "connection_rate", "failure_ratio"]
        
        for metric in metrics_to_check:
            val = features.get(metric, 0.0)
            b = self.baselines[metric]
            z = abs(self.calculate_z_score(val, b["mean"], b["std"]))
            # Convert Z-score to a 0-100 scale (Z >= 4.0 maps to 100)
            metric_score = min(100.0, (z / 4.0) * 100.0)
            scores.append(metric_score)
            
        overall_anomaly_score = round(float(np.mean(scores)), 2)
        return min(100.0, max(0.0, overall_anomaly_score))
