from preprocessor import ThreatPreprocessor

class InferenceEngine:
    def __init__(self, tier1_path, tier2_path):
        self.edge_bouncer = ThreatPreprocessor(tier1_path, tier=1)
        self.gateway_analyzer = ThreatPreprocessor(tier2_path, tier=2)

    def analyze_flow(self, flow_df):
        t1_input = self.edge_bouncer.sanitize_and_transform(flow_df)
        is_anomaly = self.edge_bouncer.predict(t1_input)
        
        if is_anomaly[0] == 0:
            return "BENIGN", None
        
        t2_input = self.gateway_analyzer.sanitize_and_transform(flow_df)
        threat_type = self.gateway_analyzer.predict(t2_input)
        
        return "ANOMALY", threat_type