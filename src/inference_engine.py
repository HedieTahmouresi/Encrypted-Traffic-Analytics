import joblib
from preprocessor import StreamPreprocessor

class InferenceEngine:
    def __init__(self, tier1_path, tier2_path):
        print("[*] Loading Tier 1 Edge Bouncer (Logistic Regression)...")
        self.t1_pipeline = joblib.load(tier1_path)
        self.t1_features = self.t1_pipeline.feature_names_in_
        
        print("[*] Loading Tier 2 Gateway Analyzer (XGBoost)...")
        self.t2_pipeline = joblib.load(tier2_path)
        self.t2_features = self.t2_pipeline.feature_names_in_
        
        self.preprocessor = StreamPreprocessor()
        
        self.tier2_labels = {
            0: 'Benign', 
            1: 'Low & Slow DoS', 
            2: 'L7 Web Flood', 
            3: 'DDoS', 
            4: 'Brute Force', 
            5: 'Exploit'
        }

    def analyze_flow(self, raw_flow_df):
        t1_input = self.preprocessor.prepare_for_tier(raw_flow_df, self.t1_features, tier=1)
        t1_pred = self.t1_pipeline.predict(t1_input)[0]
        
        if t1_pred == 0:
            return "BENIGN", None
            
        t2_input = self.preprocessor.prepare_for_tier(raw_flow_df, self.t2_features, tier=2)
        t2_pred = self.t2_pipeline.predict(t2_input)[0]
        
        print(f"[DEBUG] Tier 1 Flagged Anomaly | Tier 2 Output: {t2_pred}")

        if t2_pred == 0:
            return "BENIGN", None
        
        threat_name = self.tier2_labels.get(t2_pred, "Unknown Threat")
        return "ANOMALY", threat_name