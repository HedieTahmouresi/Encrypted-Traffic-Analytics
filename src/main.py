import os
import pandas as pd
from feature_extractor import HybridExtractor
from inference_engine import InferenceEngine

# 1. Configuration
PCAP_PATH = "./data/raw/test.pcap" # Point this to any PCAP for live demo
OUTPUT_DIR = "./data/processed/live_inference"
MODEL_T1 = "./models/tier1_edge_pipeline.pkl"
MODEL_T2 = "./models/tier2_gateway_pipeline.pkl"

def main():
    print("[*] Initializing Inference System...")
    
    # Initialize Engine
    engine = InferenceEngine(MODEL_T1, MODEL_T2)
    extractor = HybridExtractor(PCAP_PATH, OUTPUT_DIR)
    
    # 1. Extract features for the PCAP
    print("[*] Analyzing PCAP...")
    df = extractor.process()
    
    # 2. Iterate through flows and run inference
    print("[*] Running Live Detection...")
    for index, row in df.iterrows():
        # Convert row to DataFrame for the preprocessor
        flow_df = row.to_frame().T
        
        # Run detection
        status, threat = engine.analyze_flow(flow_df)
        
        # 3. Alert Output
        if status == "ANOMALY":
            print(f"[ALERT] {status} DETECTED! Threat Type: {threat[0]} | Flow: {row['uid']}")
        else:
            print("Benign flow detected.")
            pass

if __name__ == "__main__":
    main()