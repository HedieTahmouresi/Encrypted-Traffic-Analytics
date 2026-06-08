import warnings
from feature_extractor import HybridExtractor
from inference_engine import InferenceEngine

warnings.filterwarnings('ignore') 

PCAP_PATH = "./data/raw/test.pcap" 
OUTPUT_DIR = "./data/processed/live_inference"
MODEL_T1 = "./models/tier1_edge_pipeline.pkl"
MODEL_T2 = "./models/tier2_gateway_pipeline.pkl"

def main():
    print("="*60)
    print(" 🛡️ ENCRYPTED TRAFFIC ANALYTICS - LIVE INFERENCE ENGINE 🛡️")
    print("="*60)
    
    engine = InferenceEngine(MODEL_T1, MODEL_T2)
    extractor = HybridExtractor(PCAP_PATH, OUTPUT_DIR)
    
    print("\n[*] Starting packet capture and hybrid feature extraction...")
    df = extractor.process()
    
    if df is None or df.empty:
        print("[!] No valid network flows extracted. Exiting.")
        return

    print(f"\n[*] Live Detection Started on {len(df)} connections...")
    print("-" * 60)
    
    stats = {"benign": 0, "anomaly": 0}

    for index, row in df.iterrows():
        flow_df = row.to_frame().T
        
        src_ip = row.get('src_ip', 'Unknown')
        dst_ip = row.get('dst_ip', 'Unknown')
        dst_port = row.get('dst_port', 'Unknown')
        
        status, threat_type = engine.analyze_flow(flow_df)
        
        if status == "ANOMALY":
            stats["anomaly"] += 1
            print(f"[🚨 THREAT DETECTED] Type: {threat_type}")
            print(f"    Target Flow: {src_ip} -> {dst_ip}:{dst_port}\n")
        else:
            stats["benign"] += 1

    print("-" * 60)
    print("[*] Inference Session Complete.")
    print(f"    Total Flows Processed: {len(df)}")
    print(f"    Benign Passed: {stats['benign']} | Anomalies Blocked: {stats['anomaly']}")
    print("="*60)

if __name__ == "__main__":
    main()