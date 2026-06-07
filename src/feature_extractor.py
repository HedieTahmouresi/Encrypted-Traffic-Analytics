import os
import pandas as pd
from nfstream import NFStreamer
import subprocess

class HybridExtractor:
    def __init__(self, pcap_path, output_dir):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        self.nfstream_csv = os.path.join(output_dir, "nfstream_features.csv")
        self.zeek_log_dir = os.path.join(output_dir, "zeek_logs")
        
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.zeek_log_dir, exist_ok=True)
        
    def run_nfstream(self):
        # TODO: Implement NFStream logic and export to CSV
        print(f"[*] Running NFStream on {self.pcap_path}...")
        
        streamer = NFStreamer(
            source=self.pcap_path,
            decode_tunnels=True,
            statistical_analysis=True,  
            splt_analysis=10
        )
        
        total_flows = streamer.to_csv(path=self.nfstream_csv)
        print(f"[+] NFStream extraction complete. {total_flows} flows saved to {self.nfstream_csv}")

    def run_zeek(self):
        # TODO: Implement subprocess call to Zeek
        pass

    def merge_features(self):
        # TODO: Implement the complex Pandas merge logic
        pass

    def process(self):
        print(f"Starting extraction on {self.pcap_path}...")
        self.run_nfstream()
        # self.run_zeek()
        # unified_df = self.merge_features()
        # return unified_df

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))

    pcap_file = os.path.join(script_dir, "../data/raw/test.pcap")
    output_folder = os.path.join(script_dir, "../data/processed/temp")

    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file not found at {os.path.abspath(pcap_file)}")
        exit(1)
    
    extractor = HybridExtractor(
        pcap_path=pcap_file, 
        output_dir=output_folder
    )
    
    print("Hybrid Extractor Initialized.")
    print("Hybrid Extractor Initialized. Testing NFStream module...")
    extractor.run_nfstream()