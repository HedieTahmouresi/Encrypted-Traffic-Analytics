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
            splt_analysis=10,
            idle_timeout=300,
            active_timeout=1800
        )
        
        total_flows = streamer.to_csv(path=self.nfstream_csv)
        print(f"[+] NFStream extraction complete. {total_flows} flows saved to {self.nfstream_csv}")

    def run_zeek(self):
        # TODO: Implement subprocess call to Zeek
        print(f"[*] Running Zeek on {self.pcap_path}...")
        
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_extractor.zeek")
        
        cmd = [
            "zeek", 
            "-C", 
            "-r", os.path.abspath(self.pcap_path), 
            script_path
        ]
        subprocess.run(cmd, cwd=self.zeek_log_dir, check=True)
        print(f"[+] Zeek extraction complete. Logs saved to {self.zeek_log_dir}")

    def merge_features(self):
        # TODO: Implement the complex Pandas merge logic
        print("[*] Merging NFStream and Zeek features...")
        
        df_nf = pd.read_csv(self.nfstream_csv)
        zeek_log_path = os.path.join(self.zeek_log_dir, "ml_features.log")
        
        zeek_cols = [
            "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
            "duration", "orig_payload_bytes", "resp_payload_bytes", 
            "zeek_orig_pkts", "zeek_resp_pkts", "missed_bytes", "history", "conn_state",
            "tls_version", "cipher_suite", "sni_domain", "tls_resumed",
            "http_requests", "http_error_codes",
            "ftp_user", "ftp_failed_auths", "ftp_success_auths",
            "ssh_auth_success", "ssh_auth_attempts", "ssh_client"
        ]
        
        df_zeek = pd.read_csv(
            zeek_log_path, 
            sep='\t', 
            comment='#',     
            names=zeek_cols, 
            na_values='-'  
        )
        
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        df_zeek['proto'] = df_zeek['proto'].str.lower().map(protocol_map)
        
        df_zeek.rename(columns={'proto': 'protocol'}, inplace=True)
        
        df_zeek['ts_ms'] = (df_zeek['ts'] * 1000).astype('int64')
        df_nf['bidirectional_first_seen_ms'] = df_nf['bidirectional_first_seen_ms'].astype('int64')

        df_zeek.sort_values('ts_ms', inplace=True)
        df_nf.sort_values('bidirectional_first_seen_ms', inplace=True)
        
        merge_keys = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol']
        
        unified_df = pd.merge_asof(
            df_nf, 
            df_zeek, 
            left_on='bidirectional_first_seen_ms', 
            right_on='ts_ms', 
            by=merge_keys, 
            tolerance=2000, 
            direction='nearest'
        )
        unified_df.dropna(subset=['uid'], inplace=True)
        
        splt_columns = [col for col in unified_df.columns if 'splt' in col and unified_df[col].dtype == 'object']
        for col in splt_columns:
            exploded = unified_df[col].str.strip('[]').str.split(',', expand=True)
            exploded.columns = [f"{col}_{i}" for i in range(exploded.shape[1])]
            exploded = exploded.astype(float)
            unified_df = pd.concat([unified_df, exploded], axis=1)
            unified_df.drop(columns=[col], inplace=True)
            
        categorical_cols = ['conn_state', 'tls_version', 'cipher_suite', 'sni_domain', 'ftp_user', 'application_name', 'application_category_name']
        for col in categorical_cols:
            if col in unified_df.columns:
                unified_df[col] = unified_df[col].fillna('None')

        numeric_cols = ['missed_bytes', 'http_requests', 'ftp_failed_auths', 'ssh_auth_attempts']
        for col in numeric_cols:
            if col in unified_df.columns:
                unified_df[col] = unified_df[col].fillna(0)
                
        unified_df['datetime'] = pd.to_datetime(unified_df['bidirectional_first_seen_ms'], unit='ms')
        unified_df = unified_df.sort_values('datetime').set_index('datetime')
        
        ssh_mask = unified_df['application_name'].astype(str).str.contains('SSH', case=False, na=False)
        
        unified_df['ssh_flows_past_60s'] = (
            unified_df[ssh_mask]
            .groupby('src_ip')
            .rolling('60s')['id']
            .count()
            .reset_index(level=0, drop=True)
        )
        
        unified_df['ssh_flows_past_60s'] = unified_df['ssh_flows_past_60s'].fillna(0)
        unified_df = unified_df.reset_index(drop=True)
        
        output_path = os.path.join(self.output_dir, "final_hybrid_features.csv")
        unified_df.to_csv(output_path, index=False)
        print(f"[+] Merge complete. Final dataset shape: {unified_df.shape}")
        
        return unified_df

    def process(self):
        print(f"Starting extraction on {self.pcap_path}...")
        self.run_nfstream()
        self.run_zeek()
        unified_df = self.merge_features()
        return unified_df

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
    print("Testing Complete Extraction Pipeline...")
    extractor.process()