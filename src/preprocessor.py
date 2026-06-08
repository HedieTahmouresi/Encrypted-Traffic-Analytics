import pandas as pd

class StreamPreprocessor:
    def __init__(self):

        self.tier2_contaminants = [
            'id', 'uid', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac', 
            'src_oui', 'dst_oui', 'vlan_id', 'tunnel_id', 'src_port', 'dst_port',
            'datetime', 'ts', 'ts_ms', 'bidirectional_first_seen_ms', 
            'bidirectional_last_seen_ms', 'src2dst_first_seen_ms', 
            'src2dst_last_seen_ms', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
            'application_name', 'application_category_name', 'application_is_guessed', 
            'application_confidence', 'content_type', 'user_agent',
            'http_requests', 'http_error_codes',
            'ftp_user', 'ftp_failed_auths', 'ftp_success_auths',
            'ssh_auth_success', 'ssh_auth_attempts', 'ssh_client', 'ssh_flows_past_60s'
        ]

        self.tier1_contaminants = self.tier2_contaminants + [
            'sni_domain', 'cipher_suite', 'tls_version', 'tls_resumed',
            'requested_server_name', 'client_fingerprint', 'server_fingerprint'
        ]
        

    def prepare_for_tier(self, raw_flow_df, expected_features, tier):
        cols_to_drop = self.tier2_contaminants
        if tier == 1:
            cols_to_drop = self.tier1_contaminants

        clean_df = raw_flow_df.drop(columns=[c for c in cols_to_drop if c in raw_flow_df.columns], errors='ignore')
        
        aligned_df = clean_df.reindex(columns=expected_features, fill_value=0)
        
        for col in aligned_df.columns:
            if aligned_df[col].dtype == 'object' and aligned_df[col].isnull().any():
                aligned_df[col] = aligned_df[col].fillna('Missing')
                
        return aligned_df