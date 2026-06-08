import joblib
import pandas as pd

class ThreatPreprocessor:
    def __init__(self, pipeline_path, tier=1):
        self.pipeline = joblib.load(pipeline_path)
        self.expected_features = self.pipeline.named_steps['preprocessor'].feature_names_in_
        self.tier = tier

    def sanitize_and_transform(self, raw_df):
        contaminants = [
            'label', 'id', 'expiration_id', 'uid', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac', 
            'src_oui', 'dst_oui', 'vlan_id', 'tunnel_id', 'src_port', 'dst_port',
            'datetime', 'ts', 'ts_ms', 'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
            'src2dst_first_seen_ms', 'src2dst_last_seen_ms', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
            'client_fingerprint', 'server_fingerprint', 'requested_server_name', 'user_agent'
        ]
        
        if self.tier == 1:
            tier1_extras = [
                'application_name', 'application_category_name', 'application_is_guessed', 
                'application_confidence', 'content_type', 'sni_domain',
                'tls_version', 'cipher_suite', 'tls_resumed',
                'http_requests', 'http_error_codes',
                'ftp_user', 'ftp_failed_auths', 'ftp_success_auths',
                'ssh_auth_success', 'ssh_auth_attempts', 'ssh_client', 'ssh_flows_past_60s'
            ]
            contaminants.extend(tier1_extras)

        clean_df = raw_df.drop(columns=[c for c in contaminants if c in raw_df.columns], errors='ignore')
        
        clean_df = clean_df.reindex(columns=self.expected_features, fill_value=0)

        return self.pipeline.named_steps['preprocessor'].transform(clean_df)

    def predict(self, clean_df):
        return self.pipeline.named_steps['classifier'].predict(clean_df)
