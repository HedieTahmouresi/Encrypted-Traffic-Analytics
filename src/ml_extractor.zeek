module ML_Extractor;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                time     &log;
        uid:               string   &log;
        src_ip:            addr     &log;
        src_port:          port     &log;
        dst_ip:            addr     &log;
        dst_port:          port     &log;
        proto:             string   &log;
        
        # Connection Features
        duration:          interval &log &optional;
        orig_bytes:        count    &log &optional;
        resp_bytes:        count    &log &optional;
        orig_pkts:         count    &log &optional;
        resp_pkts:         count    &log &optional;
        missed_bytes:      count    &log &optional;
        history:           string   &log &optional;
        conn_state:        string   &log &optional;
        
        # TLS / SSL Features
        tls_version:       string   &log &optional;
        cipher_suite:      string   &log &optional;
        sni_domain:        string   &log &optional;
        tls_resumed:       bool     &log &default=F;
        tls_established:   bool     &log &default=F;
        
        # FTP Features
        ftp_user:          string   &log &optional;
        ftp_failed_auths:  count    &log &default=0;
        ftp_success_auths: count    &log &default=0;
        
        # SSH Features
        ssh_auth_success:  bool     &log &optional;
        ssh_auth_attempts: count    &log &default=0;
        ssh_client:        string   &log &optional;
    };
}

redef record connection += {
    ml_record: Info &optional;
};

event zeek_init() {
    Log::create_stream(ML_Extractor::LOG, [$columns=Info, $path="ml_features"]);
}

event new_connection(c: connection) {
    c$ml_record = [
        $ts=network_time(),
        $uid=c$uid,
        $src_ip=c$id$orig_h,
        $src_port=c$id$orig_p,
        $dst_ip=c$id$resp_h,
        $dst_port=c$id$resp_p,
        $proto=fmt("%s", get_port_transport_proto(c$id$orig_p))
    ];
}

# --- TLS Hooks ---
event ssl_established(c: connection) {
    if ( ! c?$ml_record || ! c?$ssl ) return;
    c$ml_record$tls_established = T;
    if ( c$ssl?$version ) c$ml_record$tls_version = c$ssl$version;
    if ( c$ssl?$cipher ) c$ml_record$cipher_suite = c$ssl$cipher;
    if ( c$ssl?$resumed ) c$ml_record$tls_resumed = c$ssl$resumed;
}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec) {
    if ( c?$ml_record && |names| > 0 ) c$ml_record$sni_domain = names[0];
}

# --- FTP Hooks ---
event ftp_request(c: connection, command: string, arg: string) {
    if ( ! c?$ml_record ) return;
    if ( command == "USER" ) c$ml_record$ftp_user = arg;
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) {
    if ( ! c?$ml_record ) return;
    
    if ( code == 530 ) {
        c$ml_record$ftp_failed_auths += 1;
    } else if ( code == 230 ) {
        c$ml_record$ftp_success_auths += 1;
    }
}

# --- SSH Hooks ---
event ssh_auth_successful(c: connection, auth_method_none: bool) {
    if ( ! c?$ml_record ) return;
    c$ml_record$ssh_auth_success = T;
    c$ml_record$ssh_auth_attempts += 1;
}

event ssh_auth_failed(c: connection) {
    if ( ! c?$ml_record ) return;
    c$ml_record$ssh_auth_success = F;
    c$ml_record$ssh_auth_attempts += 1;
}

event ssh_client_version(c: connection, version: string) {
    if ( ! c?$ml_record ) return;
    c$ml_record$ssh_client = version;
}

event connection_state_remove(c: connection) &priority=-10 {
    if ( ! c?$ml_record ) return;

    if ( c?$duration ) c$ml_record$duration = c$duration;
    if ( c?$conn && c$conn?$conn_state ) c$ml_record$conn_state = c$conn$conn_state;

    if ( c?$orig ) {
        c$ml_record$orig_bytes = c$orig$size;
        c$ml_record$orig_pkts = c$orig$num_pkts;
    }
    if ( c?$resp ) {
        c$ml_record$resp_bytes = c$resp$size;
        c$ml_record$resp_pkts = c$resp$num_pkts;
    }

    if ( c?$history ) c$ml_record$history = c$history;
    if ( c?$conn && c$conn?$missed_bytes ) c$ml_record$missed_bytes = c$conn$missed_bytes;

    Log::write(ML_Extractor::LOG, c$ml_record);
}