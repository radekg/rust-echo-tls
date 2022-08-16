use std::sync::Arc;

use rustls::{
    server::{
        AllowAnyAuthenticatedClient,
        ServerSessionMemoryCache,
    },
    KeyLogFile,
    RootCertStore,
    ServerConfig
};

use tokio::net::TcpListener;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use tokio_rustls::TlsAcceptor;

use crate::tls;

pub fn make_server_config(certs: &str, key_file: &str) -> Arc<ServerConfig> {
    let roots = tls::utils::load_certs(certs);
    let certs = roots.clone();
    let mut client_auth_roots = RootCertStore::empty();
    for root in roots {
        client_auth_roots.add(&root).unwrap();
    }
    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);
    let privkey = tls::utils::load_private_key(key_file);
    let suites = rustls::ALL_CIPHER_SUITES.to_vec();
    let versions = rustls::ALL_VERSIONS.to_vec();
    let mut config = ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");
    config.key_log = Arc::new(KeyLogFile::new());
    config.session_storage = ServerSessionMemoryCache::new(256);
    Arc::new(config)
}

pub fn new_tls_acceptor(cert_file: &str, key_file: &str) -> TlsAcceptor {
    let config = make_server_config(&cert_file, &key_file);
    let acceptor = TlsAcceptor::from(config);
    acceptor
}

pub async fn start_server(bind_address: &str, cert_file: &str, key_file: &str) {
    let acceptor = tls::server::new_tls_acceptor(cert_file, key_file);
    let listener = TcpListener::bind(bind_address).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(stream).await.unwrap();
            println!("server: Accepted client conn with TLS");
            tokio::spawn(async move {
                let mut buf = [0; 12];
                tls_stream.read(&mut buf).await.unwrap();
                println!("server: got data: {:?}", buf);
                tls_stream.write(&buf).await.unwrap();
                println!("server: flush the data out");
            });
        }
    });
}
