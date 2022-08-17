use std::sync::Arc;

use log::{info, error};
use rustls::{
    server::{
        AllowAnyAuthenticatedClient,
        ServerSessionMemoryCache,
    },
    KeyLogFile,
    RootCertStore,
    ServerConfig
};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio_rustls::{TlsAcceptor};

use crate::tls;

pub fn make_server_config(certs: &str, key_file: &str) -> Option<Arc<ServerConfig>> {
    match tls::utils::load_certs(certs) {
        None => { None }
        Some(roots) => {
            let cert_chain = roots.clone();
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                match client_auth_roots.add(&root) {
                    Ok(_) => {}
                    Err(e) => error!("failed adding root certificate to the roots: {:?}", e)
                }
            }
            let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);
            match tls::utils::load_private_key(key_file) {
                None => { None }
                Some(key_der) => {
                    let suites = rustls::ALL_CIPHER_SUITES.to_vec();
                    let versions = rustls::ALL_VERSIONS.to_vec();
                    match ServerConfig::builder()
                        .with_cipher_suites(&suites)
                        .with_safe_default_kx_groups()
                        .with_protocol_versions(&versions) {
                        Ok(builder) => {
                            match builder.with_client_cert_verifier(client_auth)
                                .with_single_cert_with_ocsp_and_sct(cert_chain, key_der, vec![], vec![]) {
                                Ok(mut config) => {
                                    config.key_log = Arc::new(KeyLogFile::new());
                                    config.session_storage = ServerSessionMemoryCache::new(256);
                                    Some(Arc::new(config))
                                }
                                Err(e) => {
                                    error!("bad certificates/private key: {:?}", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!("inconsistent cipher-suites/versions specified: {:?}", e);
                            None
                        }
                    }
                }
            }
        }
    }
}

pub fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Option<TlsAcceptor> {
    make_server_config(&cert_file, &key_file).map_or(None, |config| Some(TlsAcceptor::from(config)))
}

pub async fn handle_connection(mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>) {
    tokio::spawn(async move {
        let mut buf = [0; 12];
        match tls_stream.read(&mut buf).await {
            Ok(_nread) => {
                info!("server: got data: {:?}", buf);
                match tls_stream.write(&buf).await {
                    Ok(_nwritten) => {
                        info!("server: echoed data");
                    }
                    Err(e) => {
                        error!("server could not echo data: {:?}", e)
                    }
                }
            }
            Err(e) => {
                error!("server could not read data: {:?}", e)
            }
        }
    });
}

pub async fn start_server(bind_address: &str, cert_file: &str, key_file: &str) -> Option<tokio::task::JoinHandle<()>> {
    match tls::server::new_tls_acceptor(cert_file, key_file) {
        None => { None }
        Some(acceptor) => {
            let opt = match TcpListener::bind(bind_address).await {
                Ok(listener) => {
                    info!("server bound at {}", bind_address);
                    Some(tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _peer_addr)) => {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            info!("server: Accepted client conn with TLS");
                                            handle_connection(tls_stream).await;
                                        }
                                        Err(e) => {
                                            error!("acceptor accept failed: {:?}", e)
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("listener accept failed: {:?}", e)
                                }
                            }
                        }
                    }))
                }
                Err(e) => {
                    error!("server not bound: {:?}", e);
                    None
                }
            };
            opt
        }
    }
}
