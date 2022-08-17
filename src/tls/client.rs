use std::sync::Arc;
use crate::tls;

use log::{info, error};

use std::io;
use std::net::{
    SocketAddr,
    ToSocketAddrs,
};

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use tokio_rustls::{
    TlsConnector,
    rustls::{self},
    client::TlsStream as ClientTlsStream,
};

pub fn make_client_config(ca_file: &str, certs_file: &str, key_file: &str) -> Option<Arc<rustls::ClientConfig>> {
    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();
    match tls::utils::load_root_store(ca_file) {
        None => { None }
        Some(root_store) => {
            match tls::utils::load_certs(certs_file) {
                None => { None }
                Some(cert_chain) => {
                    match tls::utils::load_private_key(key_file) {
                        None => { None }
                        Some(key_der) => {
                            match rustls::ClientConfig::builder()
                                .with_cipher_suites(&suites)
                                .with_safe_default_kx_groups()
                                .with_protocol_versions(&versions) {
                                Ok(builder) => {
                                    match builder.with_root_certificates(root_store)
                                        .with_single_cert(cert_chain, key_der) {
                                        Ok(config) => {
                                            Some(Arc::new(config))
                                        }
                                        Err(e) => {
                                            error!("invalid client auth certs/key: {:?}", e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("inconsistent cipher-suite/versions selected: {:?}", e);
                                    None
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
}

pub async fn new_tls_stream(domain: &str, addr: std::net::SocketAddr, 
    ca_file: &str, cert_file: &str, key_file: &str) -> Option<ClientTlsStream<TcpStream>> {
    match make_client_config(&ca_file, &cert_file, &key_file) {
        None => { None }
        Some(config) => {
            let connector = TlsConnector::from(config);
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    match rustls::ServerName::try_from(domain)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname")) {
                        Ok(domain) => {
                            match connector.connect(domain, stream).await {
                                Ok(connected_stream) => {
                                    info!("stream connected");
                                    Some(connected_stream)
                                }
                                Err(e) => {
                                    error!("stream not connected: {:?}", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!("server name not resolved: {:?}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("TCP stream not connected: {:?}", e);
                    None
                }
            }
        }
    }
}

pub fn lookup_ipv4(host: &str, port: u16) -> Option<SocketAddr> {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                if let SocketAddr::V4(_) = addr {
                    return Some(addr);
                }
            }
            None
        }
        Err(e) => {
            error!("failed looking up the address: {:?}", e);
            None
        }
    }
}

pub async fn start_client(host: &str, port: u16, ca_file: &str, cert_file: &str, key_file: &str, msg: &[u8], buf: &mut [u8]) -> Option<()> {
    match lookup_ipv4(host, port) {
        None => { None }
        Some(addr) => {
            info!("client socket address is: {:?}", addr.clone());
            match new_tls_stream(host, addr, ca_file, cert_file, key_file).await {
                None => { None }
                Some(mut tls_stream) => {
                    match tls_stream.write(msg).await {
                        Ok(_nwritten) => {
                            info!("client: send data");
                            match tls_stream.read(buf).await {
                                Ok(_nread) => {
                                    info!("client: read echoed data");
                                    Some(())
                                }
                                Err(e) => {
                                    error!("client failed reading echoed data: {:?}", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!("client write data failed: {:?}", e);
                            None
                        }
                    }
                }
            }
        }
    }
}
