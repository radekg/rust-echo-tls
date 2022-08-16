use std::sync::Arc;
use crate::tls;

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

pub fn make_client_config(ca_file: &str, certs_file: &str, key_file: &str) -> Arc<rustls::ClientConfig> {
    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();
    let root_store = tls::utils::load_root_store(ca_file);
    let certs = tls::utils::load_certs(certs_file);
    let key = tls::utils::load_private_key(key_file);

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store)
        .with_single_cert(certs, key)
        .expect("invalid client auth certs/key");
    Arc::new(config)
}

pub async fn new_tls_stream(domain: &str, addr: std::net::SocketAddr, 
    ca_file: &str, cert_file: &str, key_file: &str) -> ClientTlsStream<TcpStream> {
    let config = make_client_config(&ca_file, &cert_file, &key_file);
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(&addr).await.unwrap();
    let domain = rustls::ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname")).unwrap();
    let stream = connector.connect(domain, stream).await.unwrap();
    stream
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }
    unreachable!("Cannot lookup address");
}

pub async fn start_client(host: &str, port: u16, ca_file: &str, cert_file: &str, key_file: &str, msg: &[u8], buf: &mut [u8]) {
    let addr = lookup_ipv4(host, port);
    println!("Socket address is: {:?}", addr.clone());
    let mut tls_stream =
        new_tls_stream(host, addr, ca_file, cert_file, key_file).await;
    tls_stream.write(msg).await.unwrap();
    println!("client: send data");
    tls_stream.read(buf).await.unwrap();
    println!("client: read echoed data");
}
