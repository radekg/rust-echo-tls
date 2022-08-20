use log::{error, info};
use std::sync::Arc;

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tokio_rustls::{
    client::TlsStream as ClientTlsStream,
    rustls::{self},
    TlsConnector,
};

use crate::tls;

#[derive(Debug)]
pub enum ClientError {
    AddressLookupError(std::io::Error),
    ConnectError(tokio::io::Error),
    NoAddressesAvailable,
    ReadFailedError(std::io::Error),
    WriteFailedError(std::io::Error),
    TlsError(tls::utils::TlsError),
    TlsCipherSuitesError(rustls::Error),
    TlsClientCertError(rustls::Error),
    TlsDomainNameError(rustls::client::InvalidDnsNameError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressLookupError(e) => write!(f, "failed looking up the address: {:?}", e),
            Self::ConnectError(e) => write!(f, "TCP stream not connected: {:?}", e),
            Self::NoAddressesAvailable => write!(f, "no addresses available while looking up"),
            Self::ReadFailedError(e) => write!(f, "read failed: {:?}", e),
            Self::WriteFailedError(e) => write!(f, "write failed: {:?}", e),
            Self::TlsError(e) => write!(f, "TLS error: {:?}", e),
            Self::TlsCipherSuitesError(e) => {
                write!(f, "inconsistent cipher-suite/versions selected: {:?}", e)
            }
            Self::TlsClientCertError(e) => write!(f, "invalid client auth certs/key: {:?}", e),
            Self::TlsDomainNameError(e) => write!(f, "invalid DNS name: {:?}", e),
        }
    }
}

fn make_client_config(
    ca_file: &str,
    certs_file: &str,
    key_file: &str,
) -> Result<rustls::ClientConfig, ClientError> {
    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();
    let root_store = tls::utils::load_root_store(ca_file).map_err(|e| ClientError::TlsError(e))?;
    let cert_chain = tls::utils::load_certs(certs_file).map_err(|e| ClientError::TlsError(e))?;
    let key_der = tls::utils::load_private_key(key_file).map_err(|e| ClientError::TlsError(e))?;
    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .map_err(|e| ClientError::TlsCipherSuitesError(e))?
        .with_root_certificates(root_store)
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| ClientError::TlsClientCertError(e))?;
    Ok(config)
}

async fn new_tls_stream(
    domain: &str,
    addr: std::net::SocketAddr,
    ca_file: &str,
    cert_file: &str,
    key_file: &str,
) -> Result<ClientTlsStream<TcpStream>, ClientError> {
    let config = make_client_config(&ca_file, &cert_file, &key_file)?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ClientError::ConnectError(e))?;
    let server_name =
        rustls::ServerName::try_from(domain).map_err(|e| ClientError::TlsDomainNameError(e))?;
    let connected_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| ClientError::ConnectError(e))?;
    Ok(connected_stream)
}

fn lookup_ipv4(host: &str, port: u16) -> Result<SocketAddr, ClientError> {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                if let SocketAddr::V4(_) = addr {
                    return Ok(addr);
                }
            }
            Err(ClientError::NoAddressesAvailable)
        }
        Err(e) => Err(ClientError::AddressLookupError(e)),
    }
}

pub async fn start_client(
    host: &str,
    port: u16,
    ca_file: &str,
    cert_file: &str,
    key_file: &str,
    msg: &[u8],
    buf: &mut [u8],
) -> Result<(), ClientError> {
    let addr = lookup_ipv4(host, port)?;
    info!("client socket address is: {:?}", addr.clone());
    let mut tls_stream = new_tls_stream(host, addr, ca_file, cert_file, key_file).await?;
    match tls_stream.write(msg).await {
        Ok(_nwritten) => {
            info!("client: send data");
            match tls_stream.read(buf).await {
                Ok(_nread) => {
                    info!("client: read echoed data");
                    Ok(())
                }
                Err(e) => {
                    error!("client failed reading echoed data: {:?}", e);
                    Err(ClientError::ReadFailedError(e))
                }
            }
        }
        Err(e) => {
            error!("client write data failed: {:?}", e);
            Err(ClientError::WriteFailedError(e))
        }
    }
}
