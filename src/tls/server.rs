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

#[derive(Debug)]
pub enum ServerError {
    BindError(std::io::Error),
    TlsError(tls::utils::TlsError),
    TlsCipherSuitesError(rustls::Error),
    TlsServerCertError(rustls::Error),
    WebPkiError(tokio_rustls::webpki::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindError(e) =>
                write!(f, "server not bound: {:?}", e),
            Self::TlsError(e) =>
                write!(f, "TLS error: {:?}", e),
            Self::TlsCipherSuitesError(e) =>
                write!(f, "inconsistent cipher-suite/versions selected: {:?}", e),
            Self::TlsServerCertError(e) =>
                write!(f, "invalid certificate/key: {:?}", e),
            Self::WebPkiError(e) =>
                write!(f, "failed adding root certificate to the roots: {:?}", e),
        }
    }
}

fn make_server_config(certs: &str, key_file: &str) -> Result<Arc<ServerConfig>, ServerError> {
    let roots = tls::utils::load_certs(certs).map_err(|e| ServerError::TlsError(e))?;
    let cert_chain = roots.clone();
    let mut client_auth_roots = RootCertStore::empty();
    roots.into_iter().try_for_each(|der| client_auth_roots.add(&der)).map_err(|e| ServerError::WebPkiError(e))?;
    let key_der = tls::utils::load_private_key(key_file).map_err(|e| ServerError::TlsError(e))?;
    let suites = rustls::ALL_CIPHER_SUITES.to_vec();
    let versions = rustls::ALL_VERSIONS.to_vec();

    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);

    let mut config = ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions).map_err(|e| ServerError::TlsCipherSuitesError(e))?
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(cert_chain, key_der, vec![], vec![]).map_err(|e| ServerError::TlsServerCertError(e))?;

    config.key_log = Arc::new(KeyLogFile::new());
    config.session_storage = ServerSessionMemoryCache::new(256);
    Ok(Arc::new(config))
}

fn new_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor, ServerError> {
    make_server_config(&cert_file, &key_file).map(|config| TlsAcceptor::from(config))
}

async fn handle_connection(mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>) {
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

pub async fn start_server(bind_address: &str, cert_file: &str, key_file: &str) -> Result<tokio::task::JoinHandle<()>, ServerError> {
    let acceptor = tls::server::new_tls_acceptor(cert_file, key_file)?;
    let listener = TcpListener::bind(bind_address).await.map_err(|e| ServerError::BindError(e))?;
    info!("server bound at {}", bind_address);
    Ok(tokio::spawn(async move {
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
