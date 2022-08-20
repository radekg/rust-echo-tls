use std::fs::File;
use std::io::BufReader;

#[derive(Debug)]
pub enum TlsError {
    CaFileOpenError(std::io::Error),
    CaDerParseError(std::io::Error),
    CertFileOpenError(std::io::Error),
    CertDerParseError(std::io::Error),
    PrivateKeyEmptyError,
    PrivateKeyFileOpenError(std::io::Error),
    PrivateKeyIoError(std::io::Error),
    PrivateKeyUnsupportedError,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CaFileOpenError(e) => write!(f, "failed opening CA file: {:?}", e),
            Self::CaDerParseError(e) => write!(f, "failed reading DER certs from CA file: {:?}", e),
            Self::CertFileOpenError(e) => write!(f, "failed opening certificate file: {:?}", e),
            Self::CertDerParseError(e) => {
                write!(f, "failed reading DER certs from certificate file: {:?}", e)
            }
            Self::PrivateKeyEmptyError => write!(
                f,
                "no keys found in private key file (encrypted keys not supported)"
            ),
            Self::PrivateKeyFileOpenError(e) => {
                write!(f, "failed opening private key file: {:?}", e)
            }
            Self::PrivateKeyIoError(e) => write!(f, "failed reading private key file: {:?}", e),
            Self::PrivateKeyUnsupportedError => {
                write!(f, "unsupported key found in private key file")
            }
        }
    }
}

pub fn load_root_store(ca_file: &str) -> Result<rustls::RootCertStore, TlsError> {
    let cert_file = File::open(&ca_file).map_err(|e| TlsError::CaFileOpenError(e))?;
    let mut reader = BufReader::new(cert_file);
    let mut root_store = rustls::RootCertStore::empty();
    rustls_pemfile::certs(&mut reader).map_or_else(
        |e| Err(TlsError::CaDerParseError(e)),
        |der_certs| {
            root_store.add_parsable_certificates(&der_certs);
            Ok(root_store)
        },
    )
}

pub fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, TlsError> {
    let cert_file = File::open(filename).map_err(|e| TlsError::CertFileOpenError(e))?;
    let mut reader = BufReader::new(cert_file);
    rustls_pemfile::certs(&mut reader).map_or_else(
        |e| Err(TlsError::CertDerParseError(e)),
        |der_certs| {
            Ok(der_certs
                .iter()
                .map(|v| rustls::Certificate(v.clone()))
                .collect())
        },
    )
}

pub fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, TlsError> {
    let key_file = File::open(filename).map_err(|e| TlsError::PrivateKeyFileOpenError(e))?;
    let mut reader = BufReader::new(key_file);
    match rustls_pemfile::read_one(&mut reader) {
        Ok(Some(rustls_pemfile::Item::RSAKey(key))) => Ok(rustls::PrivateKey(key)),
        Ok(Some(rustls_pemfile::Item::PKCS8Key(key))) => Ok(rustls::PrivateKey(key)),
        Ok(Some(_)) => Err(TlsError::PrivateKeyUnsupportedError),
        Ok(None) => Err(TlsError::PrivateKeyEmptyError),
        Err(e) => Err(TlsError::PrivateKeyIoError(e)),
    }
}
