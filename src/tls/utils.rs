use std::fs::File;
use std::io::BufReader;

use log::{error};

pub fn load_root_store(ca_file: &str) -> Option<rustls::RootCertStore> {
    File::open(&ca_file).map_or_else(|e| {
        error!("failed opening CA file: {:?}", e);
        None
    }, |cert_file| {
        let mut reader = BufReader::new(cert_file);
        let mut root_store = rustls::RootCertStore::empty();
        rustls_pemfile::certs(&mut reader).map_or_else(|e| {
            error!("failed reading DER certs from CA file: {:?}", e);
            None
        }, |der_certs| {
            root_store.add_parsable_certificates(&der_certs);
            Some(root_store)
        })
    })
}

pub fn load_certs(filename: &str) -> Option<Vec<rustls::Certificate>> {
    File::open(filename).map_or_else(|e| {
        error!("failed opening certificate file: {:?}", e);
        None
    }, |cert_file| {
        let mut reader = BufReader::new(cert_file);
        rustls_pemfile::certs(&mut reader).map_or_else(|e| {
            error!("failed reading DER certs from certificate file: {:?}", e);
            None
        }, |der_certs| {
            Some(der_certs.iter()
                .map(|v| rustls::Certificate(v.clone()))
                .collect())
        })
    })
}

pub fn load_private_key(filename: &str) -> Option<rustls::PrivateKey> {
    File::open(filename).map_or_else(|e| {
        error!("failed opening key file: {:?}", e);
        None
    }, |key_file| {
        let mut reader = BufReader::new(key_file);
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::RSAKey(key))) => {
                Some(rustls::PrivateKey(key))
            }
            Ok(Some(rustls_pemfile::Item::PKCS8Key(key))) => {
                Some(rustls::PrivateKey(key))
            }
            Ok(Some(_)) => {
                error!("unsupported pem file item found in {:?}", filename);
                None
            }
            Ok(None) => {
                error!("no keys found in {:?} (encrypted keys not supported)", filename);
                None
            }
            Err(e) => {
                error!("failed reading private key from file: {:?}", e);
                None
            }
        }
    })
}
