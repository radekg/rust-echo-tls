use std::fs::File;
use std::io::BufReader;

pub fn load_root_store(ca_file: &str) -> rustls::RootCertStore {
    let cert_file = File::open(&ca_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(cert_file);
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    root_store
}

pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

pub fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }
    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}
