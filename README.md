# Rust Tokio TLS server/client

A TLS server/client playground in Rust with `tokio`.

## Certificates

Install `cfssl`:

- on macOS: `brew install cfssl`

Generate CA and certificates:

```sh
./ca/genca.sh
```

This will generate a root CA certificate, intermediate CA certificate, server certificate, and a client certificate for use on `localhost`. The default CA name (_a directory representing the namespace where certificates are stored_), is `rs`. Once everything is generated, verify:

```sh
tree ca/rs/out/
```

```
ca/rs/out/
├── rs-client-key.pem
├── rs-client.pem
├── rs-intermediate-key.pem
├── rs-intermediate.pem
├── rs-key.pem
├── rs-server-chain.pem
├── rs-server-key.pem
├── rs-server.pem
├── rs-trust-chain.pem
└── rs.pem
```

## Start the server

```sh
cargo run -- server \
    --tls-certificate-chain "$(pwd)/ca/rs/out/rs-server-chain.pem" \
    --tls-key "$(pwd)/ca/rs/out/rs-server-key.pem"
```

## Start the client

```sh
cargo run -- client \
    --tls-ca-certificate "$(pwd)/ca/rs/out/rs-trust-chain.pem" \
    --tls-certificate "$(pwd)/ca/rs/out/rs-client.pem" \
    --tls-key "$(pwd)/ca/rs/out/rs-client-key.pem"
```
