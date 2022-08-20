use clap::{Parser, Subcommand};
use log::{error, info, warn};
use tokio::signal;

mod tls;

/// Simple TLS echo server/client
#[derive(Parser, Debug)]
#[clap(author = "Radek Gruchalski", version, about, long_about = None)]
#[clap(propagate_version = true)]
struct AppArgs {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Starts a client
    Client {
        #[clap(long, env="HOST", default_value_t = String::from("localhost"))]
        host: String,
        #[clap(long, value_parser = clap::value_parser!(u16).range(1024..), env="PORT", default_value_t = 5002)]
        port: u16,
        #[clap(long, value_name = "FILE", env = "TLS_CA_CERTIFICATE")]
        tls_ca_certificate: String,
        #[clap(long, value_name = "FILE", env = "TLS_CERTIFICATE")]
        tls_certificate: String,
        #[clap(long, value_name = "FILE", env = "TLS_KEY")]
        tls_key: String,
    },
    /// Starts a server
    Server {
        #[clap(long, value_name = "HOST:PORT", env="BIND_ADDRESS", default_value_t = String::from("127.0.0.1:5002"))]
        bind_address: String,
        #[clap(long, value_name = "FILE", env = "TLS_CERTIFICATE_CHAIN")]
        tls_certificate_chain: String,
        #[clap(long, value_name = "FILE", env = "TLS_KEY")]
        tls_key: String,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = AppArgs::parse();

    match &args.command {
        Some(Commands::Client {
            host,
            port,
            tls_ca_certificate,
            tls_certificate,
            tls_key,
        }) => {
            let msg = b"Hello world\n";
            let mut buf = [0; 12];

            match tls::client::start_client(
                &host,
                *port,
                &tls_ca_certificate,
                &tls_certificate,
                &tls_key,
                msg,
                &mut buf,
            )
            .await
            {
                Ok(_) => {
                    match std::str::from_utf8(&buf) {
                        Ok(v) => {
                            info!("client fully echoed: {}", v)
                        }
                        Err(e) => {
                            error!("Invalid UTF-8 sequence: {}", e)
                        }
                    };
                }
                Err(reason) => {
                    error!("client failed, reason: {:?}", reason)
                }
            };
        }
        Some(Commands::Server {
            bind_address,
            tls_certificate_chain,
            tls_key,
        }) => {
            info!("starting the server");
            match tls::server::start_server(&bind_address, &tls_certificate_chain, &tls_key).await {
                Ok(_) => {
                    match signal::ctrl_c().await {
                        Ok(()) => {}
                        Err(err) => {
                            eprintln!("Unable to listen for shutdown signal: {}", err);
                            // we also shut down in case of error
                        }
                    }
                    info!("server finished, stopping")
                }
                Err(reason) => {
                    error!("server failed, reason: {:?}", reason)
                }
            };
        }
        None => warn!("no command, nothing to do"),
    }
}
