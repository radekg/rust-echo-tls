use clap::{Parser, Subcommand};

mod tls;

use tokio::signal;

/// Simple TLS echo server/client
#[derive(Parser, Debug)]
#[clap(author = "Radek Gruchalski", version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
   #[clap(subcommand)]
   command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
   /// Starts a client
   Client {
      #[clap(long, value_parser, default_value = "localhost")]
      host: String,
      #[clap(long, value_parser, default_value_t = 5002)]
      port: u16,
      #[clap(long, value_parser)]
      tls_ca_certificate: String,
      #[clap(long, value_parser)]
      tls_certificate: String,
      #[clap(long, value_parser)]
      tls_key: String,
   },
   /// Starts a server
   Server {
      #[clap(long, value_parser, default_value = "127.0.0.1:5002")]
      bind_address: String,
      #[clap(long, value_parser)]
      tls_certificate_chain: String,
      #[clap(long, value_parser)]
      tls_key: String,
   },
}

#[tokio::main]
async fn main() {
   let args = Args::parse();
   match &args.command {
      Some(Commands::Client { host, port, tls_ca_certificate, tls_certificate, tls_key }) => {
         let msg = b"Hello world\n";
         let mut buf = [0; 12];
         tls::client::start_client(&host, *port, &tls_ca_certificate, &tls_certificate, &tls_key, msg, &mut buf).await;
         match std::str::from_utf8(&buf) {
            Ok(v) => {
               println!("Client received: {}", v)
            },
            Err(e) => {
               panic!("Invalid UTF-8 sequence: {}", e)
            },
        };
      }
      Some(Commands::Server { bind_address, tls_certificate_chain, tls_key }) => {
         println!("Starting the server...");
         tls::server::start_server(&bind_address, &tls_certificate_chain, &tls_key).await;
         match signal::ctrl_c().await {
            Ok(()) => {},
            Err(err) => {
                eprintln!("Unable to listen for shutdown signal: {}", err);
                // we also shut down in case of error
            },
         }
         println!("Server finished");
      }
      None =>
         println!("No command given")
   }
}
