use anyhow::Result;
use clap::Parser;
use daemonize::Daemonize;
use handler::{Handler};
use options::Options;
use privdrop::PrivDrop;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod handler;
mod options;

#[link(name = "c")]
extern "C" {
    fn geteuid() -> u32;
}

pub fn read_cert(
    cert_path: &std::path::Path,
) -> trust_dns_server::proto::error::ProtoResult<Vec<rustls::Certificate>> {
    let mut cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("error opening cert file: {cert_path:?}: {e}"))?;

    let mut reader = std::io::BufReader::new(&mut cert_file);
    if let Ok(certs) = rustls_pemfile::certs(&mut reader) {
        Ok(certs.into_iter().map(rustls::Certificate).collect())
    } else {
        Err(trust_dns_server::proto::error::ProtoError::from(format!(
            "failed to read certs from: {}",
            cert_path.display()
        )))
    }
}

pub fn read_key(
    path: &std::path::Path,
) -> trust_dns_server::proto::error::ProtoResult<rustls::PrivateKey> {
    let mut file = std::io::BufReader::new(std::fs::File::open(path)?);

    loop {
        match rustls_pemfile::read_one(&mut file)? {
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(_) => continue,
            None => return Err(format!("no keys available in: {}", path.display()).into()),
        };
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let options = Options::parse();
    let handler = Handler::from_options(&options);
    let mut server = ServerFuture::new(handler);

    for udp in &options.udp {
        server.register_socket(UdpSocket::bind(udp).await?);
    }

    for tcp in &options.tcp {
        server.register_listener(
            TcpListener::bind(&tcp).await?,
            Duration::from_secs(options.tcptimeout),
        );
    }

    for udp6 in &options.udp6 {
        server.register_socket(UdpSocket::bind(udp6).await?);
    }

    for tcp6 in &options.tcp6 {
        server.register_listener(
            TcpListener::bind(&tcp6).await?,
            Duration::from_secs(options.tcptimeout),
        );
    }

    for doh in &options.doh {
        let _ = server.register_https_listener(
            TcpListener::bind(doh).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
            options.domain.clone(),
        );
    }

    for doh6 in &options.doh6 {
        let _ = server.register_https_listener(
            TcpListener::bind(doh6).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
            options.domain.clone(),
        );
    }

    for tls in &options.tls {
        let _ = server.register_tls_listener(
            TcpListener::bind(tls).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
        );
    }

    for tls6 in &options.tls6 {
        let _ = server.register_tls_listener(
            TcpListener::bind(tls6).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
        );
    }

    for quic in &options.quic {
        let _ = server.register_quic_listener(
            UdpSocket::bind(quic).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
            options.domain.clone(),
        );
    }

    for quic6 in &options.quic6 {
        let _ = server.register_quic_listener(
            UdpSocket::bind(quic6).await?,
            Duration::from_secs(options.tcptimeout),
            (
                read_cert(std::path::Path::new(&options.certfile.clone())).unwrap(),
                read_key(std::path::Path::new(&options.keyfile.clone())).unwrap(),
            ),
            options.domain.clone(),
        );
    }
    
    // Drop privileges if I'm run as root.
    let mut running_as_root = false;
    unsafe {
        if geteuid() == 0 {
            running_as_root = true;
        }
    }

    if running_as_root {
        PrivDrop::default()
            .user(options.user)
            .group(options.group)
            .apply()
            .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));
    }

    match options.foreground {
        true => {
            // run the server code in the foreground
            let _ = server.block_until_done().await;
        },
        false => {
            // daemonize before running
            let daemon = Daemonize::new();
            let res = daemon.start();
            match res {
                Ok(_) => println!("Started dnssrc as pid: {}", std::process::id()),
                Err(e) => println!("Couldn't daemonize: {}", e),
            }
            let _ = server.block_until_done().await;
        }
    }
    Ok(())
}
