use clap::{ArgGroup, Parser};
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
#[clap(author = "David Groves", version, about = "A DNS server for testing")]
#[command(group(
    ArgGroup::new("socket")
        .args(["udp", "udp6", "tcp", "tcp6", "doh", "doh6", "tls", "tls6", "quic", "quic6"])
        .multiple(true)
        .required(true)
))]
#[command(group(
    ArgGroup::new("records")
        .args(["ns_records", "soa_names"])
        .multiple(true)
        .required(true)
))]

pub struct Options {
    // UDP socket to listen on.
    #[clap(long, env = "DNSSRC_UDP_ADDR")]
    #[arg(group = "socket")]
    pub udp: Vec<SocketAddr>,

    // TCP socket to listen on.
    #[clap(long, env = "DNSSRC_TCP_ADDR")]
    #[arg(group = "socket")]
    pub tcp: Vec<SocketAddr>,

    // UDP socket to listen on.
    #[clap(long, env = "DNSSRC_UDP6_ADDR")]
    #[arg(group = "socket")]
    pub udp6: Vec<SocketAddr>,

    // TCP socket to listen on.
    #[clap(long, env = "DNSSRC_TCP6_ADDR")]
    #[arg(group = "socket")]
    pub tcp6: Vec<SocketAddr>,

    // TCP4 socket to listen on for DNS over HTTPS
    #[clap(long, env = "DNSSRC_DOH_TCP_ADDR")]
    #[arg(group = "socket")]
    pub doh: Vec<SocketAddr>,

    // TCP6 socket to listen on for DNS over HTTPS
    #[clap(long, env = "DNSSRC_DOH_TCP6_ADDR")]
    #[arg(group = "socket")]
    pub doh6: Vec<SocketAddr>,

    // TCP4 socket to listen on for DNS over HTTPS
    #[clap(long, env = "DNSSRC_TLS_TCP_ADDR")]
    #[arg(group = "socket")]
    pub tls: Vec<SocketAddr>,

    // TCP6 socket to listen on for DNS over HTTPS
    #[clap(long, env = "DNSSRC_TLS_TCP6_ADDR")]
    #[arg(group = "socket")]
    pub tls6: Vec<SocketAddr>,

    // UDP for QUIC
    #[clap(long, env = "DNSSRC_QUIC_ADDR")]
    #[arg(group = "socket")]
    pub quic: Vec<SocketAddr>,

    // UDP4 for QUIC
    #[clap(long, env = "DNSSRC_QUIC6_ADDR")]
    #[arg(group = "socket")]
    pub quic6: Vec<SocketAddr>,

    // Domain name.
    #[clap(long, env = "DNSSRC_DOMAIN")]
    pub domain: String,

    // Domain name.
    #[clap(long, env = "DNSSRC_TTL", default_value = "1")]
    pub ttl: u32,

    // What user to run as.
    #[clap(long, env = "DNSSRC_USER", default_value = "nobody")]
    pub user: String,

    // What group to run as.
    #[clap(long, env = "DNSSRC_GROUP", default_value = "nogroup")]
    pub group: String,

    // TCP timeout.
    #[clap(long, default_value = "2", env = "DNSSRC_TCP_TIMEOUT")]
    pub tcptimeout: u64,

    // TLS cerfificate.
    #[clap(long, env = "DNSSRC_CERT", default_value = "tls/cert.pem")]
    pub certfile: String,

    // TLS cerfificate.
    #[clap(long, env = "DNSSRC_PEM", default_value = "tls/cert.key")]
    pub keyfile: String,

    // Force Foreground
    #[clap(long, env = "DNSSRC_FOREGROUND")]
    pub foreground: bool,

    // NS records
    #[clap(long, env = "NS_RECORDS")]
    #[arg(num_args(0..))]
    pub ns_records: Vec<String>,

    // SOA Names
    #[clap(long, env = "SOA_NAMES")]
    #[arg(num_args(0..))]
    pub soa_names: Vec<String>,
}
