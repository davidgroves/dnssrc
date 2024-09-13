[![minimum rustc: 1.64](https://img.shields.io/badge/minimum%20rustc-1.64-green?logo=rust)](https://www.whatrustisit.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

# DNSSRC

# Aims

Provide a DNS server testing how an upstream resolvers backend resolves names. This can be useful for multiple reasons including :-

- Diagnose CDN site selection for specific clients.
- Verifying the DNS Security position of that resolver.
  - Do they properly randomise source ports ?
  - Do they use DTLS or DoH for upstream requests ?
- Verify how many servers exist behind a load balanced client address.
- Verify Anycast is directing you to the correct nodes.

This tool was originally written in Perl, but has been rewritten in Rust for easier ongoing maintenence and the additon of new features.

# Building and Running DNSSRC.

## Do I need to ?

I run a public instance at `dnssrc.fibrecat.org`. Your needs may be met by simply using it. If you 
do not feel the need to run a local instance of the server, skip to the [Sending Queries](#Sending-Queries-to-DNSSRC.) section.

## How to Build.

If you have a working Rust environment, with a minimum Rust version of 1.64, you should be able to produce
working production binaries by downloading this git repo, and then running `cargo build --release` in the
base directory. Your binary will be located at `target/release/dnssrc`.

If you need to build a statically linked binary, you should read [David Vassallo's blog](https://blog.davidvassallo.me/2021/06/10/lessons-learned-building-statically-linked-rust-binaries-openssl/).

Builds are known to work on x86, amd64 and aarch64.

## How to Run.

Once you have produced binaries, you simply need to run it. The binary will be in the usual rust
location or `/target/release/dnssrc`.

## Setting options.

`dnssrc` accepts a set of options, either at the command line, or via environment variables.

You MUST specific a domain name, which it will listen to requests on. This domain must be
correctly delegated to the server via NS records in the parent domain for most operations.

Run `dnssrc --help` for a full list of options, and note the `[env: ]` section for the
environment variable options for these.

If you set both an environment variable and a command line option, the command line option
will take priority and the environment variable will be ignored.

## Listening on privileged ports.

If run as root, `dnssrc` will drop privileges as soon as it has bound the addresses. If you do not
specify, it will become `nobody/nogroup`.

Alternatively, on Linux systems, if you use setcap to give the ability to bind privilged ports
to the binary, it will work as expected. To do this, run `setcap 'cap_net_bind_service=+ep' /path/to/dnssrc`

## Simple Examples

- Listen on UDP, port 53, for IPv4 on localhost only.
  - `dnssrc --domain mydomain.com --udp 127.0.0.1:53 --foreground`
- Listen on UDP, port 53, for IPv4 on localhost only (using env variables)
  - `EXPORT DNSSRC_UDP_ADDR="127.0.0.1:53"; export DNSSRC_DOMAIN="mydomain.com"; export DNSSRC_FOREGROUND=True; dnssrc`
- Listen on TCP, port 53, for IPv6 on localhost only.
  - `dnssrc --domain mydomain.com --tcp6 [::1]:53  --foreground`
- Listen on UDP, port 53, on all interfaces.
  - `dnssrc --domain mydomain.com --udp 0.0.0.0:53 --foreground`
- Listen on UDP, port 53, on two interfaces. One with address 192.168.1.1 and the other with 192.168.2.1.
  - `dnssrc --domain mydomain.com --udp 192.168.1.1 --udp 192.168.2.1  --foreground`
- Listen on UDP port 53 for IPv4 on localhost only, and TCP port 443 for DNS over HTTPS on localhost only.
  - `dnssrc --domain mydomain.com --udp 127.1:53 --tcp6 [::1]:443  --foreground`

## Optional Extras
 - You can specify the nameserver records to use for the base zone with the `--ns_records` option.
   - `dnssrc --domain mydomain.com --udp 127.0.0.1:53 --ns_records ns0.mydomain.com ns1.mydomain.com --foreground`
 - You can specify the SOA names and values with the `--soa_names` and `--soa_values` options.
   - The first option to `soa_names` is the MNAME, the second is the RNAME.
   - The options to `soa_values` are the serial, refresh, retry, expire and minimum.
   - `dnssrc --domain mydomain.com --udp 127.0.0.1:53 --soa_names foo.mydomain.com bar.mydomain.com --soa_values 1 60 60 31356000 0 --foreground`

## TLS

For DNS over HTTPS `--doh / --doh6`, DNS over QUIC `--quic / --quic6` or DNS over TLS `--tls / --tls6`,
you must provide valid certificates.

You do so with the `--certfile` option to provide a PEM formatted certificate and `--keyfile` to provide a 4096 byte RSA key.

The script `gen_certs.sh` will produce these files signed by a local certificate authority it will also
produce in the `tls/` directory.

## Getting a letsencrypt certificate.

1. Install certbot from [lets-encrypt.org](https://letsencrypt.org/getting-started/) on your system.
1. Create directories for certbot to use. `mkdir certs; mkdir certs/config; mkdir certs/work; mkdir certs/logs`
1. Change to the `certs` directory with `cd certs`.
1. Run `certbot certonly --manual --preferred-challenges dns --server https://acme-v02.api.letsencrypt.org/directory --agree-tos --email you@example.com --domains ns0.dnssrc.fibrecat.org --work-dir work/ --logs-dir logs/ --config-dir config/`
1. Follow the instructions for configuring a TXT record on your domain, to prove you are a manager of it.
1. Convert the PEM formatted certificate to a seperate CRT and KEY file with `openssl x509 -outform der -in certificate.pem -out certificate.crt; openssl rsa -outform `



# Sending Queries to DNSSRC.

## What query names can dnssrc handle.

`dnssrc` will accept queries for the following records. If you are using the public instance, 
an example of the full name to use is `myip.dnssrc.fibrecat.org`

| Name      | Type    | Purpose                                                                       |
|---------  |---------|-------------------------------------------------------------------------------|
| myip      | A/AAAA  | Returns an A or AAAA record, of the source address of the incoming request.   |
| myport    | TXT     | Returns a TXT record with the source port of the incoming request.            |
| myaddr    | TXT     | Returns two TXT records, with both the source address and the source port.    |
| counter   | TXT     | Returns a counter that is incremented once with each request served.          |
| random    | A/AAAA/TXT     | Returns a random alphanumeric string. Useful for testing caching on clusters. |
| edns      | TXT     | Returns the EDNS client options on the incoming request.                      |
| edns-cs   | TXT     | Returns the EDNS-Client-Subnet option on the incoming request.                |
| timestamp | TXT     | Returns the current timestamp, in milliseconds from unix epoch, when the server got the request. TTL is still respected. |
| timestamp0 | TXT     | Returns the current timestamp, in milliseconds from unix epoch, when the server got the request. TTL is always set to zero. |


For example, if you invoked `dnssrc` running on 127.0.0.1:1053 for UDP requests with 
`dnssrc --domain mydomain.com --udp 127.0.0.1:1053 --foreground` and you wanted to confirm your requests to it came
from 127.0.0.1, you could run

```
$ dig +short -p 1053 @127.0.0.1 myip.mydomain.com
127.0.0.1
```

## How can I test more modern features, like DNS over QUIC

I strongly recommend the [kdig](https://www.knot-dns.cz/docs/latest/html/man_kdig.html) utility from the [knot-dns](https://www.knot-dns.cz/) team.

To get all the features, you will likely have to build a modern version from source. The version that
could be install from distribution packages on Ubuntu 24.04 and Debian 12 didn't have edns-client-subnet support,
nor support for DNS over QUIC. Debian Unstable (sid) has support though in `knot-dnsutils`.

For full support, I recommend installing at least version 3.2 from [knot-dns's github](https://github.com/CZ-NIC/knot), and when you configure it use `./configure --enable-quic=yes`

### Kdig examples
- DNS over HTTPS
  - `kdig -d -p 10443 +https +tls +tls-sni=dnssrc.fibrecat.org @127.1 myip.dnssrc.fibrecat.org`
- DNS over QUIC
  - `kdig -d -p 10443 +tls-sni=dnssrc.fibrecat.org +quic @127.1 myip.dnssrc.fibrecat.org`
- EDNS Data
  - `kdig -d TXT edns.dnssrc.fibrecat.org`
- EDNS Client Subnet
  - `kdig -d TXT edns-cs.dnssrc.fibrecat.org`
- Manually sending EDNS CS Data.
  - `kdig -d TXT edns-cs.dnssrc.fibrecat.org +edns-cs=127.0.0.1:53`

# How to contribute.

Pull requests happily accepted, particularly for open issues in the issue tracker.

Any other feedback, pls email me using my name (any variant) @ the domain used in the examples above.
Apologies for the less than simple instructions, but I'm trying to keep my inbox clean.

This is my first major bit of rust code, so it is likely to be somewhat non-ideomatic, and I
intend to revist this as I learn the language more.

# Known Bugs

- Background mode appears unreliable. More diagnosis needed.
- The public version running at dnssrc.fibrecat.org does not support DNS over HTTPS at current time.
- DNSSEC is not supported. The trust-dns library does not support dynamically signing records, and I'm not willing to implement this myself.
