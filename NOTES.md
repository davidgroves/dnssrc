https://github.com/CZ-NIC/knot
 - Need > 3.2 of this for QUIC and TLS
 - Need to run with ./configure --enable-quic=yes
 
* DoH
kdig -d -p 10443 +https +tls +tls-sni=dnssrc.fibrecat.org @127.1 myip.dnssrc.fibrecat.org

* DNS over QUIC

kdig -d -p 10443 +tls-sni=dnssrc.fibrecat.org +quic @127.1 myip.dnssrc.fibrecat.org







