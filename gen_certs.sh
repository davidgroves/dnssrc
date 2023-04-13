# !/usr/bin/env bash

set -e

OPENSSL=/usr/bin/openssl

TLSDIR=tls/
if [ -d ${TLSDIR} ]; then
    echo "Directory ${TLSDIR} already exists. Aborting."
    exit 1
fi

echo "Creating ${TLSDIR}"
mkdir ${TLSDIR}
pushd $TLSDIR

for i in ca.key ca.pem cert.key cert.csr cert.pem cert.p12 ; do
    [ -f $i ] && echo "$i exists" && exit 1;
done

echo 

cat <<-EOF > /tmp/ca.conf
[req]
prompt = no
req_extensions = req_ext
distinguished_name = dn

[dn]
C = GB
ST = Scotland
L = Glasgow
O = DNSSRC
CN = root.fibrecat.org

[req_ext]
basicConstraints = critical,CA:TRUE
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = root.fibrecat.org
EOF

# CA
echo "----> Generating CA <----"
${OPENSSL:?} req -x509 -new -nodes -newkey rsa:4096 -days 365 -keyout ca.key -out ca.pem -config /tmp/ca.conf
${OPENSSL:?} x509 -in ca.pem -out ca.der -outform der  

cat <<-EOF > /tmp/cert.conf
[req]
prompt = no
req_extensions = req_ext
distinguished_name = dn

[dn]

C = GB
ST = Scotland
L = Glasgow
O = DNSSRC
CN = dnssrc.fibrecat.org

[req_ext]

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = ns0.dnssrc.fibrecat.org
DNS.2 = ns1.dnssrc.fibrecat.org
DNS.3 = myip.dnssrc.fibrecat.org
DNS.4 = myaddr.dnssrc.fibrecat.org
DNS.5 = myport.dnssrc.fibrecat.org
DNS.6 = count.dnssrc.fibrecat.org
DNS.7 = random.dnssrc.fibrecat.org
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Cert
echo "----> Generating CERT  <----"
${OPENSSL:?} req -new -nodes -newkey rsa:4096 -keyout cert.key -out cert.csr \
             -verify \
             -config /tmp/cert.conf
${OPENSSL:?} x509 -in ca.pem -inform pem -pubkey -noout > ca.pubkey

echo "----> Signing Cert <----"
${OPENSSL:?} x509 -req -days 365 -in cert.csr -CA ca.pem -CAkey ca.key  -set_serial 0x8771f7bdee982fa6 -out cert.pem -extfile /tmp/cert.conf -extensions req_ext

echo "----> Verifying Cert <----"
${OPENSSL:?} verify -CAfile ca.pem cert.pem

echo "----> Create PCKS12 <----"
${OPENSSL:?} pkcs12 -export -inkey cert.key -in cert.pem -out cert.p12 -passout pass:mypass -name ns.example.com -chain -CAfile ca.pem

popd