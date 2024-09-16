#!/bin/bash

echo "Running Manual Tests. You need to have kdig installed, and dnssrc in your path."
echo ""
echo "Starting DNSSRC"
echo "==============="
echo ""
echo ""

dnssrc --domain test.example.com --udp 127.0.0.1:1053 --tcp 127.0.0.1:1053 \
       --udp6 "[::1]:1053" --tcp6 "[::1]:1053" --doh 127.0.0.1:8080 --doh6 "[::1]:8080" \
       --tls 127.0.0.1:8443 --tls6 "[::1]:8443" --quic 127.0.0.1:8443 \
       --quic6 "[::1]:8443" --ttl 5 --ns-records ns0.test.example.com ns1.test.example.com \
       --soa-values 1 2 3 4 5 --foreground 2>&1 >/dev/null &

sleep 1

echo "TEST1: A UDP4 query for myip.test.example.com"
EXPECTED="127.0.0.1"
VALUE=`kdig +short -p 1053 @127.0.0.1 A myip.test.example.com ` 
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST1 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST2: A UDP4 query for myip.test.example.com"
EXPECTED="::1"
VALUE=`kdig +short -p 1053 @::1 AAAA myip.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST2 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST3: A TCP4 query for myip.test.example.com"
EXPECTED="127.0.0.1"
VALUE=`kdig +tcp +short -p 1053 @127.0.0.1 A myip.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST3 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST4: A TCP6 query for myip.test.example.com"
EXPECTED="::1"
VALUE=`kdig +tcp +short -p 1053 @::1 AAAA myip.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST4 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST5: A UDP query for myport.test.example.com, forced from port 55555"
EXPECTED='"55555"'
VALUE=`kdig +short -b 127.0.0.1:55555 -p 1053 @127.0.0.1 A myport.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST5 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST6: A UDP query for myaddr.test.example.com, forced from port 44444"
EXPECTED='"127.0.0.1" "44444"'
VALUE=`kdig +short -b 127.0.0.1:44444 -p 1053 @127.0.0.1 A myaddr.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST6 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST7: A UDP query for myaddr.test.example.com, forced from port 44444"
EXPECTED='"127.0.0.1" "44444"'
VALUE=`kdig +short -b 127.0.0.1:44444 -p 1053 @127.0.0.1 A myaddr.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST7 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST8: A UDP query for edns.test.example.com"
EXPECTED='"version: 0 dnssec_ok: false max_payload: 1232 opts: 1"'
VALUE=`kdig +short +subnet="1.2.3.4/24" -p 1053 @127.0.0.1 TXT edns.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST8 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST9: A UDP A query for edns-cs.test.example.com"
EXPECTED='"1.2.3.0/24"'
VALUE=`kdig +short +subnet="1.2.3.4/24" -p 1053 @127.0.0.1 A edns-cs.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST9 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST10: A UDP6 AAAA query for edns-cs.test.example.com"
EXPECTED='"2001:db8::/64"'
VALUE=`kdig +short +subnet="2001:db8::4444:3333:2222:1111/64" -p 1053 @::1 AAAA edns-cs.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST10 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST11: A UDP6 AAAA query for edns-cs.test.example.com, but with IPv4 in the EDNS-CS Optionm"
EXPECTED='"192.0.2.0/24"'
VALUE=`kdig +short +subnet="192.0.2.100/24" -p 1053 @::1 AAAA edns-cs.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST11 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST12: A UDP HTTP/3 (QUIC) A query for myip.test.example.com"
EXPECTED='127.0.0.1'
VALUE=`kdig +quic +short -p 8443 @127.0.0.1 A myip.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST12 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST13: A UDP6 HTTP/3 (QUIC) AAAA query for myip.test.example.com"
EXPECTED='::1'
VALUE=`kdig +quic +short -p 8443 @::1 AAAA myip.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST13 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST14: A UDP AAAA query for counter.test.example.com"  
EXPECTED='"14"'
VALUE=`kdig +short -p 1053 @::1 AAAA counter.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST14 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo "TEST15: A TCP A query for counter.test.example.com"  
EXPECTED='"15"'
VALUE=`kdig +short -p 1053 @127.0.0.1 TXT counter.test.example.com`
if [ "$VALUE" != "$EXPECTED" ]; then
    echo "*** TEST15 FAILED: Expected $EXPECTED, got $VALUE"
fi

echo ""
echo "======================================================================="
echo "MANUAL TESTS: Inspect these by hand, as we can't automate the results."
echo "======================================================================="

echo "MANUAL TEST1: A UDP6 AAAA query for random.test.example.com, should print a random IPv6 address under this line"
kdig +quic +short -p 8443 @::1 AAAA random.test.example.com

echo "MANUAL TEST2: A UDP4 A query for random.test.example.com, should print a random IPv4 address under this line"
kdig +quic +short -p 8443 @127.0.0.1 A random.test.example.com

echo "MANUAL TEST3: A UDP4 TXT query for random.test.example.com, should print a random IPv4 string below this line"
kdig +quic +short -p 8443 @127.0.0.1 TXT random.test.example.com

echo ""
echo "======================================================================="
echo "Terminating DNSSRC"
killall dnssrc
