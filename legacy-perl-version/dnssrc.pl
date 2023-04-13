#!/usr/bin/perl

# Copyright 2014, David Groves

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the “Software”), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished
# to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use strict;
use warnings;
use Net::DNS::Header;
use Net::DNS::Nameserver;
use Net::DNS::RR::OPT;
use Net::Server::Daemonize qw(daemonize);
use Net::IP;
use Net::IPAddress 'num2ip';
use Net::IPv6Addr 'to_bigint';
use Math::BigInt;
use String::Random;
use Time::HiRes;
use Data::Dumper;

sub reply_handler {
    my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
    my ( $rcode, @ans, @auth, @add );
    
    if ( $qtype eq "A" && $qname eq "dnssrca.fibrecat.org" ) {
        if ( index($peerhost, ":") != -1) {
            # The reply is IPv6, we need to do the special thing
            my $foo = Net::IPv6Addr->new ($peerhost)->to_bigint;
            my $foobin = $foo->to_bin();
            $foobin=~s/^0b//g;
            my @bar = unpack("(A32)*", $foobin);

            foreach (@bar) {
                my $unpacked = unpack("N", pack("B32", substr("0" x 32 . $_, -32))) . "\n";
                my $lip = num2ip($unpacked);
                my ( $ttl, $rdata ) = ( 0, $lip);
                my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
                push @ans, $rr;
            }
            $rcode = "NOERROR";
        }
        else {
            my ( $ttl, $rdata ) = ( 0, $peerhost );
            my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
            push @ans, $rr;
            $rcode = "NOERROR";
        }
    }
    elsif ((( $qtype eq "TXT") || ( $qtype eq "A" )) && $qname eq "dnssrc.fibrecat.org" ) {
        my ( $ttl, $rdata ) = ( 0, $peerhost );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnsrandom.fibrecat.org" ) {
        my ( $ttl, $rdata ) = ( 5, int( rand(65535) ) );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnstimestamp.fibrecat.org" ) {
        my ( $ttl, $rdata ) = ( 0, Time::HiRes::time );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnsport.fibrecat.org" ) {
        my ( $ttl, $rdata ) = ( 0, $conn->{"peerport"} );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnssock.fibrecat.org" ) {
        my $output = $peerhost . "." . $conn->{"peerport"};
        my ( $ttl, $rdata ) = ( 0, $output );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnsportandid.fibrecat.org" ) {
        my $output = "Port: " . $conn->{"peerport"} . " DNSID: " . $query->header->id;
        my ( $ttl, $rdata ) = ( 0, $output );
        my $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }
    elsif ( $qtype eq "TXT" && $qname eq "dnsclientsubnet.fibrecat.org" ) {
        if ( $query->additional ) {
            my ( $code, $len, $family, $source_netmask, $scope_netmask, @ip ) =
              unpack 'nnnCCC*', ( $query->additional )[0]->rdata;
            if ( $code == 20730 ) {
                my $ip;
                if ( $family == 1 ) {
                    $ip = join '.', @ip;
                }
                if ( $family == 2 ) {
                    my $cnt = 0;
                    foreach (@ip) {
                        $ip .= sprintf( "%x", $_ );
                        if ( ++$cnt % 2 == 0 ) {
                            $ip .= ':' if $cnt <= 15;
                        }
                    }
                    my $printip = new Net::IP($ip);
                    $ip = $printip->short();

                    #$ip = join ':', map {sprintf("%x",$_)} @ip;
                }
                my $output =
                    "SourceNetmask "
                  . $source_netmask
                  . " ScopeNetmask "
                  . $scope_netmask
                  . " ClientSubnet "
                  . $ip;
                my ( $ttl, $rdata ) = ( 0, $output );
                my $rr =
                  new Net::DNS::RR("$qname $ttl $qclass $qtype \"$rdata\"");
                push @ans, $rr;
                $rcode = "NOERROR";
            }
        }
    }
    else {
        $rcode = "SERVFAIL";
    }

    # mark the answer as authoritive (by setting the 'aa' flag
    return ( $rcode, \@ans, \@auth, \@add, { aa => 1 } );
}

my $ns = new Net::DNS::Nameserver(
    LocalAddr    => [ '51.89.165.88', '2001:41d0:801:2000::2944' ],
    LocalPort    => 53,
    ReplyHandler => \&reply_handler,
    Verbose      => 0
) || die "couldn't create nameserver object\n";

daemonize('nobody', 'nogroup', '/var/run/dnssrc.pid');
$ns->main_loop;