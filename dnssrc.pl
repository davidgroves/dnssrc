#!/usr/bin/perl

# Copyright David Groves.
# This program is free software; you can redistribute it and/or modify it 
# under the same terms as Perl 5.14 itself.

use strict;
use warnings;
use Net::DNS::Header;
use Net::DNS::Nameserver;
use Net::DNS::RR::OPT;
use Net::Server::Daemonize qw(daemonize);
use Net::IP;
use String::Random;
use Time::HiRes;
use Data::Dumper;

sub reply_handler {
    my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
    my ( $rcode, @ans, @auth, @add );

#    print "Received query from $peerhost to " . $conn->{sockhost} . "\n";
#    $query->print;

    if ( $qtype eq "TXT" && $qname eq "dnssrc.fibrecat.org" ) {
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
	print $output;
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
    LocalAddr    => [ '2001:4db0:10:7::53', '85.236.110.130' ],
    LocalPort    => 53,
    ReplyHandler => \&reply_handler,
    Verbose      => 0
) || die "couldn't create nameserver object\n";

daemonize('nobody', 'nogroup', '/var/run/dnssrc.pid');
$ns->main_loop;
