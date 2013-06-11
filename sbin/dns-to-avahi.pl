#!/usr/bin/perl -w -T

use strict;
use warnings;

$ENV{PATH} = "/bin:/usr/bin"; # Minimal PATH.

use Net::DNSServer;
use Net::DNSServer::Cache;
use Net::DNSServer::avahiResolver;

my %cache = ();

my $resolver1 = new Net::DNSServer::Cache({ dns_cache => \%cache });
my $resolver2 = new Net::DNSServer::avahiResolver;

#$Net::DNSServer::Cache::expiration_check = time;

run Net::DNSServer {
    priority => [$resolver1,$resolver2],
    server => { server_type => ['Single'] }, # Needed for Cache to work.
};  # Never returns

