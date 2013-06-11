package Net::DNSServer::avahiResolver;

use strict;
use warnings;

use Exporter;
use Net::DNSServer::Base;
use Net::DNS::Packet;
use IPC::System::Simple qw(capturex $EXITVAL EXIT_ANY);
use Carp qw(carp croak cluck);
use Socket;



use vars qw(@ISA);
@ISA = qw(Net::DNSServer::Base);

my $default_ttl = 60;
my $default_dom = "local";

# Created and passed to Net::DNSServer->run()
sub new {
  my $class = shift || __PACKAGE__;
  my $self  = shift || {};
  $self->{ttl} ||= $default_ttl;
  $self->{dom} ||= $default_dom;
  $self->{nameservers} ||= do {
    # Determine me and my corresponding name server by default
    local $^W = 0;
    eval {
      require Sys::Hostname;
    } or croak "Sys::Hostname and Socket must be installed if default_nameservers is not passed";
    my ($ns1, $ns2, $myIP);
    $ns1 = Sys::Hostname::hostname()
      or die "Cannot determine hostname";
    $ns2 = $ns1;
    if ( $ns1 =~ /(^[\.]).*$/ ) {
		$ns1 = $1.".".$self->{dom};
    }
    # Forward lookup reslove via avahi? FIXME?
    $myIP = (gethostbyname($ns1))[4] or $myIP = (gethostbyname($ns2))[4]
      or die "Cannot resolve both [$ns1,$ns2]";

    [ inet_ntoa($myIP) ];
  };

  return bless $self, $class;
}

# resolve subroutine must be defined
sub resolve {
    my $self = shift;
    my $dns_packet = $self->{question};
    my ($question) = $dns_packet->question();
    if ($question->qtype eq "A" || $question->qtype eq "PTR") {
        if ($question->qname =~ /\.$self->{dom}$/ || $question->qname =~ /\.in-addr\.arpa$/ || /^$self->{dom}$/) { 
		print STDERR "DEBUG: Resloving via avahi-resolve ".$question->qname."\n";
      		my $response = bless \%{$dns_packet}, "Net::DNS::Packet"
        	|| die "Could not initialize response packet";

		my @args =();
		my $qname = $question->qname;
		if ($question->qtype eq "PTR") {
			#146.1.168.192.in-addr.arpa.
			if ($qname =~ /^([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)\.in-addr\.arpa$/) {
				$qname = "$4.$3.$2.$1";
			} else {
        			print STDERR "Bad data in query name '$qname'\n"; # log this somewhere
			}
			
			@args = ( "-4a" , $qname);
		} else {
			if ($qname =~ /^([-\@\w.]+)$/) {
        			$qname = $1;
    			} else {
        			print STDERR "Bad data in query name '$qname'\n"; # log this somewhere
    			}
			@args = ( "-4n" , $qname);
		}
		
		$SIG{'CHLD'} = 'DEFAULT'; # for Multi Single mode
		my @output = capturex(EXIT_ANY, "avahi-resolve", @args );

		if ($EXITVAL != 0) {
			print STDERR "avahi-resolve exit $?:$EXITVAL $!\n";
			return undef
		}

		if ($#output < 0) {
			print STDERR "avahi-resolve no output\n";
			return undef
		}

		my $answer;

		foreach my $line (@output) {
			chomp($line);
			my @result = split(/\s+/,$line);
			if ($#result == 1 and $result[0] eq $qname) {
				$answer = $result[1];
				### FIXME check IP.. || name..
				last;
			} else {
				print STDERR "DEBUG: avahi-resolve '$line':$#result\n";
			}
		}
		
		if ($answer) {
      			$response->push("answer",
                      		Net::DNS::RR->new
                       		("$qname $self->{ttl} $question->{qtype} $answer"));
			# Needed for cache to work
			my $n = 0;
			foreach my $ns (@{$self->{nameservers}}) {
			
      				$response->push("authority",
                       			Net::DNS::RR->new
                       			("$self->{dom} $self->{ttl} NS ns$n.$self->{dom}"));
      				$response->push("additional",
                       			Net::DNS::RR->new 
                       			("ns$n.$self->{dom} $self->{ttl} A $ns"));
					$n++;
			}
      			my $response_header = $response->header;
      			$response_header->aa(1); # Make Authoritative
	     		return $response;
		} else {
			print STDERR "DEBUG: avahi-resolve failed ".$question->qname."\n";
		}
	} else {
      		print STDERR "DEBUG: Non matching query ".$question->qname. " <> $self->{dom} || .in-addr.arpa\n";
	}
    } else { 
      	print STDERR "DEBUG: Non A/PTR record Ignored ($question->{qtype})\n";
    }
    return undef;
}

