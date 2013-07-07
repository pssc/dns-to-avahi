package Net::DNSServer::avahiResolver;

use 5.010000;
use strict;
use warnings;

use Exporter;
use Net::DNSServer::Base;
use Net::DNS::Packet;
use IPC::Cmd qw(can_run run);
use Carp qw(carp croak cluck);
use Socket;

our $VERSION = '0.01';

use vars qw(@ISA);
@ISA = qw(Net::DNSServer::Base);

my $default_ttl = 60;
my $default_dom = "local";
my $default_avahi = "avahi-resolve";
my $default_child = 'DEFAULT';

# Created and passed to Net::DNSServer->run()
sub new {
  my $class = shift || __PACKAGE__;
  my $self  = shift || {};

  $self->{avahi} = can_run($default_avahi) or warn "$default_avahi is not installed!";
  $self->{ttl} ||= $default_ttl;
  $self->{dom} ||= $default_dom;
  $self->{child} ||= $default_child;
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
		print STDERR "DEBUG: Resloving via $self->{avahi} ".$question->qname."\n";
      		my $response = bless \%{$dns_packet}, "Net::DNS::Packet"
        	|| die "Could not initialize response packet";

		my @args =( $self->{avahi} );
		my $qname = $question->qname;
		if ($question->qtype eq "PTR") {
			#146.1.168.192.in-addr.arpa.
			if ($qname =~ /^([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)\.in-addr\.arpa$/) {
				$qname = "$4.$3.$2.$1";
			} else {
        			print STDERR "Bad data in query name '$qname'\n"; # log this somewhere
			}
			
			push @args, ( "-4a" , $qname);
		} else {
			if ($qname =~ /^([-\@\w.]+)$/) {
        			$qname = $1;
    			} else {
        			print STDERR "Bad data in query name '$qname'\n"; # log this somewhere
    			}
			push @args, ( "-4n" , $qname);
		}
		
		$SIG{'CHLD'} = $self->{child}; # Reset Child Signal handler as we as work round for Single ie non forking Multi mode needed for a simple cache.
		my ($ok,$err,$full,$output, $error) = run (command => \@args);

		if (!$ok) {
			print STDERR "$self->{avahi} exit $?:$err $!\n";
			return undef
		}

		if ($#$full < 0) {
			print STDERR "$self->{avahi} no output\n";
			# FIXME check error
			return undef
		}

		my $answer;

		foreach my $line (@$full) {
			chomp($line);
			my @result = split(/\s+/,$line);
			if ($#result == 1 and $result[0] eq $qname) {
				$answer = $result[1];
				### FIXME check IP.. || name..
				last;
			} else {
				print STDERR "DEBUG: $self->{avahi} '$line':$#result\n";
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
        		$response_header->qr(1); # This is a response
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

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::DNSServer::avahiResolver - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Net::DNSServer::avahiResolver;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Net::DNSServer::avahiResolver, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

phill, E<lt>pc188@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by phill

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
