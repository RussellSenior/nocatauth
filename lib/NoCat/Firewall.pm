package NoCat::Firewall;

use NoCat qw( PUBLIC );
use strict;
use vars qw( @ISA @REQUIRED *ARP );
use constant BY_MAC => 1;
use constant BY_IP  => 2;

@ISA	    = 'NoCat';
@REQUIRED   = qw(
    ResetCmd PermitCmd DenyCmd InternalDevice ExternalDevice LocalNetwork AuthServiceAddr 
);

# These config parameters get exported into the environment after a fork
# so that they can be passed to the relevant firewall scripts.
#
my @Perform_Export = qw( 
    InternalDevice ExternalDevice LocalNetwork AuthServiceAddr DNSAddr
    GatewayPort IncludePorts ExcludePorts
);

# If /proc/net/arp is available, use it. Otherwise, fork /sbin/arp and read
# its output to get ARP cache data. Turns out '/sbin/arp -an' gives the same output
# on both Linux and *BSD. (Thank goodness.)
#
my $Arp_Cache = ( -r "/proc/net/arp" ? "/proc/net/arp" : "/sbin/arp -an|" );

# Some basic networking-style regexp building blocks.
#
my $IP_Match  = '((?:\d{1,3}\.){3}\d{1,3})';		# match xxx.xxx.xxx.xxx
my $MAC_Match = '((?:[\da-f]{1,2}:){5}[\da-f]{1,2})';   # match xx:xx:xx:xx:xx:xx

sub perform {
    my ( $self, $action, $class, $mac, $ip ) = @_;

    $class  ||= PUBLIC;
    $ip	    ||= ( $mac ? $self->fetch_ip( $mac ) : "" );
    $mac    ||= ( $ip ? $self->fetch_mac( $ip )  : "" );

    my $cmd = $self->format( $self->{"\u${action}Cmd"}, { Class => $class || PUBLIC, MAC => $mac, IP => $ip } );
    
    if ( my $pid = fork ) { # Parent.
	return;
    } elsif ( defined $pid ) { # Child.
	$ENV{$_} = ( defined( $self->{$_} ) ? $self->{$_} : "" ) for @Perform_Export;
	exec $cmd;
	die "Firewall $action failure: $cmd returned $? ($!)"; # Can't happen.
    } elsif ( not defined $pid ) {
	die "Can't fork firewall $cmd: $!";
    }
}

sub reset {
    my $self = shift;
    $self->perform( Reset => @_ );
}

sub permit {
    my $self = shift;
    $self->perform( Permit => @_ );
}

sub deny {
    my $self = shift;
    $self->perform( Deny => @_ );
}

# fetch_arp_table, fetch_mac, and fetch_ip can be called as object methods *or* as class methods.

sub fetch_arp_table {
    my ( $self, $mode ) = @_;
    my %table;

    open( ARP, $Arp_Cache ) or die "Can't open arp table $Arp_Cache: $!";

    while ( <ARP> ) {
	next unless /^\?\s+\($IP_Match\)\s+at\s+$MAC_Match/io	 # Match /sbin/arp -an
	    or /^$IP_Match\s+(?:[0-9a-fx]+\s+){2}$MAC_Match/io;  # or match /proc/net/arp

	if ( $mode eq BY_IP ) {
	    $table{$1} = $2
	} else { # BY_MAC
	    $table{$2} = $1
	}
    }

    return \%table;
}

sub fetch_mac {
    my ( $self, $ip ) = @_;
    return unless $ip;
    return $self->fetch_arp_table( BY_IP )->{$ip};
}

sub fetch_ip {
    my ( $self, $hw ) = @_;
    require Carp;
    Carp::cluck "Undefined mac address" unless $hw;
    return $self->fetch_arp_table( BY_MAC )->{$hw};
}

1;
