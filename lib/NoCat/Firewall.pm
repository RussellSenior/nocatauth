package NoCat::Firewall;

use NoCat qw( PUBLIC );
use strict;
use vars qw( @ISA @REQUIRED *ARP );
use constant BY_MAC	=> 1;
use constant BY_IP	=> 2;

@ISA	    = 'NoCat';
@REQUIRED   = qw( ResetCmd PermitCmd DenyCmd GatewayMode );

# These config parameters can (potentially) be determined dynamically.
my @Dynamic_Required = qw( InternalDevice ExternalDevice LocalNetwork );

# These config parameters get exported into the environment after a fork
# so that they can be passed to the relevant firewall scripts.
#
my @Perform_Export = qw( 
    InternalDevice ExternalDevice LocalNetwork AuthServiceAddr DNSAddr
    GatewayPort IncludePorts ExcludePorts AllowedWebHosts
);

# If /proc/net/arp is available, use it. Otherwise, fork /sbin/arp and read
# its output to get ARP cache data. Turns out '/sbin/arp -an' gives the same output
# on both Linux and *BSD. (Thank goodness.)
#
my $Arp_Cache = ( -r "/proc/net/arp" ? "/proc/net/arp" : "arp -an|" );
my $Ifconfig  = "ifconfig -a";
my $Netstat   = "netstat -rn";

# Some basic networking-style regexp building blocks.
#
my $IP_Match  = '((?:\d{1,3}\.){3}\d{1,3})';		# match xxx.xxx.xxx.xxx
my $MAC_Match = '((?:[\da-f]{1,2}:){5}[\da-f]{1,2})';   # match xx:xx:xx:xx:xx:xx

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new( @_ );
    
    $self->check_config( "AuthServiceAddr" ) 
	unless $self->{GatewayMode} and $self->{GatewayMode} eq "Open";

    unless ( grep($_, @$self{@Dynamic_Required}) == @Dynamic_Required ) {
	my %iface   = $self->interfaces;
	my $default = $self->default_route;

	# We're assuming that any interface that doesn't carry your default route
	# is an internal network.

	my $extern = $self->{ExternalDevice} ||= $default;
	my @intern = grep( $_ ne $extern, keys %iface );
	$self->{InternalDevice} ||= join(" ", @intern );
	$self->{LocalNetwork}   ||= @iface{ split /\s+/, $self->{InternalDevice} };

	$self->log( 7, "Detected $_ '$self->{$_}'" ) for @Dynamic_Required;
    }

    $self->check_config( @Dynamic_Required );
    return $self;
}

sub perform {
    my ( $self, $action, $class, $mac, $ip ) = @_;

    $class  ||= PUBLIC;
    $ip	    ||= ( $mac ? $self->fetch_ip( $mac ) : "" );
    $mac    ||= ( $ip ? $self->fetch_mac( $ip )  : "" );

    my $cmd = $self->format( $self->{"\u${action}Cmd"}, { Class => $class || PUBLIC, MAC => $mac, IP => $ip } );

    my %env = %ENV;
    local %ENV = %env;
    $ENV{$_} = ( defined( $self->{$_} ) ? $self->{$_} : "" ) for @Perform_Export;
    system $cmd;
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

sub arp_table {
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
    return $self->arp_table( BY_IP )->{$ip};
}

sub fetch_ip {
    my ( $self, $hw ) = @_;
    require Carp;
    Carp::cluck "Undefined mac address" unless $hw;
    return $self->arp_table( BY_MAC )->{$hw};
}

sub interfaces {
    my ( $self ) = @_;
    my ( $iface, $up, $network, $mask, %ifs );

    for (qx{ $Ifconfig }) {
	last unless defined $_;

	# If we got a new device, stash the previous one (if any).
	if ( /^([^\s:]+)/o ) {
	    $ifs{ $iface } = $network if $iface and $network and $up;
	    $iface = $1;
	    $up = 0;
	}

	# Get the network mask for the current interface.
	if ( /addr:$IP_Match.*?mask:$IP_Match/io ) {
	    # Linux style ifconfig.
	    $network = "$1/$2";
	} elsif ( /inet $IP_Match.*?mask 0x([a-f0-9]{8})/io ) {
	    # BSD style ifconfig.
	    $network = "$1/" . join(".", map( hex $_, split( /(..)/, $2 ) ));
	}

	# Ignore interfaces that are loopback devices or aren't up.
	$iface = "" if /\bLOOPBACK\b/o;
	$up++       if /\bUP\b/o;
    }
 
    if ( %ifs ) {
	return %ifs;
    } else {
	$self->log( 1, "Can't fetch network interface list with ifconfig: $!" );
	return;
    }
}

sub default_route {
    my ( $self ) = @_;
    
    for (qx{ $Netstat }) {
	# In both Linux and BSD, the interface is the last thing on the line.
	last unless defined $_;
	return $1 if /^(?:0.0.0.0|default)\s.*?(\S+)\s*$/o;
    }

    $self->log( 1, "Can't fetch default route with netstat: $!" );
    return;
}

1;
