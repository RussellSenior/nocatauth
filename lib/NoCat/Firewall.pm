package NoCat::Firewall;

use NoCat qw( PUBLIC );
use strict;
use vars qw( @ISA @REQUIRED *ARP );

@REQUIRED   = qw( ResetCmd PermitCmd DenyCmd );
@ISA	    = 'NoCat';

# These config parameters get exported into the environment after a fork
# so that they can be passed to the relevant firewall scripts.
#
my @Perform_Export = qw( 
    InternalDevice ExternalDevice LocalNetwork AuthServiceAddr DNSAddr 
);

sub perform {
    my ( $self, $action, $opts ) = @_;

    $action = "${action}Cmd";

    my $cmd = $self->format( $self->{$action}, $opts );
    
    if ( my $pid = fork ) {
	return;
    } elsif ( defined $pid ) {
	$ENV{$_} = $self->{$_} for @Perform_Export;
	exec $cmd;
	die "Firewall $action failure: $cmd returned $? ($!)"; # Can't happen.
    } elsif ( not defined $pid ) {
	die "Can't fork firewall $cmd: $!";
    }
}

sub reset {
    my $self = shift;
    
    # Reset the firewall.
    $self->perform( Reset => {} );
}

sub permit {
    my ( $self, $class, $mac, $ip ) = @_;
    my $prior_class = $self->{Peer}{$mac};

    $ip ||= $self->fetch_ip( $mac );

    $self->perform( Permit => { Class => $class, MAC => $mac, IP => $ip } );
}

sub deny {
    my ( $self, $class, $mac, $ip ) = @_;

    $ip ||= $self->fetch_ip( $mac );

    $self->perform( Deny => { Class => $class || PUBLIC, MAC => $mac, IP => $ip } );
}

sub _read_arp_table {
    open ARP, "</proc/net/arp" or die "Can't open arp table: $!";
    my $line = <ARP>; # throw away the header line.
    my @table;

    while (defined( $line = <ARP> )) {
	my %entry;    
	chomp $line;
	@entry{qw{ IP Type Flags HW Mask Device }} = split /\s+/, $line, 6;
	push @table, \%entry;
    }

    return @table;
}

sub fetch_mac {
    my ( $class, $ip ) = @_;
    for ( _read_arp_table ) {
	return $_->{HW} if $_->{IP} eq $ip;
    }
    return;
}

sub fetch_ip {
    my ( $class, $hw ) = @_;
    for ( _read_arp_table ) {
	return $_->{IP} if $_->{HW} eq $hw;
    }
    return;
}

1;
