package NoCat::Firewall;

use NoCat qw( PUBLIC );
use strict;
use vars qw( @ISA @REQUIRED *ARP );

@REQUIRED   = qw( ResetCmd PermitCmd DenyCmd );
@ISA	    = 'NoCat';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );
    $self->{Peer} = {};
    return $self;
}

sub perform {
    my ( $self, $action, $opts ) = @_;

    $action = "${action}Cmd";
    die "Can't find directive $action" unless $self->{$action};

    my $cmd = $self->format( $self->{$action}, $opts );
    
    if ( my $pid = fork ) {
	return;
    } elsif ( defined $pid ) {
	exec $cmd;
	die "Firewall $action failure: $cmd returned $? ($!)"; # Can't happen.
    } elsif ( not defined $pid ) {
	die "Can't fork firewall $cmd: $!";
    }
}

sub reset {
    my $self = shift;
    
    # Disavow all prior knowledge.
    %{$self->{Peer}} = ();

    # Reset the firewall.
    $self->perform( Reset => {} );
}

sub permit {
    my ( $self, $class, $mac, $ip ) = @_;
    my $prior_class = $self->{Peer}{$mac};

    $ip ||= $self->fetch_ip( $mac );

    # Insert the rule for the new class of service...
    #
    $self->perform( Permit => { Class => $class, MAC => $mac, IP => $ip } );

    # *BEFORE* removing the rule for the *old* class of service. If any, naturally.
    # This way we don't drop packets for stateful connections in the event of service upgrade.
    #
    if ( $prior_class and $class ne $prior_class ) {
	$self->deny( $class, $mac, $ip );
	$self->log( 9, "Upgrading peer $mac from $prior_class to $class service." );
    }

    # Note the new class of service.
    #
    $self->{Peer}{$mac} = $class;
}

sub deny {
    my ( $self, $class, $mac, $ip ) = @_;
    my $prior_class = $self->{Peer}{$mac};

    $ip ||= $self->fetch_ip( $mac );

    # If no class is specified, strip any known class-of-service from the matching peer.
    #
    $class ||= $prior_class;

    # Note the removal of class-of-service if it matches the one we know about.
    #
    if ( $class and $prior_class and $prior_class eq $class ) {
	delete $self->{Peer}{$mac};
    } else {
	$self->log( 4, "Denying peer $mac without prior permit." );
    }

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
