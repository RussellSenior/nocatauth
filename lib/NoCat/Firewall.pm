package NoCat::Firewall;

use NoCat;
use strict;
use vars qw( @ISA *ARP );

@ISA = 'NoCat';

sub perform {
    my ( $self, $action, $opts ) = @_;

    # Action takes the form of "PermitPublic", "PermitMember", "PermitOwner", "DenyPublic", etc.
    #
    die "Can't find directive $action" unless $self->{$action};

    my $cmd = $self->parse( $self->{$action}, $opts );
    
    if ( my $pid = fork ) {
	exec $cmd;
	die "Firewall $action failure: $cmd returned $? ($!)"; # Can't happen.
    } elsif ( not defined $pid ) {
	die "Can't fork firewall $cmd: $!";
    }
}

sub permit {
    my ( $self, $class, $mac, $ip ) = @_;
    $ip ||= $self->fetch_ip( $mac );
    $self->perform( "Permit\u\L$class", { Class => $class, MAC => $mac, IP => $ip } );
}

sub deny {
    my ( $self, $class, $mac, $ip ) = @_;
    $ip ||= $self->fetch_ip( $mac );
    $self->perform( "DenyAccess", { Class => $class, MAC => $mac, IP => $ip } );
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
