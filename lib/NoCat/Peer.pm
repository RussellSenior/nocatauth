package NoCat::Peer;

use NoCat qw( PUBLIC );
use strict;
use vars qw( @ISA @REQUIRED );

@REQUIRED   = qw( LoginTimeout );
@ISA	    = 'NoCat';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );
    
    $self->socket( $self->{Socket} ) if defined $self->{Socket};
    $self->status( "", "" ) unless defined $self->{Status};
    $self->timestamp;
    return $self;
}

sub socket {
    my ( $self, $sock ) = @_;
    if ( defined $sock ) {
	$self->{Socket} = $sock;
	$self->ip; # seed IP address.
    }
    return $self->{Socket};
}

sub ip {
    my ( $self, $ip ) = @_;
    $self->{IP} = $ip if defined $ip;

    unless ( defined $self->{IP} ) {
	if ( my $sock = $self->socket ) {
	    $self->{IP} = $sock->peerhost;
	} elsif ( my $mac = $self->{MAC} ) {
	    $self->{IP} = $self->firewall->fetch_ip( $mac );
	}
    }

    return $self->{IP};
}

sub mac {
    my ( $self, $mac ) = @_;
    $self->{MAC} = $mac if defined $mac;

    $self->{MAC} = $self->firewall->fetch_mac( $self->{IP} )
	if $self->{IP} and not defined $self->{MAC};

    return $self->{MAC};
}

sub timestamp {
    my ( $self, $reset ) = @_;
    $self->{Timestamp} = time + $self->{LoginTimeout} 
	if defined $reset or not defined $self->{Timestamp};
    return $self->{Timestamp};
}

sub expired {
    my $self = shift;
    return ( $self->timestamp < time );
}

sub token {
    my ( $self, $reset ) = @_;
    $self->{Token} = sprintf( "%x", int rand 0xFFFFFFFF )
        if defined $reset or not defined $self->{Token};
    return $self->{Token};
}

sub user {
    my ( $self, $user ) = @_;
    # $self->log( 9, "Peer::user called: $self=[$self->{User}] (@_)" );
    $self->{User} = $user if defined $user;
    return $self->{User};
}

sub status {
    my ( $self, $status ) = @_;
    $self->{Status} = $status if defined $status;
    return( $self->{Status} || "" );
}

sub class {
    my ( $self, $class, $user ) = @_;
    $self->{Class} = $class if defined $class;
    $self->user( $user ) if defined $user;
    return( $self->{Class} || PUBLIC );
}

1;
