package NoCat::Gateway::Captive;

use NoCat qw( PERMIT DENY LOGOUT );
use NoCat::Gateway;
use vars qw( @ISA @REQUIRED );
use strict;

@ISA	    = 'NoCat::Gateway';
@REQUIRED   = (
    @NoCat::Gateway::REQUIRED, 
    qw( TrustedGroups AuthServiceURL LogoutURL )
);

sub handle {
    my ( $self, $peer )	= @_;
    my $request		= $self->read_http_request( $peer ) or return;

    my $me = $peer->gateway_ip;
    $me .= ":" . $peer->socket->sockport if $request->{Host} =~ /:/o;

    # If this request is intended for us...
    if ( $request->{Host} eq $me ) {
	# Either it's a user asking to be logged out...
	if ( $request->{URI} eq LOGOUT ) {
	    $self->logout( $peer );

	# Or it's a user with an authentication ticket.
	# Re-capture them if we can't validate their ticket.
	} else {
	    $self->verify( $peer, $request->{URI} )
		or $self->capture( $peer, $request->{URL} );

	}

    # Otherwise, it's a user who needs to be captured and
    # sent to the auth service. 
    } else {
	$self->capture( $peer, $request->{URL} );
    }
}

sub punch_ticket {
    my ( $self, $msg, $mac ) = @_;
    my %auth	= $msg->parse;
    my $client	= $self->{Peer}{$mac} 
	or return $self->log( 2, "Unknown MAC notify from $mac!" );

    # TODO: better error reporting back to the auth service.
    return $self->log( 2, "Bad user/MAC match from $mac: $auth{User} != " . $client->user )
	if $client->user and $client->user ne $auth{User};
    return $self->log( 2, "Bad MAC match from $mac: $auth{Mac} != $mac" )
	if $mac ne $auth{Mac};
    return $self->log( 2, "Bad token match from $mac: $auth{Token} != " . $client->token )
	if $client->token ne $auth{Token};

    # Identify the user and class.
    $client->user( $auth{User} ); 
    $client->groups( $auth{Member} );

    # Store the new token away for when the peer renews its login.
    $client->token(1);

    # Perform the requested action.
    if ( $auth{Action} eq PERMIT ) {
	$self->permit( $client );
    } elsif ( $auth{Action} eq DENY ) {
	$self->deny( $client );
    }

    $self->log( 9, "Available MACs: @{[ keys %{$self->{Peer}} ]}" );

    return \%auth;
}

sub verify {
    my ( $self, $peer, $mac ) = @_;
    my ( $content, $line );
    my $socket = $peer->socket;

    $self->log( 8, "Received notify $mac from " . $socket->peerhost );

    $content .= $line while (defined( $line = <$socket> ));

    if ( my $client = $self->{Peer}{$mac} ) {
	my $msg = $self->message( $content );
	
	$msg->verify or return $self->log( 2, "Invalid auth message!" ); 
	$self->log( 9, "Got auth msg " . $msg->extract );

	if ($self->punch_ticket( $msg, $mac )) {
	    # Tell the auth service we got the message.
	    $msg = $self->deparse( 
		User    => $client->user, 
		Token   => $client->token, 
		Timeout => $self->{LoginTimeout} 
	    );
	    $self->log( 9, "Responding with:\n$msg" );
	    print $socket "HTTP/1.1 200 OK\n\n$msg";
	}
	
    } else {
	$self->log( 2, "Non-existent auth request!" );
	$self->log( 9, "Available MACs: @{[ keys %{$self->{Peer}} ]}" );
	print $socket "HTTP/1.1 400 Session Expired\n\n";
    }

    $socket->close;
}

sub logout {
    my ( $self, $peer ) = @_;
    my $sock = $peer->socket;
    my $url  = $self->format( $self->{LogoutURL} );

    $self->log( 5, "User " . ($peer->user || $peer->ip) . " logging out" );
    $self->deny( $peer );

    $self->redirect( $peer => $url );    
}

sub capture_params {
    my ( $self, $peer, $request ) = @_;
    return { 
	mac => $peer->mac, 
	token => $peer->token,
	redirect => $request,
	timeout => $self->{LoginTimeout}
    };
}

sub capture {
    my ( $self, $peer, $request ) = @_;
    my ( $mac, $token ) = $peer->mac;

    return $self->log( 3, "Can't capture peer ", $peer->ip, " without MAC" )
	unless $mac;

    $self->log( 7, "Capturing ", $peer->ip, " for $request" );
    
    # Remember the captured peer.	
    if ( my $original = $self->{Peer}{$mac} ) {
	# Actually, we've seen this one before. Reuse the token.
	$original->socket( $peer->socket );
	$peer = $original;
    } else {
	$self->add_peer( $peer );
    }

    # Smile for the GET URL.
    my $args = $self->capture_params( $peer, $request );
    my $url = $self->url( AuthServiceURL => $args );
    $self->redirect( $peer, $url );

    # Tell our parent we got the message.
    $self->notify_parent( Capture => $peer );
}

1;
