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

    # If this is a post request, it might be the auth service contacting us.
    # Otherwise, it must be a user, who needs to be sent to the auth service.
    #
    if ( $request->{Method} eq 'POST' ) {
	# my $own_addr = $socket->sockhost || "";
	# if ( $target_host eq $own_addr and $uri eq LOGOUT ) {
	if ( $request->{URI} eq LOGOUT ) {
	    $self->logout( $peer );
	} else {
	    $self->verify( $peer, $request->{URI} );
	}
    } else {
	$self->capture( $peer, $request->{URL} );
    }
}

sub verify {
    my ( $self, $peer, $mac ) = @_;
    my ( $content, $line );
    my $socket = $peer->socket;

    $self->log( 8, "Received notify $mac from " . $socket->peerhost );

    $content .= $line while (defined( $line = <$socket> ));

    if ( my $client = $self->{Peer}{$mac} ) {
	my $msg = $self->message( $content );

	return $self->log( 2, "Invalid auth message!" ) unless $msg->verify;
	$self->log( 9, "Got auth msg " . $msg->extract );

	my %auth = $msg->parse;

	# TODO: better error reporting back to the auth service.
	return $self->log( 2, "Bad user/MAC match: $auth{User} != " . $client->user )
	    if $client->user and $client->user ne $auth{User};
	return $self->log( 2, "Bad MAC match!" )	if $mac ne $auth{Mac};
	return $self->log( 2, "Bad token match!" )	if $client->token ne $auth{Token};

	# Identify the user and class.
	$client->user( $auth{User} ); 
	$client->groups( $auth{Member} );

	# Perform the requested action.
	if ( $auth{Action} eq PERMIT ) {
	    $self->permit( $client );
        } elsif ( $auth{Action} eq DENY ) {
	    $self->deny( $client );
	}

	# Store the new token away for when the peer renews its login.
	$client->token(1);
	$self->log( 9, "Available MACs: @{[ keys %{$self->{Peer}} ]}" );
	
	# Tell the auth service we got the message.
	$msg = $self->deparse( 
	    User    => $client->user, 
	    Token   => $client->token, 
	    Timeout => $self->{LoginTimeout} 
	);
	$self->log( 9, "Responding with:\n$msg" );
	print $socket "HTTP/1.1 200 OK\n\n$msg";

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
	$self->{Peer}{$mac} = $peer;
    }

    # Smile for the GET URL.
    ( $token, $mac, $request ) = $self->url_encode( $peer->token, $mac, $request );

    my $url = $self->format( $self->{AuthServiceURL} );
    $self->redirect( $peer, "$url?token=$token&mac=$mac&redirect=$request" );
}

1;
