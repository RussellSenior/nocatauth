package NoCat::Gateway;

use IO::Socket;
use NoCat qw( PERMIT DENY PUBLIC MEMBER OWNER LOGOUT );
use vars qw( @ISA @REQUIRED *FILE );
use strict;

@ISA	    = 'NoCat';
@REQUIRED   = qw( 
    GatewayPort ListenQueue PollInterval LoginTimeout 
    AuthServiceURL LogoutURL 
);

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    $self->{Request} ||= {};
    $self->{Peer} ||= {};
    return $self;
}

sub firewall {
    # We need the firewall to be persistent for the duration of this session.
    my $self = shift;
    $self->{Firewall} = $self->SUPER::firewall(@_) unless $self->{Firewall};
    $self->{Firewall}
}

sub run {
    my $self = shift;
    my ( @address, $fh );

    # If no IP address is specified, try them all.
    if ( $self->{GatewayAddr} ) {
	@address = ( LocalAddr => $self->{GatewayAddr} );
    } else {
	@address = ( MultiHomed => 1 );
    }

    # Use a specified port if there is one.
    push @address, ( LocalPort => $self->{GatewayPort} ) 
	if $self->{GatewayPort};

    my $server = IO::Socket::INET->new(
	Listen	    => $self->{ListenQueue},
	Proto	    => "tcp",
	Reuse	    => 1,
	@address
    );

    # Does ctrl-c'ing the server make things hang next time we reload?
    # local $SIG{INT} = sub { $server->close if $server };
    local $SIG{PIPE} = "IGNORE"; 

    # Handle connections as they come in.
    #
    while ( 1 ) {
	# Spend some time waiting for something to happen.
	vec( $fh = "", $server->fileno, 1 ) = 1;

	while (select( $fh, undef, undef, $self->{PollInterval} )) {
	    # A request!
	    my $sock	= $server->accept;
    	    my $peer	= $self->peer( $sock );
    
	    # $self->{Peer}{ $peer->token } = $peer;

	    $self->log( 8, "Connection to " . $sock->sockhost . " from " . $sock->peerhost );
	    $self->handle( $peer );
	}

	# If nothing happens, see if any logins have reached their timeout period.
	while ( my ($token, $peer) = each %{$self->{Peer}} ) {
	    if ( $peer->expired ) {
		$self->log( 8, "Expiring connection from ", $peer->ip, "." );
		$self->deny( $peer );
	    }
	} 

    } # loop forever
}

sub handle {
    my ( $self, $peer ) = @_;
    my $socket = $peer->socket;    

    # Get the HTTP header intro line.
    my $line = <$socket>;
    return $self->log( 6, "No header line from " . $peer->ip ) 
	if not $line or $line =~ /^\s*$/os;

    my ( $method, $uri ) = split /\s+/, $line;
    my %head;

    $method ||= "GET";
    $uri    ||= "/";

    # Read the HTTP header fields.
    while (defined( $line = <$socket> )) {
	$line =~ s/^\s+|\s+$//gos;
	last unless length $line;
	my ( $key, $val ) = split /:\s+/, $line, 2;
	$head{$key} = $val;
    }

    # If this is a post request, it might be the auth service contacting us.
    # Otherwise, it must be a user, who needs to be sent to the auth service.
    #
    my $target_host = $head{Host} || ""; 

    if ( $method eq 'POST' ) {
	my $own_addr = $socket->sockhost || "";
	#if ( $target_host eq $own_addr and $uri eq LOGOUT ) {
	if ( $uri eq LOGOUT ) {
	    $self->logout( $peer );
	} else {
	    $self->verify( $peer, $uri );
	}
    } else {
	$self->capture( $peer, $target_host ? "http://$target_host$uri" : "" );
    }
}

sub verify {
    my ( $self, $peer, $token ) = @_;
    my ( $content, $line );
    my $socket = $peer->socket;

    $self->log( 8, "Received auth token $token from " . $socket->peerhost );

    $content .= $line while (defined( $line = <$socket> ));

    if ( my $client = delete $self->{Peer}{$token} ) {
	my $msg = $self->message( $content );

	return $self->log( 2, "Invalid auth message!" ) unless $msg->verify;
	$self->log( 9, "Got auth msg " . $msg->extract );

	my %auth = $msg->parse;

	# TODO: better error reporting back to the auth service.
	return $self->log( 2, "Bad user/token match: $auth{User} != " . $client->user )
	    if $client->user and $client->user ne $auth{User};
	return $self->log( 2, "Bad MAC/token match!" )	if $client->mac ne $auth{Mac};
	return $self->log( 2, "Bad token match!" )	if $token ne $auth{Token};

	# Identify the user and class.
	$client->class( $auth{Class}, $auth{User} ); 

	if ( $auth{Action} eq PERMIT ) {
	    $self->permit( $client );
        } elsif ( $auth{Action} eq DENY ) {
	    $self->deny( $client );
	}

	# Store the new token away for when the peer renews its login.
	$self->{Peer}{ $client->token(1) } = $client;
	$self->log( 8, "Available tokens: @{[ keys %{$self->{Peer}} ]}" );
	
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
	$self->log( 8, "Available tokens: @{[ keys %{$self->{Peer}} ]}" );
	print $socket "HTTP/1.1 400 Bad request\n\n";
    }

    $socket->close;
}

sub permit {
    my ( $self, $peer, $class ) = @_;

    $peer->timestamp(1);

    $class = $self->classify( $peer, $class );

    if ( $peer->status ne PERMIT ) {
	$self->log( 5, "User ", $peer->user, " permitted in class $class" );
	$self->firewall->permit( $class, $peer->mac );
	$peer->status( PERMIT );
    } else {
	$self->log( 5, "User ", $peer->user, " renewed in class $class" );
    }
}

sub deny {
    my ( $self, $peer ) = @_;

    delete $self->{Peer}{$peer->token};

    # if we don't know the peer's MAC address, it must have been
    # an incidental connection (e.g. notification) that can be ignored.
    #
    return unless $peer->mac; 

    $self->log( 5, "User ", ( $peer->user || $peer->ip ), " denied service." );

    $self->firewall->deny( "", $peer->mac ); 
	# Blank class-of-service means strip ANY available class.

    $peer->status( DENY );
}

sub classify {
    my ( $self, $peer, $class ) = @_;

    $class = $peer->class( $class );

    if ( $class eq OWNER or $class eq MEMBER ) {
	my $user = $peer->user;
	return grep( $user eq $_, $self->owners ) ? OWNER : MEMBER;
    } else {
	return PUBLIC;
    }
}

sub owners {
    my $self = shift;
    my @owners;
    
    return @{$self->{_OwnerList}} if $self->{_OwnerList};    

    # Owners directive.
    push @owners,  grep($_, split( /\s+/, $self->{Owners} )) if $self->{Owners};

    # Or perhaps listed per line in an OwnersFile.
    if ( $self->{OwnerFile} ) {
	open( FILE, "<$self->{OwnerFile}" ) 
	    or return $self->log( 1, "OwnerFile $self->{OwnerFile}: $!" );

	while ( <FILE> ) {
	    # Throw away leading/trailing space.
	    s/^\s+|\s+$//gios;
	    # Owner must start with an alphanumeric.
	    push @owners, $_ if /^\w+/o;
	}
	close FILE;
    }

    # This cache doesn't get reset, which means you have to restart the server 
    # if the list changes.
    $self->{_OwnerList} = \@owners;
    return @owners;
}

sub logout {
    my ( $self, $peer ) = @_;
    my $sock = $peer->socket;

    $self->log( 5, "User " . ($peer->user || $peer->ip) . " logging out" );
    $self->deny( $peer );

    $self->redirect( $peer => $self->{LogoutURL} );    
}

sub capture {
    my ( $self, $peer, $request ) = @_;
    my ( $peer_mac, $token );

    $self->log( 7, "Capturing ", $peer->ip, "for $request" );
    
    # Remember the captured peer.	
    $self->{Peer}{$peer->token} = $peer;

    # Smile for the GET URL.
    ( $peer_mac, $token, $request ) = $self->url_encode( $peer->mac, $peer->token, $request );

    $self->redirect( $peer, "$self->{AuthServiceURL}?token=$token&mac=$peer_mac&redirect=$request" );
}

sub redirect {
    my ( $self, $peer, $url ) = @_;

    $peer->socket->print( 
	"HTTP/1.1 302 Moved\r\n",
	"Location: $url\r\n",
	"\r\n* Your Message Here *\r\n" 
    );
    $peer->socket->close;
}

1
