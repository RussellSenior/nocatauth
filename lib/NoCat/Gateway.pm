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

sub bind_socket {
    my $self = shift;
    my @address;

    return $self->{ListenSocket} if $self->{ListenSocket};

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

    $self->log( 0, "Can't bind to port $self->{GatewayPort}: $!. (Is another gateway already running?)" )
	unless $server;

    return( $self->{ListenSocket} = $server );
}

sub run {
    my $self	= shift;

    return unless $self->bind_socket;

    local $SIG{PIPE} = "IGNORE"; 

    # Handle connections as they come in.
    #
    while ( 1 ) {
	# Spend some time waiting for something to happen.
	$self->poll_socket;

	# See if any logins have reached their timeout period.
	$self->check_peers;

    } # loop forever
}

sub poll_socket {
    my $self	= shift;
    my $server	= $self->bind_socket;

    vec( my $fh = "", $server->fileno, 1 ) = 1;

    while (select( $fh, undef, undef, $self->{PollInterval} )) {
	# A request!
	my $sock	= $server->accept;
    	my $peer	= $self->peer( $sock );
    
	$self->log( 8, "Connection to " . $sock->sockhost . " from " . $sock->peerhost );
	$self->handle( $peer );
    }
}

sub check_peers { 
    my $self = shift;
    while ( my ($token, $peer) = each %{$self->{Peer}} ) {
	if ( $peer->expired ) {
	    $self->log( 8, "Expiring connection from ", $peer->ip, "." );
	    $self->deny( $peer );
	}
    }
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
	# my $own_addr = $socket->sockhost || "";
	# if ( $target_host eq $own_addr and $uri eq LOGOUT ) {
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
	$client->class( $auth{Class}, $auth{User} ); 

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

sub permit {
    my ( $self, $peer, $class ) = @_;

    $peer->timestamp(1);

    # Get *our* notion of what the peer's service class should be.
    #
    $class = $self->classify( $peer, $class );

    my $prior_class = $peer->status;

    if ( $prior_class ne $class ) {
	# Insert the rule for the new class of service...
	#
	$self->firewall->permit( $class, $peer->mac );
	
	# *BEFORE* removing the rule for the *old* class of service, if any.
	# This way we don't drop packets for stateful connections in the 
	# event of service upgrade.
	#
	if ( $prior_class and $prior_class ne DENY ) {
	    $self->log( 5, "Upgrading ", $peer->user, 
		" from $prior_class to $class service." );

	    $self->firewall->deny( $prior_class, $peer->mac );
	} else {
	    $self->log( 5, "User ", $peer->user, " permitted in class $class" );
	}

	$peer->status( $class );
    } else {
	$self->log( 5, "User ", $peer->user, " renewed in class $class" );
    }
}

sub deny {
    my ( $self, $peer ) = @_;
    my $mac	= $peer->mac or return; 

    # if we don't know the peer's MAC address, it must have been
    # an incidental connection (e.g. notification) that can be ignored.

    $peer = delete $self->{Peer}{$mac}
	or return $self->log( 4, "Denying unknown MAC address $mac?" );

    my $class	= $peer->status;

    return $self->log( 7, "Denying peer $mac without prior permit." )
	if not $class or $class eq DENY;

    $self->log( 5, "User ", ( $peer->user || $peer->ip ), " denied service." );

    $self->firewall->deny( $class, $mac ); 

    $peer->status( DENY );
}

sub classify {
    my ( $self, $peer, $class ) = @_;

    $class = $peer->class( $class );

    my $user = $peer->user;
    
    return OWNER if $user and grep( $user eq $_, $self->owners );
    return $class || PUBLIC;
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
    my ( $mac, $token ) = $peer->mac;

    return $self->log( 3, "Can't capture peer ", $peer->ip, " without MAC" )
	unless $mac;

    $self->log( 7, "Capturing ", $peer->ip, " for $request" );
    
    # Remember the captured peer.	
    if ( $self->{Peer}{$mac} ) {
	# Actually, we've seen this one before. Reuse the token.
	my $original = $self->{Peer}{$mac};
	$original->socket( $peer->socket );
	$peer = $original;
    } else {
	$self->{Peer}{$mac} = $peer;
    }

    # Smile for the GET URL.
    ( $token, $mac, $request ) = $self->url_encode( $peer->token, $mac, $request );

    $self->redirect( $peer, "$self->{AuthServiceURL}?token=$token&mac=$mac&redirect=$request" );
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
