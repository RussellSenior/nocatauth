package NoCat::Gateway;

use IO::Socket;
use NoCat;

use constant PUBLIC_CLASS => "Public";
use constant MEMBER_CLASS => "Member";
use constant OWNER_CLASS  => "Owner";
use vars qw( @ISA *FILE );
use strict;

@ISA = 'NoCat';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    $self->{Request} ||= {};
    $self->{User} ||= {};
    return $self;
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

    # Handle connections as they come in.
    #
    while ( 1 ) {
	# Spend some time waiting for something to happen.
	vec( $fh = "", $server->fileno, 1 ) = 1;

	while (select( $fh, undef, undef, $self->{PollInterval} )) {
	    # A request!
	    my $sock	= $server->accept;
    	    my $peer	= $self->peer( $sock );
    
	    $self->{Peer}{ $peer->token } = $peer;

	    $self->log( 8, "Connection to " . $sock->sockhost . " from " . $sock->peerhost );
	    $self->handle( $peer );
	}

	# If nothing happens, see if any logins have reached their timeout period.
	while ( my ($token, $peer) = each %{$self->{Peer}} ) {
	    $self->deny( $peer ) if $peer->expired;
	} 

    } # loop forever
}

sub handle {
    my ( $self, $peer ) = @_;
    my $socket = $peer->socket;    

    # Get the HTTP header intro line.
    my $line = <$socket>;
    return $self->log( 6, "No header line from " . $peer->ip ) 
	if $line =~ /^\s*$/os;

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
    if ( $method eq 'POST' ) {
	# if ( $head{Host} and $head{Host} eq $socket->sockhost and $uri =~ m|^/login|o ) {
	if ( $uri =~ m|^/login|o ) {
	    $self->renew( $peer, $uri );
	} else {
	    $self->verify( $peer, $uri );
	}
    } else {
	$self->capture( $peer, "http://$head{Host}$uri" );
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
	return $self->log( 2, "Bad user/token match!" )
	    if $client->user and $client->user ne $auth{User};
	return $self->log( 2, "Bad MAC/token match!" )	if $client->mac ne $auth{Mac};
	return $self->log( 2, "Bad token match!" )	if $token ne $auth{Token};

	$client->status( $auth{Class}, $auth{User} ); 

	if ( $auth{Action} =~ /^permit/io ) {
	    $self->permit( $client );
        } elsif ( $auth{Action}  =~ /^deny/io ) {
	    $self->deny( $client );
	}

	$self->{Peer}{ $client->token(1) } = $client;
	$self->log( 8, "Available tokens: @{[ keys %{$self->{Peer}} ]}" );
	
	$msg = $self->deparse( 
	    User    => $client->user, 
	    Token   => $client->token, 
	    Timeout => $self->{LoginTimeout} 
	);
	$self->log( 9, "Responding with $msg" );
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

    $class = $self->classify( $peer, $class );

    $self->log( 5, "User ", $peer->user, " permitted in class $class" );
    $self->firewall->permit( $class, $peer->mac );

    $peer->timestamp(1);
}

sub deny {
    my ( $self, $peer ) = @_;
		
    my $class = $self->classify( $peer );

    $peer->status( "deny" );
    delete $self->{Peer}{$peer->token};

    if ( $peer->status eq "permit" ) {
	$self->log( 5, "User ", $peer->user, " permitted in class $class" );
	$self->firewall->deny( $class, $peer->mac );
    }
}

sub classify {
    my ( $self, $peer, $class ) = @_;

    $class = $peer->status( $class );

    if ( $class =~ /^(member|owner)/io ) {
	my $user = $peer->user;
	return grep( $user eq $_, $self->owners ) ? OWNER_CLASS : MEMBER_CLASS;
    } else {
	return PUBLIC_CLASS;
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

sub capture {
    my ( $self, $peer, $request ) = @_;
    $self->redirect( $peer, "redirect=" . $self->url_encode($request) )
}

sub renew {
    my ( $self, $peer, $query ) = @_;

    $query =~ s/^.*?\?//os;
    $self->redirect( $peer, "mode=renew&$query" );
}

sub redirect {
    my ( $self, $peer, $query ) = @_;
    my ( $peer_mac, $token ) = $self->url_encode( $peer->mac, $peer->token );

    $self->log( 7, "Redirecting ", $peer->ip, "query $query to $self->{AuthServiceURL}" );

    $peer->socket->print( 
	"HTTP/1.1 302 Moved\r\n",
	"Location: $self->{AuthServiceURL}?token=$token&mac=$peer_mac&$query\r\n",
	"\r\n* Your Message Here *\r\n" 
    );
    $peer->socket->close;
}

1
