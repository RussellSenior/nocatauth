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

    $self->{Request} = {};
    $self->{User} = {};
    return $self;
}

sub run {
    my $self = shift;
    my @address;

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

    local $SIG{CHLD} = sub { wait };

    # Fork and handle connections as they come in.
    #
    my $fh = ""; vec( $fh, $server->fileno, 1 ) = 1;

    while ( 1 ) {
	# Spend some time waiting for something to happen.
	while (select( $fh, undef, undef, $self->{PollInterval} )) {
	    # A request!
    	    my $client = $server->accept;

	    $self->set_cookie( $client );

	    if ( my $pid = fork ) {
		next;
	    } elsif ( not defined $pid ) {
	        die "gateway server can't fork: $!";
	    } else {
		$server->close;
		$self->log( 8, "connection to " . $client->sockhost . " from " . $client->peerhost );
		$self->handle( $client );
		exit;
	    }
	}

	# If nothing happens, see if any logins have reached their timeout period.
	for my $user ( %{$self->{User}} ) {
	    $self->deny( $user ) if $self->{User}{$user} < time;
	} 
    }
}

sub handle {
    my ( $self, $socket ) = @_;
    
    # Get the HTTP header intro line.
    my $line = <$socket>;
    return $self->log( 6, "No header line from " . $socket->peerhost ) 
	if $line =~ /^\s*$/os;

    my ( $method, $uri, $http ) = split /\s+/, $line, 3;
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
	    $self->renew( $socket, $uri );
	} else {
	    $self->verify( $socket, $uri );
	}
    } else {
	$self->capture( $socket, "http://$head{Host}$uri" );
    }
}

sub verify {
    my ( $self, $socket, $uri ) = @_;
    my ( $content, $line );

    # $self->clear_cookie;

    $self->log( 8, "Received auth notification $uri from " . $socket->peerhost );

    print $socket "HTTP/1.1 304 No Response\n\n";
    $content .= $line while (defined( $line = <$socket> ));
    $socket->close;

    if ( my $expected_mac = delete $self->{Request}{$uri} ) {
	my $msg = $self->message;
	return $self->log( 2, "Invalid auth message!" ) unless $msg->verify( $content );

	$self->log( 9, "Got auth msg " . $msg->extract );

	my ( $cmd, $user, $mac ) = grep( $_ ne "", split( /\s+/, $msg->extract ) );
	return $self->log( 2, "Bad Request/MAC match!" ) if $expected_mac ne $mac;

	if ( $cmd eq "permit" ) {
	    $self->permit( $user, $mac );
        } elsif ( $cmd eq "deny" ) {
	    $self->deny( $user, $mac );
	}
    } else {
	$self->log( 2, "Non-existent auth request!" );
    }
}

sub permit {
    my ( $self, $user, $mac ) = @_;
    my $class = $self->classify( $user );

    $self->log( 5, "$user permitted in $class class" );
    $self->firewall->permit( $class, $mac );
    $self->{User}{$user} = time + $self->{LoginTimeout};
}

sub deny {
    my ( $self, $user, $mac ) = @_;
    my $class = $self->classify( $user );

    $self->log( 5, "$user denied from $class class" );
    $self->firewall->deny( $class, $mac );
    delete $self->{User}{$user};
}

sub classify {
    my ( $self, $user ) = @_;
    return grep( $user eq $_, $self->owners ) ? OWNER_CLASS : MEMBER_CLASS;
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
    my ( $self, $socket, $request ) = @_;
    $self->redirect( $socket, "request=" . $self->url_encode($request) )
}

sub renew {
    my ( $self, $socket, $query ) = @_;

    $query =~ s/^.*?\?//os;
    $self->redirect( $socket, "mode=renew&$query" );
}

sub set_cookie {
    my ( $self, $socket ) = @_;
    my $peer_ip  = $socket->peerhost or die "peerhost: $!";
    my $peer_mac = $self->firewall->fetch_mac( $peer_ip ); # or die "No MAC address for $peer_ip";

    if ( $peer_mac ) {
	$self->log( 7, "$peer_ip matches $peer_mac" );
    } else {
	return $self->log( 1, "Can't find MAC address for $peer_ip!" );
    }

    my $req_id = sprintf( "%x", int rand 0xFFFFFFFF );
    $self->log( 9, "$peer_ip gets cookie $req_id" );
    $self->{Request}{$req_id} = $peer_mac;
    $self->{Last_Request} = $req_id;
}

sub clear_cookie {
    my ( $self, $cookie ) = @_;
    delete $self->{Request}{ $cookie || $self->{Last_Request} };
}

sub redirect {
    my ( $self, $socket, $query ) = @_;

    my $peer_ip  = $socket->peerhost or die "peerhost: $!";
    $self->log( 7, "$peer_ip requests $query" );

    my $req_id	    = $self->{Last_Request};
    my $peer_mac    = $self->{Request}{$req_id};

    $peer_mac = $self->url_encode( $peer_mac );

    $socket->print( "HTTP/1.1 302 Moved\r\n" );
    $socket->print( "Location: $self->{AuthServiceURL}?reqid=$req_id&mac=$peer_mac&$query\r\n" );
    $socket->print( "\r\n* Your Message Here *\r\n" );
    $socket->close;

    $self->log( 9, "$peer_ip redirected to $self->{AuthServiceURL}" );
}

1;
