package NoCat::AuthService;

use NoCat qw( LOGOUT );
use IO::Socket;
use strict;
use vars qw( @ISA @REQUIRED );
use constant COOKIE_ID => "Login";

@ISA	    = 'NoCat';
@REQUIRED   = qw( 
    Database DB_User DB_Passwd GatewayPort NotifyTimeout
    LoginTimeout RenewTimeout HomePage 
);

sub cgi {
    my $self = shift;
    require CGI;
    CGI->import( "-oldstyle_urls" ); # Thanks, Lincoln.
    return $self->{CGI} ||= CGI->new( @_ );
}

sub set_cookie {
    my ( $self, $user ) = @_;
    my $cgi = $self->cgi;
    my $id  = $user->id;
    my $pw  = $user->passwd;
    
    return $self->log( 1, "Can't set cookie without username and password" )
	unless $id and $pw;

    # User cookies take the form <username>:<password>
    # and they're NEVER sent except over SSL.
    #
    # This is guaranteed to cause problems for people who are too lazy
    # to use an SSL cert on their auth service.
    #
    $self->{Cookie} = $cgi->cookie(
	-name	    => COOKIE_ID,
	-value	    => "$id:$pw",
	-path	    => "/",
	-domain	    => $cgi->virtual_host || $cgi->server_name,
	-secure	    => 1
    );
}

sub get_cookie {
    my ( $self ) = @_;
    my $cgi	 = $self->cgi;
    my $cookie	 = $cgi->cookie( COOKIE_ID ) or return;

    # See set_cookie(), above.
    #
    my ( $id, $pw ) = split( ":", $cookie );
    return unless $id and $pw;

    my $user	 = $self->user->fetch( $id ) or return;
    return unless $pw eq $user->passwd;

    return $user;
}

sub gateway_ip {
    my $self = shift;
    my $gw   = $self->cgi->remote_host;

    # If gateway is running on the same subnet as the auth server, the IP
    # of the client machine will be recieved instead of that of the gateway.
    # If LocalGateway is defined in nocat.conf, this block will check for
    # requests from the local subnet and set the gateway to that defined
    # in nocat.conf if one is found. 

    if ( $self->{LocalGateway} ) {
        require Net::Netmask;
        my $local_net = new Net::Netmask( $self->{LocalNetwork} );

	if ($local_net->match( $gw )) {
	    $self->log( 4, "Request from local ip $gw, " .
		"directing to local gateway $self->{LocalGateway}." );
	    return $self->{LocalGateway};
	}
    }

    return $gw;
}

sub message {
    my ( $self, $action, $data ) = @_;
    my %args = %$data; # 'cause we need to modify it.

    # Capitalize all of the CGI variables, which are probably all lowercase.
    $args{ucfirst lc $_} = delete $args{$_} for keys %args;

    # We don't really want to send the user's password back. 
    # (Or the address of the gateway, since it probably already knows it.)
    delete @args{qw{ Pass Gateway }}; 

    $args{Action} = $action;

    # Build a PGP message object from the arguments given.
    return $self->SUPER::message->format( %args );
}

sub notify {
    my ( $self, $action, $data ) = @_;

    # If we got a gateway argument, then the gateway is in passive mode
    # and is sending us its address so we can tell the client browser
    # where to send the authentication ticket we're about to give it.
    #
    # Otherwise, the gateway is in captive mode and wants us to contact
    # it directly.
    #
    if ( $data->{gateway} ) {
	$self->notify_via_client( $action, $data );
    } else {
	$self->notify_gateway( $action, $data );
    }
}

sub notify_via_client {
    my ( $self, $action, $data ) = @_;
    my $msg = $self->message( $action, $data )->encode;

    # Throw away the GPG header and footer, and then strip all the whitespace.
    #
    my ($tix) = ( $msg->text =~ /\n\n(.*?)\n-+/gos )
	or return $self->log( 1 =>
	 "GPG failure in passive notification from client $data->{Mac}" );

    $tix =~ s/\s//gos;
      
    # Take the ticket we've just made, and redirect the client to
    # send it to the gateway via GET request.
    # We're just given the address and port of the gateway, so
    # we have to add the http:// part.
    #
    $data->{redirect} = $self->url(
	"http://$data->{gateway}" => { ticket => $tix } );

    return $data;
}

sub notify_gateway {
    my ( $self, $action, $data ) = @_;

    # Connect to the gateway.
    my $gateway_ip = $self->gateway_ip;

    my $gateway = IO::Socket::INET->new(
	PeerAddr    => $gateway_ip,
	PeerPort    => $self->{GatewayPort},
	Proto	    => "tcp",
	Timeout	    => $self->{NotifyTimeout}	
    );

    return $self->log( 4, "Notify gateway $gateway_ip:$self->{GatewayPort}: $!" )
	unless $gateway;

    # Format the arguments into a PGP signed message.

    my $msg = $self->message( $action, $data )->sign;

    # Make an HTTP POST request of the auth message to the gateway.
    #
    $gateway->print( "POST $data->{mac} HTTP/1.1\n" );
    $gateway->print( "Host: $gateway_ip\n\n" );
    $gateway->print( $msg->text );
    $gateway->print( "\n\n" );

    # Done writing.
    # $gateway->shutdown( 1 );
    shutdown( $gateway, 1 ) # IO::Socket::INET is broken in Perl 5.005?
	or return $self->log( 4, "Shutdown gateway socket: $!" ); 

    # Get the response, then throw away the rest of the HTTP header.
    my ( $http, $code, $response ) = split /\s+/, scalar <$gateway>, 3;
    $http = <$gateway> until $http =~ /^\s*$/os;

    my %args;

    if ( $code == 200 ) { # HTTP OK
	# Parse the gateway's response.
	%args = $self->parse( <$gateway> );
    } else {
	# Save the error code.
	$self->log( 8, "Gateway returned $code ($response) for $data->{mac}." );
	$args{Error} = $code;
	$args{Message} = $response;
    }

    $gateway->close;

    return \%args;
}

sub is_login {
    my $self = shift;

    # If the "mode" CGI variable is "login" or "skip", we'll
    # consider this a login (versus, say, a renewal).

    my $mode = $self->cgi->param( "mode" ) || "";
    return scalar( $mode =~ /^(?:login|skip)/io );
}

sub renew_url {
    my ( $self, $args )	= @_;
    my $cgi		= $self->cgi;
    my $timeout;    

    # If there's arguments from a gateway response, use them.
    #
    if ( $args ) {
	$timeout = $args->{Timeout} || $args->{timeout};
	$cgi->param( token => $args->{Token} );
    } else {
	$timeout = $cgi->param( "timeout" ); 
    }

    $self->log( 6, "Don't know LoginTimeout in renew_url!" ) unless $timeout;

    $timeout ||= $self->{LoginTimeout};
    $cgi->param( timeout => $timeout );

    # Create a new popup box, or if we already have one, just refresh it.
    #
    if ( $self->is_login ) {
	$cgi->param( mode => "popup" );
	return $cgi->url( -query => 1 );
    } else {
	$cgi->param( mode => "renew" );
	$timeout = int( $timeout * $self->{RenewTimeout} );
	return "$timeout; URL=" . $cgi->url( -query => 1 );
    }
}

sub logout_url {
    my $self	= shift;
    my $cgi	= $self->cgi;
    
    my $gateway_ip = $self->gateway_ip;
    return "http://" . $gateway_ip . ":" . $self->{GatewayPort} . LOGOUT;
}

sub display {
    my ( $self, $form, $message ) = @_;
    my $cgi	= $self->cgi;
    my %vars	= ( $cgi->Vars, Message => $self->{$message} || $message || "", CGI => $cgi->url );

    print $cgi->header;

    if (my $form = $self->template( $form, \%vars )) {
	print $form;
    } else {
	print "Error: Form $self->{$form} not found.";
    }

    exit;
}

sub success {
    my ( $self, $form, $vars ) = @_;
    my @headers;    

    $vars ||= $self->cgi->Vars;

    my $redirect = ( $vars->{redirect} ||= $self->{HomePage} );

    # Add a refresh time of five seconds... unless one is already set.
    $redirect = "5; URL=$redirect" unless $redirect =~ /^\d+;/o;

    push @headers, -Refresh => $redirect;
    # push @headers, -Cookie => $self->{Cookie} if $self->{Cookie};

    # Hit the g/w with the ticket first if there is one, get a 304, 
    # then refresh the renewal link.
    push @headers, -Status => "302 Moved", -Location => $vars->{deliver_ticket}
	if $vars->{deliver_ticket};

    print $self->cgi->header( @headers ), $self->template( $form => $vars );
}

sub check_user {
    my $self = shift;
    my $cgi  = $self->cgi;
    my $user = $self->get_cookie;

    return $user if $user;

    my $base = $self->cgi->url(-full => 1, -path => 0);
    $base =~ s#/[^/]+##ios;
    
    print $cgi->header( -Refresh => "0; URL=$base/admlogin" );
    exit;
}

1;
