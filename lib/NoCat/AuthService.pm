package NoCat::AuthService;

use NoCat qw( LOGOUT );
use IO::Socket;
use strict;
use vars qw( @ISA @REQUIRED );

@REQUIRED   = qw( GatewayPort NotifyTimeout LoginTimeout RenewTimeout );
@ISA	    = 'NoCat';

sub cgi {
    my $self = shift;
    require CGI;
    CGI->import( "-oldstyle_urls" ); # Thanks, Lincoln.
    return $self->{CGI} ||= CGI->new( @_ );
}

sub notify {
    my ( $self, $action, $data ) = @_;
    my %args = %$data; # 'cause we need to modify it.

    # Connect to the gateway.

    my $gateway_ip = $self->cgi->remote_host;
    my $gateway = IO::Socket::INET->new(
	PeerAddr    => $gateway_ip,
	PeerPort    => $self->{GatewayPort},
	Proto	    => "tcp",
	Timeout	    => $self->{NotifyTimeout}	
    );

    return $self->log( 4, "Notify gateway $gateway_ip:$self->{GatewayPort}: $!" )
	unless $gateway;

    # Capitalize all of the CGI variables, which are probably all lowercase.
    $args{ucfirst $_} = delete $args{$_} for keys %args;

    # We don't really want to send the user's password back. 
    delete @args{qw{ Pass Redirect }}; 

    $args{Action} = $action;

    # Format the arguments into a PGP signed message.
    my $msg = $self->message->format( %args )->sign;

    # Make an HTTP POST request.
    $gateway->print( "POST $args{Token} HTTP/1.1\n" );
    $gateway->print( "Host: $gateway_ip\n\n" );
    $gateway->print( $msg->text );
    $gateway->print( "\n\n" ); # EOF

    # Done writing.
    # $gateway->shutdown( 1 );
    shutdown( $gateway, 1 );  # IO::Socket::INET is broken in Perl 5.005?

    # Throw away the gateway's HTTP header.
    $msg = "";
    $msg = <$gateway> until $msg =~ /^\s*$/os;
    
    # Parse the gateway's response.
    %args = $self->parse( <$gateway> );
    $gateway->close;

    return \%args;
}

sub is_login {
    my $self = shift;
    return scalar( $self->cgi->param("mode") =~ /^(?:login|skip)/io );
}

sub renew_url {
    my ( $self, $args )	= @_;
    my $cgi		= $self->cgi;
    my $timeout;    

    # If there's arguments from a gateway response, use them.
    #
    if ( $args ) {
	$timeout = $args->{Timeout};
	$cgi->param( token => $args->{Token} );
    } else {
	$timeout = $cgi->param( "timeout" ); 
    }

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
    
    return "http://" . $cgi->remote_host . ":" . $self->{GatewayPort} . LOGOUT;
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

1;
