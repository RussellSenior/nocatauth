package NoCat::AuthService;

use NoCat;
use IO::Socket;
use strict;
use vars qw( @ISA );

@ISA = 'NoCat';

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

    # $gateway->shutdown( 1 ); # Done writing.
    shutdown( $gateway, 1 );

    # Throw away the gateway's HTTP header.
    $msg = "";
    $msg = <$gateway> until $msg =~ /^\s*$/os;
    
    # Parse the gateway's response.
    %args = $self->parse( <$gateway> );
    $gateway->close;

    return \%args;
}

sub renewal {
    my ( $self, $args )	= @_;
    my $cgi		= $self->cgi;
    my $mode		= $cgi->param("mode");
    my $timeout;    

    if ( $mode =~ /^login/io ) {
	$cgi->param( mode => "popup" );
    } else {
	$cgi->param( mode => "renew" );
    }

    if ( $args ) {
	$timeout = $args->{Timeout} || $self->{LoginTimeout};
	$cgi->param( token => $args->{Token} );
    } else {
	$timeout = $cgi->param( "timeout" ); 
    }

    $cgi->param( timeout => $timeout );

    if ( $mode =~ /^login/io ) {
	return $cgi->url( -query => 1 );
    } else {
	$timeout = int(( $timeout || $self->{LoginTimeout} ) / 2);
	return "$timeout; URL=" . $cgi->url( -query => 1 );
    }
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
