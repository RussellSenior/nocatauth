package NoCat::AuthService;

use NoCat;
use IO::Socket;
use strict;
use vars qw( @ISA );

@ISA = 'NoCat';

sub cgi {
    my $self = shift;
    require CGI;
    return $self->{CGI} ||= CGI->new( @_ );
}

sub notify {
    my ( $self, $action, $user, $mac, $req_id ) = @_;

    my $gateway_ip = $self->cgi->remote_host;
    my $gateway = IO::Socket::INET->new(
	PeerAddr    => $gateway_ip,
	PeerPort    => $self->{GatewayPort},
	Proto	    => "tcp",
	Timeout	    => $self->{NotifyTimeout}	
    );

    return $self->log( 4, "Notify gateway $gateway_ip:$self->{GatewayPort}: $!" )
	unless $gateway;

    $action = lc $action;

    my $msg = $self->message;
    $msg->sign( "$action $user $mac" );

    $gateway->print( "POST $req_id HTTP/1.1\n" );
    $gateway->print( "Host: $gateway_ip\n" );
    $gateway->print( "\n" );
    $gateway->print( $msg->text );
    $gateway->close;
}

sub renewal_url {
    my ( $self, @args ) = @_;
    my ( %var, $query );    

    my $timeout	= int( $self->{LoginTimeout} / 2 );
    my $host	= $self->cgi->remote_host . ":$self->{GatewayPort}";

    $var{$_}	= $self->uri_encode( $self->cgi->param( $_ ) ) for ( @args );
    $query	= join("&", map( "$_=$var{$_}", @args ));
    
    return "$timeout; URL=http://$host/login?$query";
}

sub display {
    my ( $self, $form, $message ) = @_;
    my $cgi	= $self->cgi;
    my %vars	= ( $cgi->Vars, Message => $self->{$message} || $message || "", CGI => $cgi->url );

    print $cgi->header;

    if (my $form = $self->parse_file( $form, \%vars )) {
	print $form;
    } else {
	print "Error: Form $self->{$form} not found.";
    }

    exit;
}

1;
