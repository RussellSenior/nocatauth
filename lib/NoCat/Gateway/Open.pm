package NoCat::Gateway::Open;

use NoCat::Gateway qw( PERMIT DENY PUBLIC );
use vars qw( @ISA @REQUIRED );
use strict;

@ISA	    = 'NoCat::Gateway';
@REQUIRED   = ( @NoCat::Gateway::REQUIRED, qw( SplashForm ));

my %MIME = (
    jpg	    => "image/jpeg",
    jpeg    => "image/jpeg",
    gif	    => "image/gif",
    png	    => "image/png",
    ico     => "image/x-icon"
);

sub handle {
    my ( $self, $peer )	= @_;
    my $request		= $self->read_http_request( $peer ) or return;

    $self->log( 7, "Peer ", $peer->socket->peerhost, " requests $request->{Host}" );
    # $self->log( 9, "HTTP headers: @{[ %$request ]}" );

    # If this is a post request, it might be the auth service contacting us.
    # Otherwise, it must be a user, who needs to be sent to the auth service.
    #
    if ( $request->{Method} eq 'POST' ) {
	$self->verify ( $peer => $request );
    } elsif ( $request->{Host} eq $peer->socket->sockhost ) {
        if ( $request->{URI} eq "/" ) {
            $request->{URL} = $self->{HomePage};
            $self->capture( $peer => $request );
        } elsif ( $request->{URI} =~ /^\/\?redirect=([^&]+)/o ) {
            $request->{URL} = $self->url_decode( $1 );
            $self->splash( $peer => $request );
        } else {
            $self->serve( $peer => $request );
        }
    } else {
	$self->capture( $peer => $request ); 
    }
}

sub serve {
    my ( $self, $peer, $request ) = @_;

    my $file = "$self->{DocumentRoot}/$request->{URI}";
    $file =~ s/\.+/./gos; # Prevent ../ type whatnot.

    my $ext = ( $file =~ /([^\.\/]+)$/gos )[0]; # Try to get the file extension?
    $ext = $MIME{$ext};

    $self->log( 8, "Attempting to serve $file" );

    return $self->not_found( $peer => $request, 
	"Bad MIME type for $request->{URL}" )
	unless $ext;

    return $self->not_found( $peer => $request )
	unless -r $file and -f $file and my $size = -s $file;

    $peer->socket->print( 
	"HTTP 200 OK\r\n",
	"Content-type: $ext\r\n",
	"Content-length: $size\r\n\r\n",
	scalar $self->file( $file )
    );
    
    $peer->socket->close;
}

sub not_found {
    my ( $self, $peer, $request, $error ) = @_;

    $self->log( 2, $error || "Unable to satisfy GET $request->{URL}" );

    $peer->socket->print( 
	"HTTP 404 Not Found\r\n\r\n",
	"The requested item could not be found."
    );

    $peer->socket->close;
}

sub capture {
    my ( $self, $peer, $request ) = @_;
    my $host	= $peer->socket->sockhost;
    my $url	= $self->url_encode( $request->{URL} );

    $self->log( 8, "Capturing peer", $peer->socket->peerhost );
    $self->redirect( $peer => "http://$host/?redirect=$url" );
}

sub splash {
    my ( $self, $peer, $request ) = @_;
    my $socket = $peer->socket;
    
    $request->{action}	    = "http://" . $socket->sockhost . "/";
    $request->{redirect}    = $request->{URL};
 
    $self->log( 8, "Displaying splash page to peer", $peer->socket->peerhost );
    $peer->socket->print( 
	"HTTP/1.1 200 OK\r\n",
	"Content-type: text/html\r\n\r\n",
	$self->template( SplashForm => $request )
    );
    $peer->socket->close;
}

sub verify {
    my ( $self, $peer, $request ) = @_;
    my $socket = $peer->socket;
    my ( $line, $url );

    read( $socket, $line, $request->{"Content-length"} )
	or $self->log( 3, "Trouble reading from peer: $!" );

    $url = $self->url_decode( $1 )
	if $line =~ /(?:^|&)redirect=([^&]+)/o;
    
    if ( $url ) {
	$self->log( 5, "Opening portal for " . $socket->peerhost . " to $url" );
	$self->permit( $peer => PUBLIC );
	$self->redirect( $peer => $url ); 
    } else {
	$self->log( 5, "POST failed from " . $socket->peerhost );
	$self->capture( $peer => $request );
    }

}

1;
