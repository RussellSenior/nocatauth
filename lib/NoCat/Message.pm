package NoCat::Message;

use NoCat;
use IPC::Open2;
use strict;
use vars qw( @ISA *IN *OUT );

@ISA = 'NoCat';

sub text {
    my ( $self, $txt ) = @_;
    if ( defined $txt ) {
	$self->{Signed} = $self->{Verified} = 0;
	$self->{Msg} = $txt;
    }
    $self->{Msg}
}

sub sign {
    my ( $self, $txt ) = @_;

    return $self->text if $self->{Signed} and not defined $txt;
    $txt = $self->text( $txt );

    die "Can't find required MessageSign directive" unless $self->{MessageSign};
    my $cmd = $self->SUPER::format( $self->{MessageSign} );

    open2( \*IN, \*OUT, $cmd ) or die "$cmd: $!";
    print OUT $txt;
    close OUT;

    local $/ = undef;
    $txt = <IN>;
    close IN;

    $self->{Signed}++;
    $self->text( $txt );
    return $self;
}

sub verify {
    my ( $self, $txt ) = @_;

    return $self->text if $self->{Verified} and not defined $txt;
    $txt = $self->text( $txt );

    die "Can't find required MessageVerify directive" unless $self->{MessageVerify};
    my $cmd = $self->SUPER::format( $self->{MessageVerify} );
    my $kid = open OUT, "|-";

    if ( not defined $kid ) {
	die "$cmd: fork failure";
    } elsif ( not $kid ) {
	exec $cmd;
    }

    print OUT $txt;
    my $success = close OUT;
    $self->log( 1, "$cmd: $!" ) if $! and not $success;
    return $success;
}

sub extract {
    my $self = shift;
    my $txt = $self->text;

    if ( $txt =~ /-----BEGIN PGP SIGNED MESSAGE-----.*?\n\n(.*)-----BEGIN PGP SIGNATURE-----/os ) {
	return $1;
    } else {
	return $txt;
    }
}

sub parse {
    my ( $self, $text ) = @_;
    return $self->SUPER::parse( $self->extract( $text ) );
}

sub format {
    my ( $self, %args ) = @_;
    $self->text( $self->deparse( %args ) );
    return $self;
}

1;
