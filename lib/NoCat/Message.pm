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

    open2( \*IN, \*OUT, $self->{MessageSign} ) or die "$self->{MessageSign}: $!";
    print OUT $txt;
    close OUT;

    local $/ = undef;
    $txt = <IN>;
    close IN;

    $self->{Signed}++;
    return $self->text( $txt );
}

sub verify {
    my ( $self, $txt ) = @_;

    return $self->text if $self->{Verified} and not defined $txt;
    $txt = $self->text( $txt );

    my $kid = open OUT, "|-";

    if ( not defined $kid ) {
	die "$self->{MessageVerify}: fork failure";
    } elsif ( not $kid ) {
	exec $self->{MessageVerify};
    }

    print OUT $txt;
    my $success = close OUT;
    $self->log( 1, "$self->{MessageVerify}: $!" ) if $! and not $success;
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
