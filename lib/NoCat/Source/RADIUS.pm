package NoCat::Source::RADIUS;

use NoCat::Source;
use Net::LDAP;
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( 
    RADIUS_Host RADIUS_Secret UserIDField 
);

sub radius {
    my ($self) = @_;

    unless ($self->{Radius}) {
        my $r = Authen::Radius->new(
	    Host	=> $self->{RADIUS_Host}, 
	    Secret	=> $self->{RADIUS_Secret}
	);
	if ($r) {
	    $self->{Radius} = $r;
	} else {
	    $self->log( 0, "Can't connect to RADIUS server $self->{RADIUS_Host}" );
	}
    }

    return $self->{Radius};
}

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $result = $self->radius->check_pwd($user, $user_pw);
    return $result;
}

sub fetch_user_by_id {
    my ( $self, $id )    = @_;    
    return { $self->{UserIDField} => $id };
}

# this is really a dummy function... if a user shows up, we'll call them
# a member of the magical ANY group for now.
#
sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    return { ANY => 0 };
}

1;

