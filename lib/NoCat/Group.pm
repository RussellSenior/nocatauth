package NoCat::Group;

use NoCat;
use strict;
use vars qw( @REQUIRED @ISA );

@ISA	    = 'NoCat';

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new( @_ );

    $self->{Users}  ||= {};
    $self->{Former} ||= {};
    
    return $self;
}

sub source {
    my $self = shift;
    $self->{Source} ||= $self->SUPER::source( @_ );
    return $self->{Source};
}

sub id {
    my $self = shift;
    $self->{Name} = shift if @_;
    return $self->{Name};
}

sub users {
    my $self = shift;
    return $self->{Users};
}

sub create {
    my ( $self, $id ) = @_;
    $self->id( $id ) if $id;
    return $self;
}

sub fetch {
    my ( $self, $id ) = @_;
    $self->id( $id ) if $id;

    my $users = $self->source->fetch_users_by_group( $self->id );
    if ( $users ) {
	%{$self->{Former}} = %{$self->{Users}} = %$users;
    } 
    return $self;
}

sub store {
    my $self	= shift;
    my $group	= $self->id;
    my $member	= $self->{Users};
    my $former	= $self->{Former};

    while ( my ($user, $status) = each %$member ) {
	if ( exists $former->{$user} ) {
	    if (  $former->{$user} ne $status ) {
		$self->source->update_group_member( $group, $user, $status );
		$former->{$user} = $status;
	    }
	} else {
	    $self->source->add_group_member( $group, $user, $status );
	}
    }

    while ( my ($user, $status) = each %$former ) {
	$self->source->drop_group_member( $group, $user )
	    unless exists $member->{$user};
    }
    
    %$former = %$member;
    return scalar keys %$member;
}

sub add {
    my ( $self, $user, $admin ) = @_;
    $self->{Users}{$user->id} = $admin || 0;
    return $self;
}

sub drop {
    my ( $self, $user ) = @_;
    delete $self->{Users}{$user->id};
    return $self;
}

1;
