package NoCat::Source;

use NoCat;
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = 'NoCat';
@REQUIRED   = qw( DataSource );

my @API_Methods = qw(
    create_user
    store_user

    fetch_user_by_id
    fetch_users_by_group
    fetch_groups_by_user

    add_group_member
    drop_group_member
    update_group_member
);

sub _virtual {
    my ($self, $func) = @_;

    require Carp;
    Carp::croak( ref($self), " does not implement a $func method" );
}

for my $method ( @API_Methods ) {
    no strict 'refs';
    *{__PACKAGE__ . "::$method"} = sub { _virtual($_[0], $method) };
}

sub new {
    my $self	= shift;
    my $class	= ref( $self ) || $self;

    if ( $class eq __PACKAGE__ ) {
	return $self->instantiate( "DataSource", @_ );
    } else {
	return $self->SUPER::new( @_ );
    }
}

1;
