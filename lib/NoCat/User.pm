package NoCat::User;

use NoCat;
use Digest::MD5 qw( md5_base64 );
use strict;
use vars qw( @REQUIRED @ISA );

@ISA	    = 'NoCat';
@REQUIRED   = qw( UserIDField UserPasswdField );

# new() instantiates a new NoCat::User object and returns it. 
# You'll probably want to use NoCat->user() to call this for you.
# Use ->set() and/or ->fetch() to actually populate the object returned.
#
sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    $self->{Data}   ||= {};
    
    if ( my $new_pw = $self->passwd ) {
	$self->set_password( $new_pw );
    } 
    return $self;
}

sub source {
    my $self = shift;
    $self->{Source} ||= $self->SUPER::source( @_ );
    return $self->{Source};
}

# set() takes a hash of values to set within the NoCat::User object.
# Cleartext passwords are automatically MD5 hashed.
#
sub set {
    my ( $self, %user ) = @_;
    for ( keys %user ) {
	$self->{Data}{$_} = $user{$_};
	$self->set_password( $user{$_} ) if $_ eq $self->{UserPasswdField};
    }
    return $self;   
}

# set_password() MD5-hashes a password and sets the password field to it.
#
sub set_password {
    my ( $self, $new_pw ) = @_;
    $self->{Data}{$self->{UserPasswdField}} = md5_base64( $new_pw );
    return $self->{Data};   
}

# data() returns a hash containing the values of the User object. 
# Don't modify this hash, please.
#
sub data {
    my $self = shift;
    return $self->{Data};
}

# id() returns the unique user ID from the User object.
#
sub id {
    my $self = shift;
    $self->{Data}{ $self->{UserIDField} } = shift if @_;
    return $self->{Data}{ $self->{UserIDField} };
}

# passwd() returns the (hopefully hashed) password from the User object.
#
sub passwd {
    my $self = shift;
    $self->set_password( @_ ) if @_;
    return $self->{Data}{ $self->{UserPasswdField} };
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create {
    my $self = shift;
    $self->source->create_user( $self );
    return $self;
}

# fetch() retrieves an existing NoCat::User object from the database.
# fetch() takes a hash containing field/value pairs to match against existing objects, and
#    returns the first one it finds.
#
#    $user->fetch( $user->{UserIDField} => "Foo" ); 
#      ... is probably the logical way to fetch a user uniquely identified as "Foo".
#
sub fetch {
    my ( $self, $id )    = @_;
    $self->{Data} = $self->source->fetch_user_by_id( $id );
    return $self;
}

sub store {
    my ( $self, $id )    = @_;
    $self->source->store_user( $self );
    return $self;
}

# authenticate() takes a cleartext password and returns true if the User object's
#    password matches the existing hashed password.
#
sub authenticate {
    my ( $self, $user_pw )  = @_;
    my $stored_pw	    = $self->passwd
	or $self->log( 1, "User password not loaded yet" );

    return md5_base64( $user_pw ) eq $stored_pw;
}

sub groups {
    my ( $self ) = @_;

    $self->{Group} = $self->source->fetch_groups_by_user( $self ) || {}
	unless $self->{Group};

    return( wantarray ? keys %{$self->{Group}} : $self->{Group} );
}

1;
