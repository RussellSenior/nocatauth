package NoCat::User;

use NoCat;
use Digest::MD5 qw( md5_base64 );
use strict;
use vars qw( @ISA );

@ISA = 'NoCat';

my @Required_Parameters = qw( 
    Database DB_User DB_Passwd UserTable 
    UserIDField UserPasswdField UserAuthField 
);

# new() instantiates a new NoCat::User object and returns it. 
# You'll probably want to use NoCat->user() to call this for you.
# Use ->set() and/or ->fetch() to actually populate the object returned.
#
sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    $self->log( 1, "NoCat::User instantiated without required $_ parameter" )
	for ( grep !$self->{$_}, @Required_Parameters );

    $self->{Data} ||= {};
    
    if ( my $new_pw = $self->data->{$self->{UserPasswdField}} ) {
	$self->set_password( $new_pw );
    } 
    return $self;
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
    return $self->{Data}{ $self->{UserIDField} };
}

# db() instantiates (as needed) and returns a connection to an external database.
#
sub db {
    my $self = shift;

    return $self->{DB} if $self->{DB};

    require DBI;
    $self->{Own_DB}++;
    $self->{DB} = DBI->connect( @$self{qw{ Database DB_User DB_Passwd }}, { RaiseError => 1 } );
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create {
    my $self	= shift;
    my @fields	= keys %{$self->{Data}};
    my @place	= ("?") x @fields;
    
    local $" = ", ";
    $self->db->do( "insert into $self->{UserTable} (@fields) values (@place)", {}, values %{$self->{Data}} );
}

# fetch() retrieves an existing NoCat::User object from the database.
# fetch() takes a hash containing field/value pairs to match against existing objects, and
#    returns the first one it finds.
#
#    $user->fetch( $user->{UserIDField} => "Foo" ); 
#      ... is probably the logical way to fetch a user uniquely identified as "Foo".
#
sub fetch {
    my ( $self, %where ) = @_;
    my %data;

    my $ever = join(" and ", map( "$_ = ?", keys %where ));
    my $st = $self->db->prepare( "select * from $self->{UserTable} where $ever" );

    $st->execute( values %where );
    $st->bind_columns(\( @data{ @{$st->{NAME}} } ));
    $st->fetch;    

    %{$self->{Data}} = %data;
    $self
}

# store() saves an already existing NoCat::User object back to the database, 
#    presumably after a fetch() and set().
#
sub store {
    my $self	= shift;
    my @fields	= join(", ", map( "$_ = ?", keys %{$self->{Data}} ));
    $self->db->do( "update $self->{UserTable} set @fields", {}, values %{$self->{Data}} );
}

# authenticate() takes a cleartext password and returns true if the User object's
#    password matches the existing hashed password.
#
sub authenticate {
    my ( $self, $user_pw )  = @_;
    my $stored_pw	    = $self->data->{ $self->{UserPasswdField} } 
	or $self->log( 1, "User password not loaded yet" );

    return md5_base64( $user_pw ) eq $stored_pw;
}

# authorize() returns a user's authorization field.
#
sub authorize {
    my $self			= shift;
    my ( $table, $id, $auth )   = @$self{qw{ UserTable UserIDField UserAuthField }}; 
    my ( $result )		= $self->db->selectrow_array(
	"select $auth from $table where $id = ?", {}, $self->id
    );
    return $result;
}

sub DESTROY {
    my $self = shift;
    $self->db->disconnect if $self->{Own_DB};
}

1;
