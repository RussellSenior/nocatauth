package NoCat;

use strict;
use vars qw( *FILE );

my %Defaults = (
    PollInterval    => 10,
    ListenQueue	    => 10,
    LoginTimeout    => 300,
    NotifyTimeout   => 30,
    GatewayPort	    => 5280, 
    Verbosity	    => 5
);

sub import {
    $SIG{__WARN__} = sub { NoCat->log( 0, @_ ) };
}

sub new {
    my $class = shift;
    my @default = %Defaults;
    my %args = @_;

    # A couple of ways to inherit parental values...
    push @default, %$class if ref $class;    
    push @default, %{$args{Parent}} if ref $args{Parent};

    my $self = bless { @default, %args }, ref( $class ) || $class;

    $self->read_config( delete $self->{ConfigFile} ) if $self->{ConfigFile};
    $self;
}

sub read_config {
    my ( $self, $file ) = @_;
    open FILE, "<$file" or die "Can't read config $file: $!";

    while (defined( my $line = <FILE> )) {
	# Strip leading & trailing whitespace.
	$line =~ s/^\s+|\s+$//gos;

	# If it doesn't start with an alphanumeric, it's a comment.
	next unless $line =~ /^\w/o;

	# Split key / value pairs.
	my ( $key, $val ) = split /\s+/, $line, 2;
	$self->{$key} = $val;
    }
}

sub log {
    my ( $self, $level, @msg ) = @_;

    # Bag if this message is too verbose.
    #
    if ( not ref $self  or $level <= $self->{Verbosity} ) {
	# Get relevant time/date data.
	my ( $s, $m, $h, $d, $mo, $yr ) = (localtime())[0..5];
	$yr += 1900; $mo++; chomp @msg;

	# Log message takes form: [YYYY-MM-DD HH-MM-SS] *Your message here*
	print STDERR (sprintf( "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", $yr, $mo, $d, $h, $m, $s, "@msg" ));
    }
    return;
}

sub url_encode {
    my ( $self, @args ) = @_;
    for ( @args ) {
	$_ = "" unless defined $_;
	s/(\W)/sprintf("%%%02x", ord $1)/egos;
    }
    return wantarray ? @args : $args[0];
}

sub url_decode {
    my ( $self, @args ) = @_;
    s/%([0-9A-Z]{2})/chr hex $1/egios for ( @args );
    return wantarray ? @args : $args[0];
}

sub parse {
    my ( $self, $string, $extra ) = @_;

    # Merge parameters from %$extra, if any.
    my %args = $extra ? ( %$self, %$extra ) : %$self;

    # Throughout $string, replace strings of form $var or ${var} with value of $args{var}.
    $string =~ s/\$\{?(\w+)\}?/ defined( $args{$1} ) ? $args{$1} : "" /egios;

    return $string;
}

sub parse_file {
    my ( $self, $filename, $extra ) = @_;

    $filename = $self->{$filename} if $self->{$filename};
    $filename = "$self->{DocumentRoot}/$filename" if $self->{DocumentRoot} and not -r $filename;    

    open( FILE, "<$filename" )
	or return $self->log( 1, "parse_file $filename: $!" );

    my $file = do { local $/ = undef; <FILE> };
    return $self->parse( $file, $extra ); 
}

sub gateway {
    my $self = shift;
    require NoCat::Gateway;
    return NoCat::Gateway->new( Parent => $self, @_ );
}

sub firewall {
    my $self = shift;
    require NoCat::Firewall;
    return NoCat::Firewall->new( Parent => $self, @_ );
}

sub auth_service {
    my $self = shift;
    require NoCat::AuthService;
    return NoCat::AuthService->new( Parent => $self, @_ );
}

sub user {
    my $self = shift;
    require NoCat::User;
    return NoCat::User->new( Parent => $self, @_ );
}

sub message {
    my $self = shift;
    require NoCat::Message;
    return NoCat::Message->new( Parent => $self, @_ );
}
    
1;
