package NoCat::Source::LDAP;

use NoCat::Source;
use Net::LDAP;
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( 
    LDAP_Host LDAP_Base UserIDField 
    GroupTable GroupIDField GroupAdminField
);

sub ldap {
    my ($self) = @_;
    unless ($self->{LDAP}) {
	my $ldap = Net::LDAP->new( $self->{LDAP_Host} );
	if ($ldap) {
	    $self->{LDAP} = $ldap;
	} else {
	    $self->log( 0, "Can't connect to LDAP server $self->{LDAP_Host}" );
	}
    }
    return $self->{LDAP};
}

sub dn {
    my ($self,$user_id) = @_;
    my $mesg = $self->ldap->search(
        base   => $self->{LDAP_Base},
        filter => "uid=$user_id"
    );
    my $entry = $mesg->entry(0);
 
    my $dn = $entry->dn;
    return $dn;
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create_user {
    my ( $self, $user )	= @_;
    my %data = %{ $user->data };

    $data{$self->{UserStampField}} = undef if $self->{UserStampField};

    my @fields	= keys %data;
    my @place	= ("?") x @fields;
    
    #$self->ldap->add($self->dn($user->id, attr => %data_ldap );
}

sub store_user {
    my ( $self, $user )	= @_;
    my $data	= $user->data;
    my $fields	= $self->where( "," => keys %$data );
 
    local $" = ", ";
    #$self->ldap->modify( $self->dn($user->id, attr => %$data);
}

sub authenticate_user {
    my ($self, $user_pw,$user) = @_;
    my $username = $user->id;
    my $retval = 0;    
     
    my $result = $self->ldap->bind( $self->dn($username), 'password' => $user_pw);
    if($result->code == 0) {
	$retval = 1;
    }

    return $retval;
}

sub fetch_user_by_id {
    my ( $self, $id )    = @_;    
    my $mesg = $self->ldap->search(
				   base   => $self->{LDAP_Base},
				   filter => "uid=$id"
				   );
    my $entry = $mesg->entry(0);
    return { $self->{UserIDField} => $entry->get_value('uid') };
    
}


sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    my %data;
    my $uid = $user->id;
    my $mesg = $self->ldap->search(
				   base => $self->{LDAP_Base},
				   filter => "memberUID=$uid"
				   );
    foreach my $entry ($mesg->all_entries) {
	$data{$entry->get_value('gidNumber')} = 1;
    }
    return \%data;
}

sub fetch_users_by_group {
    my ( $self, $group ) = @_;
    my %data;
    my $gid = $group->id;
    my $mesg = $self->ldap->search(
				   base => $self->{LDAP_Base},
				   filter => "gidNumber=$gid"
				   );
    foreach my $entry ($mesg->all_entries) {
	foreach my $user ($entry->get_value('memberUID')) {
	    $data{$user} = 1;
	}
    }
    return \%data;
}

=pod

These need to be implemented for the admin interface to work.
(Or get a real LDAP browser! :-)

sub add_group_member {
    my ( $self, $group, $user, $admin ) = @_;

}

sub drop_group_member {
    my ( $self, $group, $user ) = @_;
}

sub update_group_member {
    my ( $self, $group, $user, $admin ) = @_;

}

=cut

1;

