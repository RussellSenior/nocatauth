#!/usr/bin/perl -w

use lib '/usr/local/nocat/lib'; 
use NoCat;
use Digest::MD5 qw( md5_base64 );
use strict;

my $c  = 0;
my $db = NoCat->source( ConfigFile => $ENV{NOCAT} )->db;
my $st = $db->prepare(
    "select Pass, User from Member where length(Pass) <> 22"
);

$st->execute;

while ( my $q = $st->fetch ) {
    $db->do("update Member set Pass = ? where User = ?", {},
        md5_base64( $q->[0] ), $q->[1]);
    $c++;
}

print "$c records updated.\n";

__END__
