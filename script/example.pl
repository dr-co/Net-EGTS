#!/usr/bin/perl

use warnings;
use strict;

use utf8;
use open qw(:std :utf8);
use lib qw(lib);

use Getopt::Long;
GetOptions(
    'did=i' => \my $did,
);

use Net::EGTS::Util;
use Net::EGTS::Simple;

die "Require --did=NUM\n" unless $did;

my $client = Net::EGTS::Simple->new(
        host    => 'rnis.mos.ru',
        port    => 4045,
        did     => $did,
);
$client->connect or die 'Can`t connect';

my $result1 = $client->auth;
die $result1 unless ref $result1;

my $result2 = $client->posdata({
    id          => 1,
    time        => str2time( time ),
    longitude   => 33,
    latitude    => 55,
    avg_speed   => 20,
    direction   => 180,
    order       => 0,
});
die $result2 unless ref $result2;

$client->disconnect or die 'Can`t disconnect';
