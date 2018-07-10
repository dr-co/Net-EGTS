#!/usr/bin/perl

use warnings;
use strict;
use utf8;
use open qw(:std :utf8);
use lib qw(lib ../lib t/lib ../t/lib);

use Test::More tests    => 5;
use Test::EGTS;

BEGIN {
    use_ok 'Net::EGTS::Simple';
}

my $s = tsocket;
my $client = Net::EGTS::Simple->new(
    host    => 'localhost',
    port    => 4444,
    did     => 0,
    socket  => $s,
);
isa_ok $client, 'Net::EGTS::Simple';

subtest 'auth' => sub {
    plan tests => 3;

    my $test_in = q{
        00000001 00000000 00000011 00001011
        00000000 00010000 00000000 00000000
        00000000 00000000 10110011 00000000
        00000000 00000000 00000110 00000000
        00000000 00000000 00011000 00000001
        00000001 00000000 00000011 00000000
        00000000 00000000 00000000 00000000
        10001110

        00000001 00000000 00000011 00001011
        00000000 00001011 00000000 00000001
        00000000 00000001 11000010 00000100
        00000000 00000001 00000000 01011000
        00000001 00000001 00001001 00000001
        00000000 00000000 11100111 00111100
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_in;
    $s->last_recv( $test_in );

    my $result = $client->auth;
    ok ref $result, 'auth';

    my $test_out = q{
        00000001 00000000 00000011 00001011
        00000000 00001111 00000000 00000000
        00000000 00000001 10011011 00001000
        00000000 00000000 00000000 00000000
        00000001 00000001 00000101 00000101
        00000000 00000000 00000000 00000000
        00000000 00000000 11111001 11011100
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_out;

    is length($s->last_send), length($test_out), 'send length';
    is $s->last_send, $test_out, 'send data';
};

subtest 'posdata' => sub {
    plan tests => 3;

    my $test_in = q{
        00000001 00000000 00000011 00001011
        00000000 00010000 00000000 00000010
        00000000 00000000 00111111 00000001
        00000000 00000000 00000110 00000000
        00000010 00000000 00011000 00000010
        00000010 00000000 00000011 00000000
        00000001 00000000 00000000 01010000
        10100001
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_in;
    $s->last_recv( $test_in );

    my $result = $client->posdata({
        id          => 908944,
        longitude   => 37.672935,
        latitude    => 55.767856,
        time        => '2018-07-09 13:10:16 +0000',
    });
    ok ref $result, 'auth';

    my $test_out = q{
        00000001 00000000 00000011 00001011
        00000000 00100011 00000000 00000001
        00000000 00000001 00000100 00011000
        00000000 00000001 00000000 00000001
        10010000 11011110 00001101 00000000
        00000010 00000010 00010000 00010101
        00000000 10111000 00100011 00000110
        00010000 11010111 11101001 10100000
        10011110 00001010 01001100 10010100
        00110101 00000011 00000000 00000000
        00000000 00000000 00000000 00000000
        00000000 00000000 10001111 00000101
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_out;

    is length($s->last_send), length($test_out), 'send length';
    is
        unpack('B*' => $s->last_send),
        unpack('B*' => $test_out),
        'send data'
    ;
};

subtest 'posdata 2' => sub {
    plan tests => 3;

    my $test_in = q{
        00000001 00000000 00000011 00001011
        00000000 00010000 00000000 00000011
        00000000 00000000 01111001 00000010
        00000000 00000000 00000110 00000000
        00000011 00000000 00011000 00000010
        00000010 00000000 00000011 00000000
        00000010 00000000 00000000 00000100
        11001000
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_in;
    $s->last_recv( $test_in );

    my $result = $client->posdata({
        id          => 908944,
        longitude   => 37.672935,
        latitude    => 55.767856,
        time        => '2018-07-09 13:10:36 +0000',
    });
    ok ref $result, 'auth';

    my $test_out = q{
        00000001 00000000 00000011 00001011
        00000000 00100011 00000000 00000010
        00000000 00000001 11001110 00011000
        00000000 00000010 00000000 00000001
        10010000 11011110 00001101 00000000
        00000010 00000010 00010000 00010101
        00000000 11001100 00100011 00000110
        00010000 11010111 11101001 10100000
        10011110 00001010 01001100 10010100
        00110101 00000011 00000000 00000000
        00000000 00000000 00000000 00000000
        00000000 00000000 01110001 01111100
    };
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test_out;

    is length($s->last_send), length($test_out), 'send length';
    is
        unpack('B*' => $s->last_send),
        unpack('B*' => $test_out),
        'send data'
    ;
};