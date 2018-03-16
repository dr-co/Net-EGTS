#!/usr/bin/perl

use warnings;
use strict;
use utf8;
use open qw(:std :utf8);
use lib qw(lib ../lib);

use Test::More tests    => 4;

BEGIN {
    use_ok 'Net::EGTS::Util';
    use_ok 'Net::EGTS::Packet';
}

subtest 'auth service - response' => sub {
    plan tests => 16;

    my $test = q(
        00000001 00000000 00000011 00001011
        00000000 00001111 00000000 00000000
        00000000 00000001 10011011 00001000
        00000000 00000000 00000000 10000000
        01000000 00000001 00000101 00000101
        00000000 00000000 11010010 00000111
        00000000 00000000 11110111 10001000
    );
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test;

    my $bin = "$test";
    my $packet = Net::EGTS::Packet->new->decode( \$bin );

    note $packet->as_debug;

    is $packet->PRV, 1, 'Protocol Version';
    is $packet->SKID, 0, 'Security Key ID';

    is $packet->PRF, 0, 'Prefix';
    is $packet->RTE, 0, 'Route';
    is $packet->ENA, 0, 'Encryption Algorithm';
    is $packet->CMP, 0, 'Compressed';
    is $packet->PR,  3, 'Priority';

    is $packet->HL,  11, 'Header Length';
    is $packet->HE,  0, 'Header Encoding';
    is $packet->FDL, 15, 'Frame Data Length';
    is $packet->PID, 0, 'Packet Identifier';
    is $packet->PT,  1, 'Packet Type';
    is $packet->HCS, 155, 'Header Check Sum';

    is length($packet->SFRD), 15, 'Service Frame Data';
    is $packet->SFRCS, 35063, 'Service Frame Data Check Sum';

    my $result = $packet->encode;
    is dumper_bitstring($result), dumper_bitstring($test), 'encode';
};

subtest 'auth service - response - partial decoding' => sub {
    plan tests => 11;

    my $test = q(
        00000001 00000000 00000011 00001011
        00000000 00001111 00000000 00000000
        00000000 00000001 10011011 00001000
        00000000 00000000 00000000 10000000
        01000000 00000001 00000101 00000101
        00000000 00000000 11010010 00000111
        00000000 00000000 11110111 10001000
    );
    s{[^01]}{}g, $_ = pack('B*' => $_) for $test;

    my $bin = "$test";
    my $in  = '';
    is length($bin), 28, 'bufer length 28';

    my $packet = Net::EGTS::Packet->new;

    $in .= substr $bin, 0 => 3, '';
    my ($res1, $need1) = $packet->decode( \$in );
    is $res1, undef, 'Undefined';
    is $need1, 7, 'Need more for header complete';
    is length($in), 3, 'bufer not truncated';

    $in .= substr $bin, 0 => 10, '';
    my ($res2, $need2) = $packet->decode( \$in );
    is $res2, undef, 'Undefined';
    is $need2, 15, 'Need more for data complete';
    is length($in), 2, 'bufer truncated by header';

    $in .= substr $bin, 0 => 15, '';
    my ($res3, $need3) = $packet->decode( \$in );
    isa_ok $res3, 'Net::EGTS::Packet', 'Decode complete';
    is $need3, undef, 'No need more for data complete';
    is length($in), 0, 'bufer truncated by data';

    note $packet->as_debug;

    my $result = $packet->encode;
    is dumper_bitstring($result), dumper_bitstring($test), 'encode';
};
