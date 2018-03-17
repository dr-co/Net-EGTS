#!/usr/bin/perl

use warnings;
use strict;
use utf8;
use open qw(:std :utf8);
use lib qw(lib ../lib);

use Test::More tests    => 2;

BEGIN {
    use_ok 'Net::EGTS::Util';
}

subtest 'usize' => sub {
    plan tests => 5;

    is usize('C'), 1, 'C';
    is usize('S'), 2, 'S';
    is usize('L'), 4, 'L';

    is usize('B8'), 1, 'B8';

    is usize('CS'), 3, 'CS';
};
