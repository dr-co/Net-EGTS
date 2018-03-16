#!/usr/bin/perl

use warnings;
use strict;
use utf8;
use open qw(:std :utf8);
use lib qw(lib ../lib);

use Test::More tests    => 4;

BEGIN {
    use_ok 'Net::EGTS::Service::Record';
    use_ok 'Net::EGTS::Codes';
}

subtest 'base' => sub {
    plan tests => 19;

    my $record = Net::EGTS::Service::Record->new(
        SST => EGTS_AUTH_SERVICE,
        RST => EGTS_AUTH_SERVICE,
        RD  => 'abc',
    );
    isa_ok $record, 'Net::EGTS::Service::Record';

    my $bin = $record->encode;
    ok $bin, 'encode';
    note $record->as_debug;

    my $result = Net::EGTS::Service::Record->new( $bin );
    isa_ok $result, 'Net::EGTS::Service::Record';
    note $result->as_debug;

    my $result2 = Net::EGTS::Service::Record->new->decode( \$bin );
    isa_ok $result2, 'Net::EGTS::Service::Record';
    note $result2->as_debug;

    is $record->RL, 3, 'Record Length';
    is $record->RN, 0, 'Record Number';

    is $record->SSOD, 0, 'Source Service On Device)';
    is $record->RSOD, 0, 'Recipient Service On Device) ';
    is $record->GRP, 0, 'Group';
    is $record->RPP, 0, 'Record Processing Priority';
    is $record->TMFE,  0, 'Time Field Exists';
    is $record->EVFE,  0, 'Event ID Field Exists';
    is $record->OBFE,  0, 'Object ID Field Exists';

    is $record->OID,  undef, 'Object Identifier';
    is $record->EVID,  undef, 'Event Identifier';
    is $record->TM, undef, 'Time';

    is $record->SST, EGTS_AUTH_SERVICE, 'Source Service Type';
    is $record->RST, EGTS_AUTH_SERVICE, 'Recipient Service Type';
    is $record->RD, 'abc', 'Record Data';
};

subtest 'time' => sub {
    plan tests => 3;

    my $record = Net::EGTS::Service::Record->new(
        SST     => EGTS_AUTH_SERVICE,
        RST     => EGTS_AUTH_SERVICE,
        RD      => 'abc',

        time    => '2018-01-01 22:30:00',
    );
    isa_ok $record, 'Net::EGTS::Service::Record';

    is $record->TM,     252531000, 'Time';
    is $record->TMFE,   1, 'Time Field Exists';
};
