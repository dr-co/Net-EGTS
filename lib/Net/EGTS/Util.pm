use utf8;
use strict;
use warnings;

package Net::EGTS::Util;
use base qw(Exporter);

use Carp;
use Digest::CRC     qw();
use Date::Parse     qw();
use List::MoreUtils qw(natatime any);

our @EXPORT = qw(
    crc8 crc16
    str2time time2new new2time
    dumper_bitstring
    usize
);

use constant TIMESTAMP_20100101_000000_UTC  => 1262304000;

=head2 crc8 $bytes

CRC8 with EGTS customization

=cut

sub crc8($) {
    use bytes;
    my $ctx = Digest::CRC->new(
        width   => 8,
        poly    => 0x31,
        init    => 0xff,
        xorout  => 0x00,
        check   => 0xf7,
    );
    $ctx->add($_[0]);
    return $ctx->digest;
}

=head2 crc16 $bytes

CRC16 with EGTS customization

=cut

sub crc16($) {
    use bytes;
    my $ctx = Digest::CRC->new(
        width   => 16,
        poly    => 0x1021,
        init    => 0xffff,
        xorout  => 0x0000,
        check   => 0x29b1,
    );
    $ctx->add($_[0]);
    return $ctx->digest;
}

=head2 str2time $str

Return timestamp from any time format

=cut

sub str2time($) {
    return undef unless defined $_[0];
    return undef unless length  $_[0];
    return $_[0] if $_[0] =~ m{^\d+$};
    return Date::Parse::str2time( $_[0] );
}

=head2 time2new [$time]

Return time from 2010 instead of 1970

=cut

sub time2new(;$) {
    my ($time) = @_;
    $time //= time;
    return ($time - TIMESTAMP_20100101_000000_UTC);
}

=head2 new2time [$time]

Return time from 1970 instead of 2010

=cut

sub new2time($) {
    my ($time) = @_;
    return ($time + TIMESTAMP_20100101_000000_UTC);
}

=head2 dumper_bitstring $bin, [$size]

Return bitstring from I<$bin> chanked by I<$size>

=cut

sub dumper_bitstring($;$) {
    my ($bin, $size) = @_;
    my @bytes = ((unpack('B*', $bin)) =~ m{.{8}}g);
    my $it = natatime( ($size || 4), @bytes );
    my @chunks;
    while (my @vals = $it->()) {
        push @chunks, join ' ', @vals;
    }
    return join "\n", @chunks;
}

=head2 usize $mask

Return size in bytes of pack/unpack mask

=cut

sub usize {
    my ($mask) = @_;
    use bytes;
    return length pack $mask => 0;
}

1;
