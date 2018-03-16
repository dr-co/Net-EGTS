use utf8;

package Net::EGTS::Service::Record;
use namespace::autoclean;
use Mouse;

use Carp;
use List::MoreUtils     qw(natatime);

use Net::EGTS::Util     qw(str2time time2new new2time usize dumper_bitstring);
use Net::EGTS::Types;

# Record Length
has RL          =>
    is          => 'rw',
    isa         => 'USHORT',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        use bytes;
        return length($self->RD);
    },
;

# Record Number
has RN         => is => 'rw', isa => 'USHORT', default => 0;

# Flags:
# Source Service On Device)
has SSOD        => is => 'rw', isa => 'BIT1', default => 0x0;
# Recipient Service On Device)
has RSOD        => is => 'rw', isa => 'BIT1', default => 0x0;
# Group
has GRP         => is => 'rw', isa => 'BIT1', default => 0x0;
# Record Processing Priority
has RPP         => is => 'rw', isa => 'BIT2', default => 0x00;
# Time Field Exists
has TMFE        => is => 'rw', isa => 'BIT1', default => 0x0;
# Event ID Field Exists
has EVFE        => is => 'rw', isa => 'BIT1', default => 0x0;
# Object ID Field Exists
has OBFE        => is => 'rw', isa => 'BIT1', default => 0x0;

# Optional:
# Object Identifier
has OID         => is => 'rw', isa => 'Maybe[UINT]';
# Event Identifier
has EVID        => is => 'rw', isa => 'Maybe[UINT]';
# Time
has TM          => is => 'rw', isa => 'Maybe[UINT]';

# Source Service Type
has SST         => is => 'rw', isa => 'BYTE';
# Recipient Service Type
has RST         => is => 'rw', isa => 'BYTE';
# Record Data
has RD          =>
    is          => 'rw',
    isa         => 'BINARY',
    trigger     => sub {
         my ($self, $value, $old) = @_;
         die 'Record Data too short'    if length($value) < 3;
         die 'Record Data too long'     if length($value) > 65498;
    }
;

# Record binary
has bin         => is => 'rw', isa => 'Str',  default => '';
# TM as timestamp
has time        =>
    is          => 'ro',
    isa         => 'Int',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        return undef unless         $self->TMFE;
        return undef unless defined $self->TM;
        return new2time $self->TM;
    },
;

around BUILDARGS => sub {
    my $orig  = shift;
    my $class = shift;

    # simple scalar decoding support
    my $bin   = @_ % 2 ? shift : undef;
    my %opts  = @_;

    # simple time support
    if( defined $opts{time} ) {
        $opts{time} = str2time( $opts{time} );
        $opts{TM}   = time2new( $opts{time} );
        $opts{TMFE} = 1 if $opts{TM};
    }

    return $class->$orig( bin => $bin, %opts ) if $bin;
    return $class->$orig( %opts );
};
sub BUILD {
    my $self = shift;
    my $args = shift;
    $self->decode( \$self->bin ) if length $self->bin;
}

# Get chunk from binary and store it
sub take {
    my ($self, $bin, $mask, $length) = @_;
    use bytes;

    $length //= usize($mask);
    confess "Can`t get chunk of length $length" if $length > length $$bin;

    my $chunk = substr $$bin, 0 => $length, '';
    $self->bin( $self->bin . $chunk );

    return unpack $mask => $chunk;
}

sub encode {
    my ($self) = @_;
    use bytes;

    croak 'Source Service Type required'    unless defined $self->SST;
    croak 'Recipient Service Type required' unless defined $self->RST;
    croak 'Record Data required'            unless defined $self->RD;
    croak 'Wrong Record Length'             unless $self->RL >= 3 &&
                                                   $self->RL <= 65498;

#    # Time seconds from 2010-01-01 00:00:00 UTC     uint
#    my $tm;
#    if( exists $opts{time} ) {
#        $tm = $opts{time} - TIMESTAMP_20100101_000000_UTC
#            if defined $opts{time};
#    } else {
#        $tm = time - TIMESTAMP_20100101_000000_UTC
#    }
#
    my $mask = 'S S B8';

    # Optional fields
    my @optional;
    if( $self->OBFE || $self->GRP ) {
        $mask .= ' L ';
        push @optional, $self->OID;
    }
    if( $self->EVFE ) {
        $mask .= ' L ';
        push @optional, $self->EVID;
    }
    if( $self->TMFE ) {
        $mask .= ' L ';
        push @optional, $self->TM;
    }

    $mask .= 'C C a*';

    my $bin = pack $mask =>
        $self->RL, $self->RN,
        sprintf(
            '%b%b%b%02b%b%b%b',
            $self->SSOD, $self->RSOD, $self->GRP, $self->RPP, $self->TMFE,
            $self->EVFE, $self->OBFE,
        ),
        @optional,
        $self->SST, $self->RST, $self->RD
    ;

    $self->bin( $bin );
    return $bin;
}

sub decode {
    my ($self, $bin) = @_;
    use bytes;

    $self->RL( $self->take($bin => 'S') );
    $self->RN( $self->take($bin => 'S') );

    my $flags = $self->take($bin => 'B8');
    $self->SSOD( ($flags & 0b10000000) >> 7 );
    $self->RSOD( ($flags & 0b01000000) >> 6 );
    $self->GRP(  ($flags & 0b00100000) >> 5 );
    $self->RPP(  ($flags & 0b00011000) >> 3 );
    $self->TMFE( ($flags & 0b00000100) >> 2 );
    $self->EVFE( ($flags & 0b00000010) >> 1 );
    $self->OBFE( ($flags & 0b00000001)      );

    $self->OID(  $self->take($bin => 'L') ) if $self->OBFE || $self->GRP;
    $self->EVID( $self->take($bin => 'L') ) if $self->EVFE;
    $self->TM(   $self->take($bin => 'L') ) if $self->TMFE;

    $self->SST( $self->take($bin => 'C') );
    $self->RST( $self->take($bin => 'C') );

    $self->RD( $self->take($bin => 'a*' => $self->RL) );

    return $self;
}

=head2 decode_all \$bin

Parse all records from packet Service Frame Data

=cut

sub decode_all($) {
    my ($bin) = @_;
    use bytes;

    my $i = 0;
    my @result;
    while( my $length = length $bin ) {
        my $record = Net::EGTS::Service::Record->new(RN => $i)->decode( \$bin );
        die 'Something wrong in records decode' unless $record;

        push @result, $record;
        ++$i;
    }

    return wantarray ? @result : \@result;
}

=head2 as_debug

Return human readable string

=cut

sub as_debug {
    my ($self) = @_;

    my @bytes = ((unpack('B*', $self->bin)) =~ m{.{8}}g);

    my @str;
    push @str => sprintf('RL:     %s  %s',      splice @bytes, 0 => 2);
    push @str => sprintf('RN:     %s  %s',      splice @bytes, 0 => 2);
    push @str => sprintf('FLAGS:  %s',          splice @bytes, 0 => 1);

    push @str => sprintf('OID:    %s %s %s %s', splice @bytes, 0 => 4)
        if defined $self->OID;
    push @str => sprintf('EVID:   %s %s %s %s', splice @bytes, 0 => 4)
        if defined $self->EVID;
    push @str => sprintf('TM:     %s %s %s %s', splice @bytes, 0 => 4)
        if defined $self->TM;

    push @str => sprintf('SST:    %s',          splice @bytes, 0 => 1);
    push @str => sprintf('RST:    %s',          splice @bytes, 0 => 1);

    my $it = natatime 4, @bytes;
    my @chunks;
    while (my @vals = $it->()) {
        push @chunks, join(' ', @vals);
    }
    push @str => sprintf('RD:     %s', join("\n        ", @chunks));

    return join "\n", @str;
}








#use Carp;
#use List::MoreUtils     qw(natatime any);
#
#use Net::EGTS::Util     qw(crc8 crc16 dumper_bitstring);
#use Net::EGTS::Types;
#use Net::EGTS::Codes;
##use Net::EGTS::Record   qw(decode_records);
#
#require Net::EGTS::Packet::Response;
#require Net::EGTS::Packet::Appdata;
#require Net::EGTS::Packet::SignedAppdata;
#
## Global packet identifier
#our $PID    = 0;
#
## State machine
#our @STATES = qw(null base header ok);
#our %STATES = (
#    # initial
#    null        => {
#        'index' => 0,
#        'sub'   => \&_decode_base,
#        'next'  => [qw(base ok)]
#    },
#    # the length of the header is known
#    base        => {
#        'index' => 1,
#        'sub'   => \&_decode_header,
#        'next'  => [qw(header ok)],
#    },
#    # header complete, process data
#    header      => {
#        'index' => 2,
#        'sub'   => \&_decode_data,
#        'next'  => [qw(ok)],
#    },
#    # complete
#    ok          => {
#        'index' => 3,
#        'sub'   => sub { return $_[0] },
#        'next'  => [qw{ok}],
#    },
#);
#
## Packet types and classes
#our %TYPES = (
#    EGTS_PT_RESPONSE,       'Net::EGTS::Packet::Response',
#    EGTS_PT_APPDATA,        'Net::EGTS::Packet::Appdata',
#    EGTS_PT_SIGNED_APPDATA, 'Net::EGTS::Packet::SignedAppdata',
#);
#
## Protocol Version
#has PRV         => is => 'rw', isa => 'BYTE', default => 0x01;
## Security Key ID
#has SKID        => is => 'rw', isa => 'BYTE', default => 0;
#
## Flags:
## Prefix
#has PRF         => is => 'rw', isa => 'BIT2', default => 0x00;
## Route
#has RTE         => is => 'rw', isa => 'BIT1', default => 0x0;
## Encryption Algorithm
#has ENA         => is => 'rw', isa => 'BIT2', default => 0x00;
## Compressed
#has CMP         => is => 'rw', isa => 'BIT1', default => 0x0;
## Priority
#has PRIORITY    => is => 'rw', isa => 'Priority', coerce => 1, default => 0x00;
#
## Header Length
#has HL          =>
#    is          => 'rw',
#    isa         => 'BYTE',
#    lazy        => 1,
#    builder     => sub {
#        my ($self) = @_;
#        my $length = 11;
#        $length += 2 if defined $self->PRA;
#        $length += 2 if defined $self->RCA;
#        $length += 1 if defined $self->TTL;
#        return $length;
#    },
#;
## Header Encoding
#has HE          => is => 'rw', isa => 'BYTE', default => 0x0;
## Frame Data Length
#has FDL         =>
#    is          => 'rw',
#    isa         => 'USHORT',
#    lazy        => 1,
#    builder     => sub {
#        use bytes;
#        return length $_[0]->SFRD;
#    },
#;
## Packet Identifier
#has PID         =>
#    is          => 'rw',
#    isa         => 'USHORT',
#    lazy        => 1,
#    builder     => sub {
#        my $pid = $PID;
#        $PID = 0 unless ++$PID >= 0 && $PID <= 65535;
#        return $pid;
#    }
#;
## Packet Type
#has PT          => is => 'rw', isa => 'BYTE';
#
## Optional (set if RTE enabled):
## Peer Address
#has PRA         => is => 'rw', isa => 'Maybe[USHORT]';
## Recipient Address
#has RCA         => is => 'rw', isa => 'Maybe[USHORT]';
## Time To Live
#has TTL         => is => 'rw', isa => 'Maybe[BYTE]';
#
## Header Check Sum
#has HCS         =>
#    is          => 'rw',
#    isa         => 'BYTE',
#    lazy        => 1,
#    builder     => sub {
#        my ($self) = @_;
#        use bytes;
#        my $length = $self->HL - 1; # HL - HCS
#        die 'Binary too short to get CRC8' if $length > length $self->bin;
#        return crc8( substr( $self->bin, 0 => $length ) );
#    },
#;
#
## Service Frame Data
#has SFRD        => is => 'rw', isa => 'Maybe[BINARY]', default => '';
## Service Frame Data Check Sum
#has SFRCS       =>
#    is          => 'rw',
#    isa         => 'Maybe[USHORT]',
#    lazy        => 1,
#    builder     => sub {
#        use bytes;
#        die 'Binary too short to get CRC16' if $_[0]->FDL > length $_[0]->SFRD;
#        return undef unless defined $_[0]->SFRD;
#        return undef unless length  $_[0]->SFRD;
#        return crc16( $_[0]->SFRD );
#    }
#;
#
## Private:
## Packet binary
#has bin         => is => 'rw', isa => 'Str',  default => '';
## Counter of bytes need to complete packet decode
#has need        => is => 'rw', isa => 'uInt', default => 10;
## Current packet decoder state
#has state       => is => 'rw', isa => 'Str',  default => 'null';
#
##around BUILDARGS => sub {
##    my $orig  = shift;
##    my $class = shift;
##
##    # store binary
###    my $bin = shift @_ unless @_ % 2;
##
##    my $self = $class->$orig( @_ );
##
##    # try decode
###    return undef unless ref $self->decode( $bin );
##
##    return $self;
##};
#
## Store binary and count how mutch more bytes need
#sub add {
#    my ($self, @bin) = @_;
#    use bytes;
#
#    for my $bin ( @bin ) {
#        $self->bin( $self->bin . $bin );
#        $self->need( $self->need - length($bin) );
#    }
#    return $self;
#}
#
## Goto next decode state
#sub next {
#    my ($self, $state, $need) = @_;
#
#    croak 'Something wrong. Has bynary data for decode.' if $self->need;
#    croak sprintf 'Can`t goto state "%s" from "%s"', $state, $self->state
#        unless any { $_ eq $state} @{$STATES{ $self->state }{next}};
#
#    $self->state( $state );
#    $self->need( $need );
#    return $self;
#}
#
#=head2 decode \$bin
#
#Decode binary stream I<$bin> into packet object.
#The binary stream will be truncated!
#Return:
#
#=over
#
#=item undef, $need
#
#if decode in process and need more data
#
#=item object
#
#if the packet is fully decoded
#
#=item error code
#
#if there are any problems
#
#=back
#
#=cut
#
#sub decode {
#    my ($self, $bin) = @_;
#    use bytes;
#
#    for my $name ( @STATES ) {
#        # all complete
#        return bless $self, $TYPES{ $self->PT } if $self->state eq 'ok';
#
#        # skip completed steps
#        next unless $name eq $self->state;
#
#        # need more data
#        my $bin_length = length($$bin);
#        return (undef, $self->need - $bin_length) if $bin_length < $self->need;
#
#        # get current state definition
#        my $state   = $STATES{$name};
#        my $sub     = $state->{sub};
#
#        # process data
#        my $result = $self->$sub( $bin );
#        return $result unless ref $result;
#    }
#
#    die 'Unknown packet state: ', $self->state;
#}
#
## Basic header part with header length
#sub _decode_base {
#    my ($self, $bin) = @_;
#    use bytes;
#
#    my $base = substr $$bin, 0 => 10, '';
#    my ($prv, $skid, $flags, $hl, $he, $fdl, $pid, $pt) =
#        unpack 'C C C C C S S C' => $base;
#    $self->add( $base );
#
#    $self->PRV( $prv );
#    $self->SKID($skid );
#    $self->HL(  $hl );
#    $self->HE(  $he );
#    $self->FDL( $fdl );
#    $self->PID( $pid );
#    $self->PT(  $pt );
#
#    $self->PRF(         ($flags & 0b11000000) >> 6 );
#    $self->RTE(         ($flags & 0b00100000) >> 5 );
#    $self->ENA(         ($flags & 0b00011000) >> 3 );
#    $self->CMP(         ($flags & 0b00000100) >> 2 );
#    $self->PRIORITY(    ($flags & 0b00000011)      );
#
#    return EGTS_PC_UNS_PROTOCOL     unless $self->PRV == 0x01;
#    return EGTS_PC_INC_HEADERFORM   unless $self->HL  == 11 || $self->HL == 16;
#    return EGTS_PC_UNS_PROTOCOL     unless $self->PRF == 0x00;
#
#    return $self->next(base => $self->HL - length($self->bin)); # optional + HCS
#}
#
## Complete header with data length
#sub _decode_header {
#    my ($self, $bin) = @_;
#    use bytes;
#
#    my $optional = '';
#    if( $self->RTE ) {
#        $optional = substr $$bin, 0 => 5, '';
#        my ($pra, $rca, $ttl) = unpack 'S S C' => $optional;
#        $self->add( $optional );
#
#        $self->PRA( $pra );
#        $self->RCA( $rca );
#        $self->TTL( $ttl );
#
#        die 'RTE not supported';
#    }
#
#    # Header CRC8
#    my $crc8 = substr $$bin, 0 => 1, '';
#    my $hsc = unpack 'C' => $crc8;
#    $self->add( $crc8 );
#
#    return EGTS_PC_HEADERCRC_ERROR unless $self->HCS == $hsc;
#
#    # Complete package. No data.
#    return $self->next(ok => 0) unless $self->FDL;
#    # Next get data
#    return $self->next(header => $self->FDL + 2); # SFRD + SFRCS
#}
#
## Complete packet decode
#sub _decode_data {
#    my ($self, $bin) = @_;
#    use bytes;
#
#    my $sfrd = substr $$bin, 0 => $self->FDL, '';
#    $self->SFRD( $sfrd );
#    $self->add( $sfrd );
#
#    my $crc16 = substr $$bin, 0 => 2, '';
#    my $sfrcs = unpack 'S' => $crc16;
#
#    $self->SFRCS( $sfrcs );
#    $self->add( $crc16 );
#    return EGTS_PC_DATACRC_ERROR unless $self->SFRCS == crc16 $self->SFRD;
#
#    unless( $self->ENA == 0x00 ) {
#        warn 'Encryption not supported yet';
#        return EGTS_PC_DECRYPT_ERROR;
#    }
#
#    unless( $self->CMP == 0x00 ) {
#        warn 'Compression not supported yet';
#        return EGTS_PC_INC_DATAFORM;
#    }
#
#    return $self->next(ok => 0);
#}
#
#=head2 encode
#
#Build packet as bynary
#
#=cut
#
#sub encode {
#    my ($self) = @_;
#    use bytes;
#
#    croak 'Encryption not supported yet'    if $self->ENA;
#    croak 'Compression not supported yet'   if $self->CMP;
#    croak 'Packet Type required'            unless defined $self->PT;
#
#    my $mask = 'C C B8 C C S S C';
#
#    # Optional fields
#    my @optional;
#    if( $self->PRA || $self->RCA || $self->TTL ) {
#        $mask .= ' S S C ';
#        push @optional, $self->PRA;
#        push @optional, $self->RCA;
#        push @optional, $self->TTL;
#
#        $self->RTE( 0x1 );
#    }
#
#    # Header Length
#    $self->HL( 10 + ($self->RTE ? 5 : 0) + 1 );
#
#    # Build base header
#    my $bin =  pack $mask =>
#        $self->PRV, $self->SKID,
#        sprintf(
#            '%02b%b%02b%b%02b',
#            $self->PRF, $self->RTE, $self->ENA, $self->CMP, $self->PRIORITY,
#        ),
#        $self->HL, $self->HE, $self->FDL, $self->PID, $self->PT,
#        @optional,
#    ;
#
#    # Header Check Sum
#    $self->HCS( crc8 $bin );
#    $bin .= pack 'C' => $self->HCS;
#
#    # Service Frame Data
#    $bin .= $self->SFRD;
#
#    # Service Frame Data Check Sum
#    if( $self->SFRD && $self->FDL ) {
#        $bin .= pack 'S' => $self->SFRCS;
#    }
#
#    $self->bin( $bin );
#    $self->need( 0 );
#    $self->next( 'ok' => 0 );
#    return $bin;
#}
#
#=head2 as_debug
#
#Return human readable string
#
#=cut
#
#sub as_debug {
#    my ($self) = @_;
#
#    my @bytes = ((unpack('B*', $self->bin)) =~ m{.{8}}g);
#
#    my @str;
#    push @str => sprintf('PRV:    %s',      shift @bytes);
#    push @str => sprintf('SKID:   %s',      shift @bytes);
#    push @str => sprintf('FLAGS:  %s',      shift @bytes);
#    push @str => sprintf('HL:     %s',      shift @bytes);
#    push @str => sprintf('HE:     %s',      shift @bytes);
#    push @str => sprintf('FDL:    %s %s',   shift @bytes, shift @bytes);
#    push @str => sprintf('PID:    %s %s',   shift @bytes, shift @bytes);
#    push @str => sprintf('PT:     %s',      shift @bytes);
#
#    push @str => sprintf('PRA:    %s %s',  shift @bytes, shift @bytes)
#        if defined $self->PRA;
#    push @str => sprintf('RCA:    %s %s',  shift @bytes, shift @bytes)
#        if defined $self->RCA;
#    push @str => sprintf('TTL:    %s',     shift @bytes)
#        if defined $self->TTL;
#
#    push @str => sprintf('HCS:    %s',     shift @bytes);
#
#    if( @bytes ) {
#        my @cfrcs = reverse (pop(@bytes), pop(@bytes));
#
#        my $it = natatime 4, @bytes;
#        my @chunks;
#        while (my @vals = $it->()) {
#            push @chunks, join(' ', @vals);
#        }
#
#        push @str => sprintf('SFRD:   %s', join("\n        ", @chunks));
#        push @str => sprintf('SFRCS:  %s %s', @cfrcs);
#    }
#
#    return join "\n", @str;
#}

__PACKAGE__->meta->make_immutable();
