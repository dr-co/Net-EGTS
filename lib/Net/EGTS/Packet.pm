use utf8;

package Net::EGTS::Packet;
use base qw(Exporter);
use Mouse;

use Carp;
use List::MoreUtils     qw(natatime any);

use Net::EGTS::Util     qw(crc8 crc16 dumper_bitstring);
use Net::EGTS::Types;
#use Net::EGTS::Record   qw(decode_records);

# Packet types
use constant EGTS_PT_RESPONSE               => 0;
use constant EGTS_PT_APPDATA                => 1;
use constant EGTS_PT_SIGNED_APPDATA         => 2;

# Result codes
use constant EGTS_PC_OK                     => 0;
use constant EGTS_PC_IN_PROGRESS            => 1;
use constant EGTS_PC_UNS_PROTOCOL           => 128;
use constant EGTS_PC_DECRYPT_ERROR          => 129;
use constant EGTS_PC_PROC_DENIED            => 130;
use constant EGTS_PC_INC_HEADERFORM         => 131;
use constant EGTS_PC_INC_DATAFORM           => 132;
use constant EGTS_PC_UNS_TYPE               => 133;
use constant EGTS_PC_NOTEN_PARAMS           => 134;
use constant EGTS_PC_DBL_PROC               => 135;
use constant EGTS_PC_PROC_SRC_DENIED        => 136;
use constant EGTS_PC_HEADERCRC_ERROR        => 137;
use constant EGTS_PC_DATACRC_ERROR          => 138;
use constant EGTS_PC_INVDATALEN             => 139;
use constant EGTS_PC_ROUTE_NFOUND           => 140;
use constant EGTS_PC_ROUTE_CLOSED           => 141;
use constant EGTS_PC_ROUTE_DENIED           => 142;
use constant EGTS_PC_INVADDR                => 143;
use constant EGTS_PC_TTLEXPIRED             => 144;
use constant EGTS_PC_NO_ACK                 => 145;
use constant EGTS_PC_OBJ_NFOUND             => 146;
use constant EGTS_PC_EVNT_NFOUND            => 147;
use constant EGTS_PC_SRVC_NFOUND            => 148;
use constant EGTS_PC_SRVC_DENIED            => 149;
use constant EGTS_PC_SRVC_UNKN              => 150;
use constant EGTS_PC_AUTH_DENIED            => 151;
use constant EGTS_PC_ALREADY_EXISTS         => 152;
use constant EGTS_PC_ID_NFOUND              => 153;
use constant EGTS_PC_INC_DATETIME           => 154;
use constant EGTS_PC_IO_ERROR               => 155;
use constant EGTS_PC_NO_RES_AVAIL           => 156;
use constant EGTS_PC_MODULE_FAULT           => 157;
use constant EGTS_PC_MODULE_PWR_FLT         => 158;
use constant EGTS_PC_MODULE_PROC_FLT        => 159;
use constant EGTS_PC_MODULE_SW_FLT          => 160;
use constant EGTS_PC_MODULE_FW_FLT          => 161;
use constant EGTS_PC_MODULE_IO_FLT          => 162;
use constant EGTS_PC_MODULE_MEM_FLT         => 163;
use constant EGTS_PC_TEST_FAILED            => 164;

our @EXPORT = qw(
    EGTS_PT_RESPONSE
    EGTS_PT_APPDATA
    EGTS_PT_SIGNED_APPDATA

    EGTS_PC_OK
    EGTS_PC_IN_PROGRESS
    EGTS_PC_UNS_PROTOCOL
    EGTS_PC_DECRYPT_ERROR
    EGTS_PC_PROC_DENIED
    EGTS_PC_INC_HEADERFORM
    EGTS_PC_INC_DATAFORM
    EGTS_PC_UNS_TYPE
    EGTS_PC_NOTEN_PARAMS
    EGTS_PC_DBL_PROC
    EGTS_PC_PROC_SRC_DENIED
    EGTS_PC_HEADERCRC_ERROR
    EGTS_PC_DATACRC_ERROR
    EGTS_PC_INVDATALEN
    EGTS_PC_ROUTE_NFOUND
    EGTS_PC_ROUTE_CLOSED
    EGTS_PC_ROUTE_DENIED
    EGTS_PC_INVADDR
    EGTS_PC_TTLEXPIRED
    EGTS_PC_NO_ACK
    EGTS_PC_OBJ_NFOUND
    EGTS_PC_EVNT_NFOUND
    EGTS_PC_SRVC_NFOUND
    EGTS_PC_SRVC_DENIED
    EGTS_PC_SRVC_UNKN
    EGTS_PC_AUTH_DENIED
    EGTS_PC_ALREADY_EXISTS
    EGTS_PC_ID_NFOUND
    EGTS_PC_INC_DATETIME
    EGTS_PC_IO_ERROR
    EGTS_PC_NO_RES_AVAIL
    EGTS_PC_MODULE_FAULT
    EGTS_PC_MODULE_PWR_FLT
    EGTS_PC_MODULE_PROC_FLT
    EGTS_PC_MODULE_SW_FLT
    EGTS_PC_MODULE_FW_FLT
    EGTS_PC_MODULE_IO_FLT
    EGTS_PC_MODULE_MEM_FLT
    EGTS_PC_TEST_FAILED
);

# Global packet identifier
our $PID    = 0;

# State machine
our @STATES = qw(null base header ok);
our %STATES = (
    # initial
    null        => {
        index   => 0,
        sub     => \&decode_packet_base,
        next    => [qw(base)]
    },
    # the length of the header is known
    base        => {
        index   => 1,
        sub     => \&decode_packet_header,
        next    => [qw(header ok)],
    },
    # header complete, process data
    header      => {
        index   => 2,
        sub     => \&decode_packet_data,
        next    => [qw(ok)],
    },
    # complete
    ok          => {
        index   => 3,
        sub     => sub { return $_[0] },
        next    => [],
    },
);

# Protocol Version
has PRV         => is => 'rw', isa => 'BYTE', default => 0x01;
# Security Key ID
has SKID        => is => 'rw', isa => 'BYTE', default => 0;

# Flags:
# Prefix
has PRF         => is => 'rw', isa => 'BIT2', default => 0x00;
# Route
has RTE         => is => 'rw', isa => 'BIT1', default => 0x0;
# Encryption Algorithm
has ENA         => is => 'rw', isa => 'BIT2', default => 0x00;
# Compressed
has CMP         => is => 'rw', isa => 'BIT1', default => 0x0;
# Priority
has PR          => is => 'rw', isa => 'Priority', coerce => 1, default => 0x00;

# Header Length
has HL          =>
    is          => 'rw',
    isa         => 'BYTE',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        my $length = 11;
        $length += 2 if defined $self->PRA;
        $length += 2 if defined $self->RCA;
        $length += 1 if defined $self->TTL;
        return $length;
    },
;
# Header Encoding
has HE          => is => 'rw', isa => 'BYTE', default => 0x0;
# Frame Data Length
has FDL         =>
    is          => 'rw',
    isa         => 'USHORT',
    lazy        => 1,
    builder     => sub {
        use bytes;
        return length $_[0]->SFRD;
    },
;
# Packet Identifier
has PID         =>
    is          => 'rw',
    isa         => 'USHORT',
    lazy        => 1,
    builder     => sub {
        my $pid = $PID;
        $PID = 0 unless ++$PID >= 0 && $PID <= 65535;
        return $pid;
    }
;
# Packet Type
has PT          => is => 'rw', isa => 'BYTE';

# Optional (set if RTE enabled):
# Peer Address
has PRA         => is => 'rw', isa => 'Maybe[USHORT]';
# Recipient Address
has RCA         => is => 'rw', isa => 'Maybe[USHORT]';
# Time To Live
has TTL         => is => 'rw', isa => 'Maybe[BYTE]';

# Header Check Sum
has HCS         =>
    is          => 'rw',
    isa         => 'BYTE',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        use bytes;
        my $length = $self->HL - 1; # HL - HCS
        die 'Binary too short to get CRC8' if $length > length $self->bin;
        return crc8( substr( $self->bin, 0 => $length ) );
    },
;

# Service Frame Data
has SFRD        => is => 'rw', isa => 'Maybe[BINARY]', default => '';
# Service Frame Data Check Sum
has SFRCS       =>
    is          => 'rw',
    isa         => 'Maybe[USHORT]',
    lazy        => 1,
    builder     => sub {
        use bytes;
        die 'Binary too short to get CRC16' if $_[0]->FDL > length $_[0]->SFRD;
        return undef unless defined $_[0]->SFRD;
        return undef unless length  $_[0]->SFRD;
        return crc16( $_[0]->SFRD );
    }
;

# Private:
# Packet binary
has bin         => is => 'rw', isa => 'Str',  default => '';
# Counter of bytes need to complete packet decode
has need        => is => 'rw', isa => 'uInt', default => 10;
# Current packet decoder state
has state       => is => 'rw', isa => 'Str',  default => 'null';

# Store binary and count how mutch more bytes need
sub add {
    my ($self, @bin) = @_;
    use bytes;

    for my $bin ( @bin ) {
        $self->bin( $self->bin . $bin );
        $self->need( $self->need - length($bin) );
    }
    return $self;
}

# Goto next decode state
sub next {
    my ($self, $state, $need) = @_;

    croak 'Something wrong. Has bynary data for decode.' if $self->need;
    croak sprintf 'Can`t goto state "%s" from "%s"', $state, $self->state
        unless any { $_ eq $state} @{$STATES{ $self->state }{next}};

    $self->state( $state );
    $self->need( $need );
    return $self;
}

=head2 decode \$bin

Decode binary stream I<$bin> into packet object

=cut

sub decode {
    my ($self, $bin) = @_;
    use bytes;

    for my $name ( @STATES ) {
        # all complete
        return $self if $self->state eq 'ok';

        # goto next step
        next unless $name eq $self->state;

        # need more data
        my $bin_length = length($$bin);
        return (undef, $self->need - $bin_length) if $bin_length < $self->need;

        # get current state definition
        my $state   = $STATES{$name};
        my $sub     = $state->{sub};

        # process data
        my $result = $self->$sub( $bin );
        return $result unless ref $result;
    }

    die 'Unknown packet state: ', $self->state;
}

# Basic header part with header length
sub decode_packet_base {
    my ($self, $bin) = @_;
    use bytes;

    my $base = substr $$bin, 0 => 10, '';
    my ($prv, $skid, $flags, $hl, $he, $fdl, $pid, $pt) =
        unpack 'C C C C C S S C' => $base;
    $self->add( $base );

    $self->PRV( $prv );
    $self->SKID($skid );
    $self->HL(  $hl );
    $self->HE(  $he );
    $self->FDL( $fdl );
    $self->PID( $pid );
    $self->PT(  $pt );

    $self->PRF( ($flags & 0b11000000) >> 6 );
    $self->RTE( ($flags & 0b00100000) >> 5 );
    $self->ENA( ($flags & 0b00011000) >> 3 );
    $self->CMP( ($flags & 0b00000100) >> 2 );
    $self->PR(  ($flags & 0b00000011)      );

    return EGTS_PC_UNS_PROTOCOL     unless $self->PRV == 0x01;
    return EGTS_PC_INC_HEADERFORM   unless $self->HL  == 11 || $self->HL == 16;
    return EGTS_PC_UNS_PROTOCOL     unless $self->PRF == 0x00;

    return $self->next(base => $self->HL - length($self->bin)); # optional + HCS
}

# Complete header with data length
sub decode_packet_header {
    my ($self, $bin) = @_;
    use bytes;

    my $optional = '';
    if( $self->RTE ) {
        $optional = substr $$bin, 0 => 5, '';
        my ($pra, $rca, $ttl) = unpack 'S S C' => $optional;
        $self->add( $optional );

        $self->PRA( $pra );
        $self->RCA( $rca );
        $self->TTL( $ttl );

        die 'RTE not supported';
    }

    # Header CRC8
    my $crc8 = substr $$bin, 0 => 1, '';
    my $hsc = unpack 'C' => $crc8;
    $self->add( $crc8 );

    return EGTS_PC_HEADERCRC_ERROR unless $self->HCS == $hsc;

    # Complete package. No data.
    return $self->next(ok => 0) unless $self->FDL;
    # Next get data
    return $self->next(header => $self->FDL + 2); # SFRD + SFRCS
}

# Complete packet decode
sub decode_packet_data {
    my ($self, $bin) = @_;
    use bytes;

    my $sfrd = substr $$bin, 0 => $self->FDL, '';
    $self->SFRD( $sfrd );
    $self->add( $sfrd );

    my $crc16 = substr $$bin, 0 => 2, '';
    my $sfrcs = unpack 'S' => $crc16;

    $self->SFRCS( $sfrcs );
    $self->add( $crc16 );
    return EGTS_PC_DATACRC_ERROR unless $self->SFRCS == crc16 $self->SFRD;

    unless( $self->ENA == 0x00 ) {
        warn 'Encryption not supported yet';
        return EGTS_PC_DECRYPT_ERROR;
    }

    unless( $self->CMP == 0x00 ) {
        warn 'Compression not supported yet';
        return EGTS_PC_INC_DATAFORM;
    }

    return $self->next(ok => 0);
}

=head2 encode

Build packet

=cut

sub encode {
    my ($self) = @_;
    use bytes;

    croak 'Encryption not supported yet'    if $self->ENA;
    croak 'Compression not supported yet'   if $self->CMP;
    croak 'Packet Type required'            unless defined $self->PT;

    my $mask = 'C C B8 C C S S C';

    # Optional fields
    my @optional;
    if( $self->PRA || $self->RCA || $self->TTL ) {
        $mask .= ' S S C ';
        push @optional, $self->PRA;
        push @optional, $self->RCA;
        push @optional, $self->TTL;

        $self->RTE( 0x1 );
    }

    # Header Length
    $self->HL( 10 + ($self->RTE ? 5 : 0) + 1 );

    # Build base header
    my $bin =  pack $mask =>
        $self->PRV, $self->SKID,
        sprintf(
            '%02b%b%02b%b%02b',
            $self->PRF, $self->RTE, $self->ENA, $self->CMP, $self->PR,
        ),
        $self->HL, $self->HE, $self->FDL, $self->PID, $self->PT,
        @optional,
    ;

    # Header Check Sum
    $self->HCS( crc8 $bin );
    $bin .= pack 'C' => $self->HCS;

    # Service Frame Data
    $bin .= $self->SFRD;

    # Service Frame Data Check Sum
    if( $self->SFRD && $self->FDL ) {
        $bin .= pack 'S' => $self->SFRCS;
    }

    $self->bin( $bin );
    $self->next( 'ok' => 0 ) unless $self->state eq 'ok';
    return $bin;
}

#around BUILDARGS => sub {
#    my $orig  = shift;
#    my $class = shift;
#
#    if( @_ == 1 ) {
#        __PACKAGE__->new->decode( shift @_ );
#    }
#
#    # Apply data
#    if( my $data = delete $opts{data} ) {
#        if ( ! ref $data ) {
#            $opts{SFRD}  .= $data;
#            $opts{SFRCS}  = crc16 $opts{SFRD};
#        } elsif( 'ARRAY' eq ref $data ) {
#            $opts{SFRD}  .= join '', @$data;
#            $opts{SFRCS}  = crc16 $opts{SFRD};
#        } else {
#            die 'Field data must be arrayref or scalar';
#        }
#    }
#
#    return $class->$orig( %opts );
#};

=head2 as_debug

Human readable

=cut

sub as_debug {
    my ($self) = @_;

    my @bytes = ((unpack('B*', $self->bin)) =~ m{.{8}}g);

    my @str;
    push @str => sprintf('PRV:    %s',      shift @bytes);
    push @str => sprintf('SKID:   %s',      shift @bytes);
    push @str => sprintf('FLAGS:  %s',      shift @bytes);
    push @str => sprintf('HL:     %s',      shift @bytes);
    push @str => sprintf('HE:     %s',      shift @bytes);
    push @str => sprintf('FDL:    %s %s',   shift @bytes, shift @bytes);
    push @str => sprintf('PID:    %s %s',   shift @bytes, shift @bytes);
    push @str => sprintf('PT:     %s',      shift @bytes);

    push @str => sprintf('PRA:    %s %s',  shift @bytes, shift @bytes)
        if defined $self->PRA;
    push @str => sprintf('RCA:    %s %s',  shift @bytes, shift @bytes)
        if defined $self->RCA;
    push @str => sprintf('TTL:    %s',     shift @bytes)
        if defined $self->TTL;

    push @str => sprintf('HCS:    %s',     shift @bytes);

    if( @bytes ) {
        my @cfrcs = reverse (pop(@bytes), pop(@bytes));

        my $it = natatime 4, @bytes;
        my @chunks;
        while (my @vals = $it->()) {
            push @chunks, join(' ', @vals);
        }

        push @str => sprintf('SFRD:   %s', join("\n        ", @chunks));
        push @str => sprintf('SFRCS:  %s %s', @cfrcs);
    }

    return join "\n", @str;
}

__PACKAGE__->meta->make_immutable();
