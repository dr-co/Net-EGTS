use utf8;

package Net::EGTS::SubRecord::Teledata::PosData;
use Mouse;
extends qw(Net::EGTS::SubRecord);

use Carp;

use Net::EGTS::Util     qw(usize time2new lat2mod lon2mod);
use Net::EGTS::Codes;

# Navigation Time
has NTM         => is => 'rw', isa => 'UINT', default => sub{ time2new };
# Latitude
has LAT         =>
    is          => 'rw',
    isa         => 'UINT',
    lazy        => 1,
    builder     => sub { lat2mod $_[0]->latitude },
;
# Longitude
has LONG        =>
    is          => 'rw',
    isa         => 'UINT',
    lazy        => 1,
    builder     => sub { lon2mod $_[0]->longitude },
;

# Flags:
# altitude exists
has ALTE        => is => 'rw', isa => 'BIT1', default => 0;
# east/west
has LOHS        =>
    is          => 'rw',
    isa         => 'BIT1',
    lazy        => 1,
    builder     => sub { $_[0]->longitude > 0 ? 0x0 : 0x1 },
;
# south/nord
has LAHS        =>
    is          => 'rw',
    isa         => 'BIT1',
    lazy        => 1,
    builder     => sub { $_[0]->latitude > 0 ? 0x0 : 0x1 },
;
# move
has MV          =>
    is          => 'rw',
    isa         => 'BIT1',
    lazy        => 1,
    builder     => sub { $_[0]->avg_speed ? 0x1 : 0x0 },
;
# from storage
has ВВ          => is => 'rw', isa => 'BIT1', default => 0;
# coordinate system
has CS          => is => 'rw', isa => 'BIT1', default => 0;
# 2d/3d
has FIX         => is => 'rw', isa => 'BIT1', default => 1;
# valid
has VLD         => is => 'rw', isa => 'BIT1', default => 1;

# Speed (lower bits)
has SPD_LO      =>
    is          => 'rw',
    isa         => 'BYTE',
    lazy        => 1,
    builder     => sub { $_[0]->avg_speed ? 0x1 : 0x0 },
;
# Direction the Highest bit
has DIRH        => is => 'rw', isa => 'BIT1', default => ;
# Altitude Sign
has ALTS        => is => 'rw', isa => 'BIT1', default => 0;
# Speed (highest bits)
has SPD_HI      => is => 'rw', isa => 'BIT6', default => ;

# Direction
has DIR         => is => 'rw', isa => 'BYTE', default => ;
# Odometer
has ODM         => is => 'rw', isa => 'BINARY3', default => 0;
# Digital Inputs
has DIN         => is => 'rw', isa => 'BIT8', default => 0;
# Source
has SRC         => is => 'rw', isa => 'BYTE', default => EGTS_SRCD_TIMER;

# Optional:
# Altitude
has ALT         => is => 'rw', isa => 'Maybe[BINARY3]';
# Source Data
has SRCD        => is => 'rw', isa => 'Maybe[SHORT]';

# TM as timestamp
has time        =>
    is          => 'ro',
    isa         => 'Int',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        return undef unless defined $self->NTM;
        return new2time $self->NTM;
    },
;
# Signed latitude
has latitude    =>
    is          => 'ro',
    isa         => 'Num',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        return undef unless defined $self->LAT;
        return mod2lat $self->LAT, $self->LAHS;
    },
;
# Signed longitude
has longitude   =>
    is          => 'ro',
    isa         => 'Num',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        return undef unless defined $self->LONG;
        return mod2lon $self->LONG, $self->LOHS;
    },
;
# Speed
#has avg_speed   =>
#    is          => 'ro',
#    isa         => 'Num',
#    lazy        => 1,
#    builder     => sub {
#        my ($self) = @_;
#        return undef unless defined $self->SPD_LO;
#        return undef unless defined $self->SPD_HI;
#        return
#    },
#;

#after 'decode' => sub {
#    my ($self) = @_;
#    die 'SubRecord not EGTS_SR_POS_DATA type'
#        unless $self->SRT == EGTS_SR_POS_DATA;
#
#    my $bin = $self->SRD;
#    $self->RCD( $self->nip(\$bin => 'C') );
#};


before 'encode' => sub {
    my ($self) = @_;
    die 'SubRecord not EGTS_SR_POS_DATA type'
        unless $self->SRT == EGTS_SR_POS_DATA;

    # Pack stupid bits economy
    my $stupid = $self->SPD_HI;
    $stupid = ($stupid | 0b10000000) if $self->DIRH;
    $stupid = ($stupid | 0b01000000) if $self->ALTS;

    my $bin = pack 'L L L B8 C C C a3 B8 C' =>
        $self->NTM, $self->LAT, $self->LONG,
        sprintf(
            '%b%b%b%b%b%b%b%b',
            $self->ALTE, $self->LOHS, $self->LAHS, $self->MV,
            $self->BB, $self->CS, $self->FIX, $self->VLD,
        ),
        $self->SPD_LO, $stupid,
        $self->DIR,
        $self->ODM,
        $self->DIN,
        $self->SRC,
    ;
    $bin .= pack 'a3', $self->ALT  if $self->ALTE;
    $bin .= pack 'S',  $self->SRCD if $self->SRCD;

    $self->SRD( $bin );
};

around BUILDARGS => sub {
    my $orig    = shift;
    my $class   = shift;
    my %opts    = @_;

    # simple time support
    if( defined $opts{time} ) {
        $opts{time} = str2time( $opts{time} );
        $opts{NTM}  = time2new( $opts{time} );
    }
    # simple lon support
    if( defined $opts{latitude} ) {
        $opts{LAT} = lat2mod $opts{latitude};
    }
    # simple lon support
    if( defined $opts{longitude} ) {
        $opts{LONG} = lon2mod $opts{longitude};
    }

    return $class->$orig( %opts, SRT => EGTS_SR_POS_DATA );
};

augment as_debug => sub {
    my ($self) = @_;
    use bytes;

    my @bytes = ((unpack('B*', $self->SRD)) =~ m{.{8}}g);

    my @str;
    push @str => sprintf('RCD:    %s',          splice @bytes, 0 => usize('C'));

    return @str;
};

sub egts_encode_sr_pos_data {
    my (%data) = @_;
    use bytes;

#    # Время навигации (4 байта) секунды с 00:00:00 01.01.2010 UTC
#    my $ntm     = defined $data{time}
#        ? $data{time} - TIMESTAMP_20100101_000000_UTC
#        : time - TIMESTAMP_20100101_000000_UTC
#    ;
#    # Широта (4 байта)
#    my $lat     = int( abs($data{latitude})  / 90  * 0xffffffff);
#    # Долгота (4 байта)
#    my $long    = int( abs($data{longitude}) / 180 * 0xffffffff);

#    # Флаги (1 байт):
#    # Наличие поля alt (1 бит)
#    my $alte    = 0;
#    # Полушарие долготы  (1 бит)
#    my $lohs    = $data{longitude} > 0 ? 0 : 1;
#    # Полушарие широты  (1 бит)
#    my $lahs    = $data{latitude}  > 0 ? 0 : 1;
#    # В движении (1 бит)
#    my $mv      = ($data{avg_speed} && $data{avg_speed} > 0) ? 1 : 0;
#    # Актуальные или отложенные данные (1 бит)
#    my $bb      = 0;
#    # Тип системы координат (1 бит)
#    my $cs      = 0;
#    # 2D или 3D (1 бит)
#    my $fix     = 1;
#    # Валидность данных (1 бит)
#    my $vld     = 1;

    # Скорость, округленная до 0.1 (14 бит):
    my $spd     = int(($data{avg_speed} // 0) * 10);

    # Старший бит параметра dir (1 бит)
    my $dirh    = ($data{direction} && $data{direction} > 255) ? 1 : 0;
#    # Флаг выше уровня моря или ниже (1 бит)
#    my $alts    = 0;

    # Ебучая экономия на битах
    my $spd_low  = ($spd & 0x000000ff);             # (1 байт)
    my $spd_high = ($spd & 0x0000ff00) >> 8;        # (6 бит)
    $spd_high = ($spd_high | 0b10000000) if $dirh;  # (1 бит)
    $spd_high = ($spd_high | 0b01000000) if $alts;  # (1 бит)

    # Направление (1 байт)
    my $dir     =
        ! defined( $data{direction} )   ? 0                         :
        $data{direction} > 255          ? $data{direction} - 256    :
                                          $data{direction}
    ;
#    # Одометр (3 байта)
#    my $odm     = 0;

    # Флаги (1 байт) Старший бит устанавливается на заказе.
    my $din     = $data{order}
        ? 0b10000000
        : 0b00000000
    ;

    # Источник события (1 байт)
#    my $src     = EGTS_SRCD_TIMER; #EGTS_SRCD_EXTERNAL;
    # Высота над уровнем моря (3 байта)
#    my $alt     = 0;
    # Данные для $src (2 байта)
#    my $srcd    = 0;

#    my $sr = pack 'L L L B8 C C C a3 B8 C' =>
#        $ntm, $lat, $long,
#        join('', $alte, $lohs, $lahs, $mv, $bb, $cs, $fix, $vld),
#        $spd_low,
#        $spd_high,
#        $dir,
#        $odm,
#        $din,
#        $src,
#    ;
#
#    $sr .= pack 'a3', $alt  if $alte;
#    $sr .= pack 'S',  $srcd if $srcd;
#
#    return EGTS_SR_POS_DATA, $sr;
}

__PACKAGE__->meta->make_immutable();
