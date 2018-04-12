use utf8;

package Net::EGTS::Simple;
use Mouse;

use Carp;
use IO::Socket::INET;
use Data::Dumper;

use Net::EGTS::Util;
use Net::EGTS::Types;
use Net::EGTS::Codes;

use Net::EGTS::Packet;
use Net::EGTS::Record;
use Net::EGTS::SubRecord;

use Net::EGTS::Packet::Appdata;
use Net::EGTS::SubRecord::Auth::DispatcherIdentity;

=head1 NAME

Net::EGTS::Simple - simple socket transport

=cut

# Timeout, sec. (0 .. 255)
use constant EGTS_SL_NOT_AUTH_TO            => 6;

# Response timeout
use constant EGTS_TL_RESPONSE_ТО         => 5;
# Resend attempts if timeout TL_RESPONSE_ТО
use constant EGTS_TL_RESEND_ATTEMPTS     => 3;
# Connection timeout
use constant EGTS_TL_RECONNECT_ТО        => 30;

has host        => is => 'ro', isa => 'Str', required => 1;
has port        => is => 'ro', isa => 'Int', required => 1;

has timeout     => is => 'ro', isa => 'Int', default => EGTS_TL_RECONNECT_ТО;
has attempt     => is => 'ro', isa => 'Int', default => EGTS_TL_RESEND_ATTEMPTS;
has rtimeout    => is => 'ro', isa => 'Int', default => EGTS_TL_RESPONSE_ТО;

has did         => is => 'ro', isa => 'Int', required => 1;
has type        => is => 'ro', isa => 'Int', default => 0;
has description => is => 'ro', isa => 'Maybe[Str]';

has socket      =>
    is          => 'ro',
    isa         => 'Object',
    lazy        => 1,
    clearer     => 'socket_drop',
    builder     => sub {
        my ($self) = @_;
        my $socket = IO::Socket::INET->new(
            PeerAddr    => $self->host,
            PeerPort    => $self->port,
            Proto       => 'tcp',
            Timeout     => $self->timeout,
        );
        die "Open socket error: $!\n" unless $socket;
        return $socket;
    }
;

=head2 reset

Reset internal counters for new connection

=cut

sub reset {
    $Net::EGTS::Packet::PID = 0;
#    $Net::EGTS::Record::RN  = 0;
}

sub connect {
    my ($self) = @_;
    $self->disconnect if $self->socket;
    $self->reset;
    return $self;
}

sub disconnect {
    my ($self) = @_;
    $self->socket->shutdown(2);
    $self->socket_drop;
    $self->reset;
    return $self;
}

sub auth {
    my ($self) = @_;
    use bytes;

    my $in = '';

    my $a = Net::EGTS::SubRecord::Auth::DispatcherIdentity->new(
        DT      => $self->type,
        DID     => $self->did,
        DSCR    => $self->description,
    );
    $a->encode;
    warn 'sub', $a->as_debug;

    my $r = Net::EGTS::Record->new(
            SST => EGTS_AUTH_SERVICE,
            RST => EGTS_AUTH_SERVICE,
            RD  => $a->bin,
        );
    $r->encode;
    warn 'record', $r->as_debug;

    my $packet1 = Net::EGTS::Packet::Appdata->new(
        PRIORITY    => 0b11,
        SFRD        => $r->bin,
    );
    $packet1->encode;
#warn Dumper $packet1;
    warn "auth =[send]=>\n", $packet1->as_debug;
#    $self->{socket}->send( $packet1->encode );
#
#    while (1) {
#        my $in = '';
#        $self->{socket}->recv($in, 65536)
#    }

    die;
    return $self;
}

#sub auth {
#    my ($self) = @_;
#
#    my ($in, $out) = ('', '');
#
#    $out = egts_encode_packet(
#        priority    => 'low',
#        data        => [
#            egts_encode_r(
#                source      => EGTS_AUTH_SERVICE,
#                recipient   => EGTS_AUTH_SERVICE,
#                direction   => 'none',
#                time        => undef,
#                data        => [
#                    egts_encode_sr
#                        egts_encode_sr_dispatcher_identity(
#                            $self->{dt},
#                            $self->{did},
#                            $self->{desc},
#                        ),
#                ],
#            )
#        ],
#    );
#    $self->{socket}->send($out);
##    warn sprintf("auth %d bytes =[send]=>\n%s\n",
##        length($out),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $out => 4
##    );
#
#    # Получаем ответ
#    $self->{socket}->recv($in, 65536);
##    warn sprintf("auth %d bytes <=[recv]=\n%s\n\n",
##        length($in),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $in => 4
##    );
##    my ($response) = egts_decode_packets $in;
##    return 'Packet not EGTS_PT_RESPONSE'
##        unless $response->{type} == EGTS_PT_RESPONSE;
#
#
#    $self->{socket}->recv($in, 65536);
##    warn sprintf("auth %d bytes <=[recv]=\n%s\n\n",
##        length($in),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $in => 4
##    );
##    my ($result) = egts_decode_packets $in;
##    return 'Packet not EGTS_PT_APPDATA'
##        unless $result->{type} == EGTS_PT_APPDATA;
#
##    warn dumper $result;
#
##    # Подтверждение принятия пакета авторизации
##
##    # Подтверждение проходжения авторизации
##    return 'Not result' unless $response->{type} == EGTS_SR_RESULT_CODE;
##    warn dumper {result => $result};
##
##    # Отправим подтверждение
##    $out = egts_encode_packet(
##        priority    => 'low',
##        data        => [
##            egts_encode_r(
##                source      => EGTS_AUTH_SERVICE, #$self->{service},
##                recipient   => EGTS_AUTH_SERVICE,
##                direction   => 'none',
##                time        => undef,
##                data        => [
##                    egts_encode_sr
##                        egts_encode_sr_record_response(
##                            $response->{id},
##                            EGTS_PC_OK,
##                        ),
##                ],
##            )
##        ],
##    );
##    $self->{socket}->send($out);
##    warn sprintf("auth %d bytes =[send]=>\n%s\n",
##        length($out),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $out => 4
##    );
#
##    warn dumper \@response;
#    return $self;
#}
#
#sub teledata {
#    my ($self, $data) = @_;
#
#    my $oid = delete $data->{id};
#
#    my ($in, $out) = ('', '');
#
#    $out = egts_encode_packet(
#        priority    => 'low',
#        data        => [
#            egts_encode_r(
#                oid         => $oid,
#                source      => EGTS_TELEDATA_SERVICE,#$self->{service},
#                recipient   => EGTS_TELEDATA_SERVICE,
#                direction   => 'none',
#                time        => undef,
#                data        => [
#                    egts_encode_sr
#                        egts_encode_sr_pos_data( %$data )
#                ],
#            )
#        ],
#    );
#
#    $self->{socket}->send($out);
##    warn sprintf("teledata %d bytes =[send]=>\n%s\n",
##        length($out),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $out => 4
##    );
#
#    $self->{socket}->recv($in, 65536);
##    warn sprintf("teledata %d bytes <=[recv]=\n%s\n\n",
##        length($in),
##        join "\n", map {join ' ', @$_} dumper_bitstring_chunked $in => 4
##    );
#
##    my @response = egts_decode_packets $in;
##    return 'Not response' unless $response[0]{type} == EGTS_PT_RESPONSE;
##    warn dumper \@response;
#
#    return $self;
#}

__PACKAGE__->meta->make_immutable();
