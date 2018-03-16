use utf8;

package Net::EGTS::Packet::Response;
use Mouse;
extends qw(Net::EGTS::Packet);

use Net::EGTS::Types;
use Net::EGTS::Codes;

# Response Packet ID
has RPID        => is => 'rw', isa => 'USHORT';
# Processing Result
has PR          => is => 'rw', isa => 'BYTE';
# Service Data Record
has SDR         => is => 'rw', isa => 'BYNARY';

after 'decode' => sub {
    my ($self) = @_;
    die 'Packet not EGTS_PT_RESPONSE type'
        unless $self->PT == EGTS_PT_RESPONSE;

    return unless defined $self->SFRD;
    return unless length  $self->SFRD;

    $self->RPID( unpack 'S' => substr( $self->SFRD, 0 => 2 ) );
    $self->PR(   unpack 'C' => substr( $self->SFRD, 2 => 1 ) );
    $self->SDR(                substr( $self->SFRD, 3      ) );
};

around BUILDARGS => sub {
    my $orig    = shift;
    my $class   = shift;
    return $class->$orig( @_, PT => EGTS_PT_RESPONSE );
};

__PACKAGE__->meta->make_immutable();
