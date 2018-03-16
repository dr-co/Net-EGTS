use utf8;

package Net::EGTS::Packet::SignedAppdata;
use namespace::autoclean;
use Mouse;
extends qw(Net::EGTS::Packet);

use Net::EGTS::Types;
use Net::EGTS::Codes;

# Signature Length
has SIGL        => is => 'rw', isa => 'SHORT', default => 0;
# Signature Data
has SIGD        => is => 'rw', isa => 'Maybe[BINARY]';
# Service Data Record
has SDR         => is => 'rw', isa => 'Maybe[BINARY]';

after 'decode' => sub {
    my ($self) = @_;
    die 'Packet not EGTS_PT_SIGNED_APPDATA type'
        unless $self->PT == EGTS_PT_SIGNED_APPDATA;

    return unless defined $self->SFRD;
    return unless length  $self->SFRD;

    $self->SIGL( unpack 'S' => substr( $self->SFRD, 0 => 2              ) );
    $self->SIGD(               substr( $self->SFRD, 2 => $self->SIGL    ) );
    $self->SDR(                substr( $self->SFRD, 2 + $self->SIGL     ) );
};

around BUILDARGS => sub {
    my $orig    = shift;
    my $class   = shift;
    return $class->$orig( @_, PT => EGTS_PT_SIGNED_APPDATA );
};

__PACKAGE__->meta->make_immutable();
