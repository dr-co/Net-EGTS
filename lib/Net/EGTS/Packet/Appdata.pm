use utf8;

package Net::EGTS::Packet::Appdata;
use namespace::autoclean;
use Mouse;
extends qw(Net::EGTS::Packet);

use Net::EGTS::Types;
use Net::EGTS::Codes;

# Service Data Record
has SDR         =>
    is          => 'rw',
    isa         => 'Maybe[BINARY]',
    lazy        => 1,
    builder     => sub {
        my ($self) = @_;
        return unless defined $self->SFRD;
        return unless length  $self->SFRD;
        return $self->SFRD,
    },
;

after 'decode' => sub {
    my ($self) = @_;
    die 'Packet not EGTS_PT_APPDATA type'
        unless $self->PT == EGTS_PT_APPDATA;
};

around BUILDARGS => sub {
    my $orig    = shift;
    my $class   = shift;
    return $class->$orig( @_, PT => EGTS_PT_APPDATA );
};

__PACKAGE__->meta->make_immutable();
