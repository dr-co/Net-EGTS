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
    isa         => 'BYNARY',
    lazy        => 1,
    builder     => sub { return $_[0]->SFRD },
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
