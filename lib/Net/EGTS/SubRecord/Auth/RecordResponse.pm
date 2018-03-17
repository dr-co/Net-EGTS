use utf8;

package Net::EGTS::SubRecord::Auth::RecordResponse;
use Mouse;
extends qw(Net::EGTS::SubRecord);

use Carp;

use Net::EGTS::Util     qw(usize);
use Net::EGTS::Codes;

# Confirmed Record Number
has CRN         => is => 'rw', isa => 'USHORT', default => 0;
# Record Status
has RST         => is => 'rw', isa => 'BYTE', default => 0;

after 'decode' => sub {
    my ($self) = @_;
    die 'SubRecord not EGTS_SR_RECORD_RESPONSE type'
        unless $self->SRT == EGTS_SR_RECORD_RESPONSE;

    my $bin = $self->SRD;

    $self->CRN( $self->take(\$bin => 'S') );
    $self->RST( $self->take(\$bin => 'C') );
};

before 'encode' => sub {
    my ($self) = @_;
    die 'SubRecord not EGTS_SR_RECORD_RESPONSE type'
        unless $self->SRT == EGTS_SR_RECORD_RESPONSE;

    $self->SRD( pack 'SC' => $self->CRN, $self->RST );
};

around BUILDARGS => sub {
    my $orig    = shift;
    my $class   = shift;
    return $class->$orig( @_, SRT => EGTS_SR_RECORD_RESPONSE );
};

augment as_debug => sub {
    my ($self) = @_;

    my @bytes = ((unpack('B*', substr $self->bin, usize('CS'))) =~ m{.{8}}g);

    my @str;
    push @str => sprintf('CRN:    %s  %s',      splice @bytes, 0 => usize('S'));
    push @str => sprintf('RST:    %s',          splice @bytes, 0 => usize('C'));

    return @str;
};

__PACKAGE__->meta->make_immutable();
