use utf8;

package Net::EGTS::Types;
use namespace::autoclean;
use Mouse;
use Mouse::Util::TypeConstraints;

subtype 'BOOLEAN',  as 'Bool';
subtype 'BYTE',     as 'Int',   where { 0 <= $_ && $_ <= 255 };
subtype 'USHORT',   as 'Int',   where { 0 <= $_ && $_ <= 65535 };
subtype 'UINT',     as 'Int',   where { 0 <= $_ && $_ <= 4294967295 };
subtype 'ULONG',    as 'Int',   where { 0 <= $_ && $_ <= 18446744073709551615 };
subtype 'SHORT',    as 'Int',   where { -32768 <= $_ && $_ <= 32767 };
subtype 'INT',      as 'Int',   where { -2147483648 <= $_ && $_ <= 2147483647 };
subtype 'FLOAT',    as 'Num';
subtype 'DOUBLE',   as 'Num';
subtype 'STRING',   as 'Str';
subtype 'BINARY',   as 'Str';

subtype 'BIT1',     as 'Bool';
subtype 'BIT2',     as 'Int', where { 0 <= $_ && $_ <= 3 };

subtype 'uInt',     as 'Int', where { 0 <= $_ };

subtype 'Priority', as 'BIT2';
coerce  'Priority' => from 'Str' => via sub {
    return
        ! defined($_)    ? 0b00000000    :
        $_ eq 'highest'  ? 0b00000000    :
        $_ eq 'high'     ? 0b00000001    :
        $_ eq 'medium'   ? 0b00000010    :
        $_ eq 'low'      ? 0b00000011    :
        die 'Priority must be one of: "highest", "high", "medium", "low"'
    ;
};

__PACKAGE__->meta->make_immutable();
