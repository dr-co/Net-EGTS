use utf8;

package Net::EGTS::Codes;
use Mouse;
extends qw(Exporter);

our @EXPORT;

# Packet types
use constant EGTS_PT_RESPONSE               => 0;
use constant EGTS_PT_APPDATA                => 1;
use constant EGTS_PT_SIGNED_APPDATA         => 2;
push @EXPORT, qw(
    EGTS_PT_RESPONSE
    EGTS_PT_APPDATA
    EGTS_PT_SIGNED_APPDATA
);

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
push @EXPORT, qw(
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


__PACKAGE__->meta->make_immutable();
