/*******************************************************************************************
*文件:  smb.h
*描述:  SMB模块
*作者:  王君雷
*日期:  2019-05-27
*修改:
*
*******************************************************************************************/
#ifndef __FC_SMB_1_H__
#define __FC_SMB_1_H__

#include "datatype.h"

#define SMB_COM_CREATE_DIRECTORY        0x00
#define SMB_COM_DELETE_DIRECTORY        0x01
#define SMB_COM_OPEN                0x02
#define SMB_COM_CREATE              0x03
#define SMB_COM_CLOSE               0x04
#define SMB_COM_FLUSH               0x05
#define SMB_COM_DELETE              0x06
#define SMB_COM_RENAME              0x07
#define SMB_COM_QUERY_INFORMATION       0x08
#define SMB_COM_SET_INFORMATION         0x09
#define SMB_COM_READ                0x0A
#define SMB_COM_WRITE               0x0B
#define SMB_COM_LOCK_BYTE_RANGE         0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE       0x0D
#define SMB_COM_CREATE_TEMPORARY        0x0E
#define SMB_COM_CREATE_NEW          0x0F
#define SMB_COM_CHECK_DIRECTORY         0x10
#define SMB_COM_PROCESS_EXIT            0x11
#define SMB_COM_SEEK                0x12
#define SMB_COM_LOCK_AND_READ           0x13
#define SMB_COM_WRITE_AND_UNLOCK        0x14
#define SMB_COM_READ_RAW            0x1A
#define SMB_COM_READ_MPX            0x1B
#define SMB_COM_READ_MPX_SECONDARY      0x1C
#define SMB_COM_WRITE_RAW           0x1D
#define SMB_COM_WRITE_MPX           0x1E
#define SMB_COM_WRITE_MPX_SECONDARY     0x1F
#define SMB_COM_WRITE_COMPLETE          0x20
#define SMB_COM_QUERY_SERVER            0x21
#define SMB_COM_SET_INFORMATION2        0x22
#define SMB_COM_QUERY_INFORMATION2      0x23
#define SMB_COM_LOCKING_ANDX            0x24
#define SMB_COM_TRANSACTION         0x25
#define SMB_COM_TRANSACTION_SECONDARY       0x26
#define SMB_COM_IOCTL               0x27
#define SMB_COM_IOCTL_SECONDARY         0x28
#define SMB_COM_COPY                0x29
#define SMB_COM_MOVE                0x2A
#define SMB_COM_ECHO                0x2B
#define SMB_COM_WRITE_AND_CLOSE         0x2C
#define SMB_COM_OPEN_ANDX           0x2D
#define SMB_COM_READ_ANDX           0x2E
#define SMB_COM_WRITE_ANDX          0x2F
#define SMB_COM_NEW_FILE_SIZE           0x30
#define SMB_COM_CLOSE_AND_TREE_DISC     0x31
#define SMB_COM_TRANSACTION2            0x32
#define SMB_COM_TRANSACTION2_SECONDARY      0x33
#define SMB_COM_FIND_CLOSE2         0x34
#define SMB_COM_FIND_NOTIFY_CLOSE       0x35
/* Used by Xenix/Unix       0x60-0x6E */
#define SMB_COM_TREE_CONNECT            0x70
#define SMB_COM_TREE_DISCONNECT         0x71
#define SMB_COM_NEGOTIATE           0x72
#define SMB_COM_SESSION_SETUP_ANDX      0x73
#define SMB_COM_LOGOFF_ANDX         0x74
#define SMB_COM_TREE_CONNECT_ANDX       0x75
#define SMB_COM_QUERY_INFORMATION_DISK      0x80
#define SMB_COM_SEARCH              0x81
#define SMB_COM_FIND                0x82
#define SMB_COM_FIND_UNIQUE         0x83
#define SMB_COM_FIND_CLOSE          0x84
#define SMB_COM_NT_TRANSACT         0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY       0xA1
#define SMB_COM_NT_CREATE_ANDX          0xA2
#define SMB_COM_NT_CANCEL           0xA4
#define SMB_COM_NT_RENAME           0xA5
#define SMB_COM_OPEN_PRINT_FILE         0xC0
#define SMB_COM_WRITE_PRINT_FILE        0xC1
#define SMB_COM_CLOSE_PRINT_FILE        0xC2
#define SMB_COM_GET_PRINT_QUEUE         0xC3
#define SMB_COM_READ_BULK           0xD8
#define SMB_COM_WRITE_BULK          0xD9
#define SMB_COM_WRITE_BULK_DATA         0xDA


#define SMB_FLAGS_RESPONSE 0x80

#define SMB_SHARE_ACCESS_READ   0x00000001
#define SMB_SHARE_ACCESS_WRITE  0x00000002
#define SMB_SHARE_ACCESS_DELETE 0x00000004

//Trans2 Request - subcommand
#define FIND_FIRST2   0x0001
#define SET_PATH_INFO 0x0006
#define SET_FILE_INFO 0x0008

#define SET_FILE_POSIX_OPEN   521
#define SET_FILE_POSIX_UNLINK 522
#define SET_DISPOSITION_INFO  1013
#define DELETE_PENDING        0x01

#pragma pack(push, 1)

//32B
typedef struct SMB_HEADER {
    uint8 Protocol[4];
    uint8 Command;
    uint32 Status;
    uint8  Flags;
    uint16 Flags2;
    uint16 PIDHigh;
    uint8  SecurityFeatures[8];
    uint16 Reserved;
    uint16 TID;
    uint16 PIDLow;
    uint16 UID;
    uint16 MID;
} SMB_HEADER, *PSMB_HEADER;

//49B
typedef struct SMB_Parameters {
    uint8 WordCount;
    uint8 AndXCommand;
    uint8 AndXReserved;
    uint16 AndXOffset;
    uint8 Reserved;
    uint16 NameLength;
    uint32 Flags;
    uint32 RootDirectoryFID;
    uint32 DesiredAccess;
    uint64 AllocationSize;
    uint32 ExtFileAttributes;
    uint32 ShareAccess;
    uint32 CreateDisposition;
    uint32 CreateOptions;
    uint32 ImpersonationLevel;
    uint8 SecurityFlags;
} SMB_Parameters, *PSMB_Parameters;

//36B
typedef struct SMB_TRANS2_REQUEST {
    uint8 WordCount;
    uint16 TotalParameterCount;
    uint16 TotalDataCount;
    uint16 MaxParameterCount;
    uint16 MaxDataCount;
    uint8 MaxSetupCount;
    uint8 Reserved1;
    uint16 Flags;
    uint32 Timeout;
    uint16 Reserved2;
    uint16 ParameterCount;
    uint16 ParameterOffset;
    uint16 DataCount;
    uint16 DataOffset;
    uint8 SetupCount;
    uint8 Reserved3;
    uint16 Setup;
} SMB_TRANS2_REQUEST, *PSMB_TRANS2_REQUEST;

typedef struct SET_PATH_INFO_PARAMETER {
    uint16 level;
    uint32 reserved;
} SET_PATH_INFO_PARAMETER, *PSET_PATH_INFO_PARAMETER;

typedef struct SET_FILE_INFO_PARAMETER {
    uint16 FID;
    uint16 InformationLevel;
    uint16 Reserved;
} SET_FILE_INFO_PARAMETER, *PSET_FILE_INFO_PARAMETER;

#define ASCII_FORMAT 0x04
typedef struct DELETE_DIRECTORY_REQUEST {
    uint8 wordcount;
    uint16 bytecount;
    uint8 bufferformat;
} DELETE_DIRECTORY_REQUEST, *PDELETE_DIRECTORY_REQUEST;

#pragma pack(pop)

#endif
