/*******************************************************************************************
*文件:  smb2.h
*描述:  SMB模块
*作者:  王君雷
*日期:  2019-05-27
*修改:
*
*******************************************************************************************/
#ifndef __FC_SMB_2_H__
#define __FC_SMB_2_H__

#include "datatype.h"

/* SMB2 COMMAND CODES */
#define SMB2_COM_NEGOTIATE_PROTOCOL     0x00
#define SMB2_COM_SESSION_SETUP      0x01
#define SMB2_COM_SESSION_LOGOFF     0x02
#define SMB2_COM_TREE_CONNECT       0x03
#define SMB2_COM_TREE_DISCONNECT    0x04
#define SMB2_COM_CREATE         0x05
#define SMB2_COM_CLOSE          0x06
#define SMB2_COM_FLUSH          0x07
#define SMB2_COM_READ           0x08
#define SMB2_COM_WRITE          0x09
#define SMB2_COM_LOCK           0x0A
#define SMB2_COM_IOCTL          0x0B
#define SMB2_COM_CANCEL         0x0C
#define SMB2_COM_KEEPALIVE      0x0D
#define SMB2_COM_FIND           0x0E
#define SMB2_COM_NOTIFY         0x0F
#define SMB2_COM_GETINFO        0x10
#define SMB2_COM_SETINFO        0x11
#define SMB2_COM_BREAK          0x12

/* This structure contains information from the SMB2 header
 * as well as pointers to the conversation and the transaction specific
 * structures.
 */
#define SMB2_FLAGS_RESPONSE 0x00000001
#define SMB2_FLAGS_ASYNC_CMD    0x00000002
#define SMB2_FLAGS_CHAINED  0x00000004
#define SMB2_FLAGS_SIGNATURE    0x00000008
#define SMB2_FLAGS_PRIORITY_MASK    0x00000070
#define SMB2_FLAGS_DFS_OP   0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION 0x20000000

#define SMB2_FLAGS_PRIORITY1    0x00000010
#define SMB2_FLAGS_PRIORITY2    0x00000020
#define SMB2_FLAGS_PRIORITY3    0x00000030
#define SMB2_FLAGS_PRIORITY4    0x00000040
#define SMB2_FLAGS_PRIORITY5    0x00000050
#define SMB2_FLAGS_PRIORITY6    0x00000060
#define SMB2_FLAGS_PRIORITY7    0x00000070

/* SMB2 FLAG MASKS */
#define SMB2_FLAGS_ATTR_ENCRYPTED   0x00004000
#define SMB2_FLAGS_ATTR_INDEXED     0x00002000
#define SMB2_FLAGS_ATTR_OFFLINE     0x00001000
#define SMB2_FLAGS_ATTR_COMPRESSED  0x00000800
#define SMB2_FLAGS_ATTR_REPARSEPOINT    0x00000400
#define SMB2_FLAGS_ATTR_SPARSE      0x00000200
#define SMB2_FLAGS_ATTR_TEMPORARY   0x00000100
#define SMB2_FLAGS_ATTR_NORMAL      0x00000080
#define SMB2_FLAGS_ATTR_DEVICE      0x00000040
#define SMB2_FLAGS_ATTR_ARCHIVE     0x00000020
#define SMB2_FLAGS_ATTR_DIRECTORY   0x00000010
#define SMB2_FLAGS_ATTR_VOLUMEID    0x00000008
#define SMB2_FLAGS_ATTR_SYSTEM      0x00000004
#define SMB2_FLAGS_ATTR_HIDDEN      0x00000002
#define SMB2_FLAGS_ATTR_READONLY    0x00000001

#define SMB2_OPLOCK_LEVEL_NONE      0x00
#define SMB2_OPLOCK_LEVEL_II        0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH     0x09
#define SMB2_OPLOCK_LEVEL_LEASE     0xFF

/*create disposition*/
#define FILE_SUPERSEDE              0x00000000 //If the file already exists, supersede it. Otherwise, create the file.
#define FILE_OPEN                   0x00000001 //If the file already exists, return success; otherwise, fail the operation.
#define FILE_CREATE                 0x00000002 //If the file already exists, fail the operation; otherwise, create the file.
#define FILE_OPEN_IF                0x00000003 //Open the file if it already exists; otherwise, create the file.
#define FILE_OVERWRITE              0x00000004 //Overwrite the file if it already exists; otherwise, fail the operation.
#define FILE_OVERWRITE_IF           0x00000005 //Overwrite the file if it already exists; otherwise, create the file.

/*SMB2 Create options Mask*/
#define FILE_DIRECTORY_FILE            0x00000001
#define FILE_WRITE_THROUGH             0x00000002
#define FILE_SEQUENTIAL_ONLY           0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT      0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_COMPLETE_IF_OPLOCKED      0x00000100
#define FILE_NO_EA_KNOWLEDGE           0x00000200
#define FILE_RANDOM_ACCESS             0x00000800
#define FILE_DELETE_ON_CLOSE           0x00001000
#define FILE_OPEN_BY_FILE_ID           0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT    0x00004000
#define FILE_NO_COMPRESSION            0x00008000
#define FILE_OPEN_REMOTE_INSTANCE      0x00000400
#define FILE_OPEN_REQUIRING_OPLOCK     0x00010000
#define FILE_DISALLOW_EXCLUSIVE        0x00020000
#define FILE_RESERVE_OPFILTER          0x00100000
#define FILE_OPEN_REPARSE_POINT        0x00200000
#define FILE_OPEN_NO_RECALL            0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

/*Info Type*/
#define SMB2_0_INFO_FILE               0x01 //The file information is being set.
#define SMB2_0_INFO_FILESYSTEM         0x02 //The underlying object store information is being set.
#define SMB2_0_INFO_SECURITY           0x03 //The security information is being set.
#define SMB2_0_INFO_QUOTA              0x04 //The underlying object store quota information is being set.

/*info Level*/
#define SMB2_FILE_BASIC_INFO           0x04
#define SMB2_FILE_RENAME_INFO          0x0a
#define SMB2_FILE_DISPOSITION_INFO     0x0d
#define SMB2_FILE_ALLOCATION_INFO      0x13
#define SMB2_FILE_ENDOFFILE_INFO       0x14

#pragma pack(push, 1)
//64B
typedef struct SMB2_HEADER {
    uint8 server_componet[4]; //protocolid. The value MUST be set to 0x424D53FE
    uint16 header_length;     //structuresize.MUST be set to 64, which is the size, in bytes,of the SMB2 header structure
    uint16 credit_charge;
    union {
        struct {
            uint16 channel_sequence;//This field is an indication to the server about the client's Channel change.
            uint16 reserved;        //This field SHOULD be set to zero and the server MUST ignore it on receipt.
        } s1;
        uint32 status;              //The client MUST set this field to 0 and the server MUST ignore it on receipt.
    } u1;
    uint16 command;
    union {
        uint16 credits_requested;
        uint16 credits_response;
    } u2;
    uint32 flags;       //A flags field, which indicates how to process the operation.
    uint32 nextcommand;
    uint64 message_id;
    uint32 reserved;
    uint32 tree_id;     //Uniquely identifies the tree connect for the command.
    uint64 session_id;  //Uniquely identifies the established session for the command.
    uint8 signature[16];//The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the
    //Flags field of the SMB2 header and the message is not encrypted.
    //If the message is not signed, this field MUST be 0.
} SMB2_HEADER, *PSMB2_HEADER;

typedef struct SMB2_CREATE_REQUEST {
    uint16 structuresize;//The client MUST set this field to 57, indicating the size of the request structure, not including the header.
    //The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent.
    uint8 securityflags;//This field MUST NOT be used and MUST be reserved.
    uint8 oplock;//The requested oplock level.
    uint32 impersonation;//This field specifies the impersonation level requested by the application that is issuing the create request,
    uint64 createflags;//This field MUST NOT be used and MUST be reserved. The client SHOULD set this field to zero, and the server MUST ignore it on receipt.
    uint64 reserved;//This field MUST NOT be used and MUST be reserved. The client sets this to any value, and the server MUST ignore it on receipt.
    uint32 accessmask;//The level of access that is required
    uint32 fileattributes;
    uint32 shareaccess;
    uint32 disposition;
    uint32 createoptions;
    uint16 nameoffset;
    uint16 namelength; //The length of the file name, in bytes. If no file name is provided, this field MUST be set to 0.
    uint32 craetecontextsoffset;
    uint32 craetecontextslength;
    uint8 buffer[1]; //In the request, the Buffer field MUST be at least one byte in length.
} SMB2_CREATE_REQUEST, *PSMB2_CREATE_REQUEST;

typedef struct SMB2_SET_INFO_REQUEST {
    uint16 structuresize; //The client MUST set this field to 33, indicating the size of the request structure, not including the header.
    //The client MUST set this field to this value regardless of how long Buffer[] actually is in the request being sent.
    uint8 infotype;
    uint8 fileinfoclass;
    uint32 bufferlength;
    uint16 bufferoffset;
    uint16 reserved;
    uint32 additionalInformation;
    uint8 fileid[16];
    uint8 buffer[1];
} SMB2_SET_INFO_REQUEST, *PSMB2_SET_INFO_REQUEST;

#pragma pack(pop)

#endif
