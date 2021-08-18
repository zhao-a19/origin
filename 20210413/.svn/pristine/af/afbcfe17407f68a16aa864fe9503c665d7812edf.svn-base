/*******************************************************************************************
*文件:  cip_parser.h
*描述:  cip解析
*作者:  王君雷
*日期:  2021-02-01
*修改:
*******************************************************************************************/
#ifndef __CIP_PARSER_H__
#define __CIP_PARSER_H__

#include <vector>
using namespace std;

#include <stdio.h>
#include "datatype.h"

#define CIP_ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CIP_ODD_NUMBER(n) (((n) + 1) / 2 * 2)       //是奇数时后面需要补一个字节
#define MAX_POINT_NAME_LEN  64                      //测点名称最大支持长度
#define MAX_CIP_SERVICE     127    //小于等于127为请求  大于127为响应

//command
#define NOP                0x0000
#define LIST_SERVICES      0x0004
#define LIST_IDENTITY      0x0063
#define LIST_INTERFACES    0x0064
#define REGISTER_SESSION   0x0065
#define UNREGISTER_SESSION 0x0066
#define SEND_RR_DATA       0x006F
#define SEND_UNIT_DATA     0x0070
#define INDICATE_STATUS    0x0072
#define CANCEL             0x0073

//status codes
#define SUCCESS               0x0000
#define INVALID_CMD           0x0001
#define NO_RESOURCES          0x0002
#define INCORRECT_DATA        0x0003
#define INVALID_SESSION       0x0064
#define INVALID_LENGTH        0x0065
#define UNSUPPORTED_PROT_REV  0x0069
//Found in wireshark
#define ENCAP_HEADER_ERROR    0x006A

//Common Packet Format Types
#define NULL_ADDR               0x0000
#define CONNECTION_BASED        0x00a1
#define CONNECTED_DATA_ITEM     0x00b1
#define UNCONNECTED_DATA_ITEM   0x00b2
#define SEQUENCE_ADDR_ITEM      0x8002 //0xB002 查阅资料显示应该为0x8002 suricate有误
//Found in wireshark add by wjl
#define LIST_IDENTITY_RESP      0x000C
#define LIST_SERVICES_RESP      0x0100
#define SOCK_ADR_INFO_OT        0x8000
#define SOCK_ADR_INFO_TO        0x8001

//CIP service codes
#define CIP_RESERVED        0x00
#define CIP_GET_ATTR_ALL    0x01
#define CIP_GET_ATTR_LIST   0x03
#define CIP_SET_ATTR_LIST   0x04
#define CIP_RESET           0x05
#define CIP_START           0x06
#define CIP_STOP            0x07
#define CIP_CREATE          0x08
#define CIP_DELETE          0x09
#define CIP_MSP             0x0a
#define CIP_APPLY_ATTR      0x0d
#define CIP_GET_ATTR_SINGLE 0x0e
#define CIP_SET_ATTR_SINGLE 0x10
#define CIP_KICK_TIMER      0x4b
#define CIP_OPEN_CONNECTION 0x4c
#define CIP_CHANGE_START    0x4f
#define CIP_GET_STATUS      0x50
//Found in wireshark add by wjl
#define CIP_FORWARD_OPEN    0x54
#define CIP_FORWARD_CLOSE   0x4e
#define CIP_UNCONNECTED_SEND 0x52

//PATH sizing codes
#define PATH_CLASS_8BIT         0x20
#define PATH_CLASS_16BIT        0x21
#define PATH_INSTANCE_8BIT      0x24
#define PATH_INSTANCE_16BIT     0x25
#define PATH_ATTR_8BIT          0x30
#define PATH_ATTR_16BIT         0x31 //possible value

#define CLASS_CONNECTION_MANAGER 0x06
#define CONNECTION_MANAGER_READ  0x4c
#define CONNECTION_MANAGER_WRITE 0x4d
#define ANSI_SEGMENT_TYPE        0x91

#pragma pack(push, 1)
typedef struct _encapsulation_header {
    uint16 command;        //封装命令
    uint16 length;         //消息头之后的字节数
    uint32 sesionhandle;   //会话句柄 会话标识
    uint32 status;         //状态码
    uint64 sendercontext;  //发件人上下文
    uint32 options;        //选项
} EncapsulationHeader, *PEncapsulationHeader;

/**
 * ENIP encapsulation data header
 */
typedef struct _ENIPEncapDataHdr {
    uint32 interface_handle;
    uint16 timeout;
    uint16 item_count;
} ENIPEncapDataHdr, *PENIPEncapDataHdr;

/**
 * ENIP encapsulation address item
 */
typedef struct _ENIPEncapAddresItem {
    uint16 type;
    uint16 length;
    uint32 conn_id;     //可选 不一定存在
    uint32 sequence_num;//可选 不一定存在
} ENIPEncapAddresItem, *PENIPEncapAddresItem;

/**
 * ENIP encapsulation data item
 */
typedef struct _ENIPEncapDataItem {
    uint16 type;
    uint16 length;
    uint16 sequence_count; //可选 不一定存在
} ENIPEncapDataItem, *PENIPEncapDataItem;

/**
 * CIP Request Header
 */
typedef struct _CIPReqHdr {
    uint8 service;
    uint8 path_size;
} CIPReqHdr, *PCIPReqHdr;

/**
 * CIP Response Header
 * 暂未使用
 */
typedef struct _CIPRespHdr {
    uint8 service;
    uint8 pad;
    uint8 status;
    uint8 status_size;
} CIPRespHdr, *PCIPRespHdr;

/**
 * CIP ConnectionManager对象头部
 */
typedef struct _CIPConnectionManagerHdr {
    uint8 ticktime;
    uint8 timeoutticks;
    uint16 requestsize;
    uint8 service;
    uint8 pathsize;
    uint8 segmenttype;
    uint8 datasize;
} CIPConnectionManagerHdr, *PCIPConnectionManagerHdr;

/**
 * CIP ConnectionManagerMSP对象头部
 */
typedef struct _CIPConnectionManagerMSPHdr {
    uint8 ticktime;
    uint8 timeoutticks;
    uint16 requestsize;
    uint8 service;
    uint8 pathsize;
    uint8 segmenttype1;
    uint8 classtype1;
    uint8 segmenttype2;
    uint8 instance;
    uint16 servicenum;
} CIPConnectionManagerMSPHdr, *PCIPConnectionManagerMSPHdr;

typedef struct _ServicePacketHdr {
    uint8 service;
    uint8 pathsize;
    uint8 segmenttype;
    uint8 datasize;
} ServicePacketHdr, *PServicePacketHdr;

typedef struct _PointTypeValue {
    uint16 type;
    uint16 num;
    uint8 ch[0];
} PointTypeValue, *PPointTypeValue;

#pragma pack(pop)

typedef struct _SegmentEntry {
    uint16 segment;   /**< segment type */
    uint16 value;     /**< segment value (class or attribute) */
} SegmentEntry;

typedef struct _AttributeEntry {
    uint16 attribute; /**< segment class */
} AttributeEntry;

enum CIPACTION {
    CIPActionNULL = 0,
    CIPReadAction = 1,
    CIPWriteAction = 2,
};
#define CIP_READ_STR "Read"
#define CIP_WRITE_STR "Write"

/**
 * 测点数据类型
 */
//网络资料：
//c1-bool
//c2-sint
//c3-short
//c4-int
//c7-ushort
//c8-uint
//ca-float
//cb-double
//d0-string
enum PointType {
    POINT_UNKNOWN = 0x0000,
    POINT_INT = 0x00C3,
    POINT_BOOL = 0x00C1,
    //POINT_LONG = 0x00C4,
    //POINT_BYTE = 0x00C2,
    POINT_FLOAT = 0x00CA,
};

class CIPParser
{
public:
    CIPParser(void);
    virtual ~CIPParser(void);
    bool parser(unsigned char *sdata, int slen);

    bool get_command(char *cmd, int cmdlen);
    bool get_enip_command(char *cmd, int cmdlen);
    bool get_action(char *cmd, int cmdlen);

    bool get_para(char *para, int parasize);
    bool get_pointname(char *name, int namelen);
    bool get_service(char *service, int srvlen);

    PointType get_pointtype(void);
    vector<int> get_vecint(void);
    vector<float> get_vecfloat(void);
    vector<int> get_vecbool(void);

private:
    void clear(void);
    void parser_more(unsigned char *sdata, int slen);

    void DecodeCommonPacketFormatPDU(unsigned char *input, int input_len, int offset_len);
    void DecodeReqisterSession(unsigned char *input, int input_len, int offset_len);
    void DecodeCIPPDU(unsigned char *input, int input_len, int offset_len);
    void DecodeCIPRequestPDU(unsigned char *input, int input_len, int offset_len);
    void DecodeService(unsigned char *input, int input_len, int offset_len);
    void DecodeCIPRequestPathPDU(unsigned char *input, int input_len, int offset_len);
    void DecodeConnectionManager(unsigned char *input, int input_len, int offset_len);
    void DecodeConnectionManagerMSP(unsigned char *input, int input_len, int offset_len);
    void GetTypeValue(unsigned char *input, int input_len, int offset_len);

    char m_pointname[MAX_POINT_NAME_LEN];//测点名称
    vector<SegmentEntry> m_segentry;     //暂未使用
    vector<AttributeEntry> m_attrentry;  //解析出的值 暂未使用

    CIPACTION m_action;                  //读取 or 写入  or 其他
    PEncapsulationHeader m_pheader;
    PENIPEncapDataHdr m_pdataheader;
    PCIPConnectionManagerHdr m_pconnmanhdr;
    PCIPConnectionManagerMSPHdr m_pconnmanmsphdr;
    PPointTypeValue m_ptypevalue;
    PCIPReqHdr m_pciprequestheader;

    ENIPEncapAddresItem m_addritem;
    ENIPEncapDataItem m_dataitem;

    vector<int> m_vecint;
    vector<float> m_vecfloat;
    vector<int> m_vecbool;
};

#endif
