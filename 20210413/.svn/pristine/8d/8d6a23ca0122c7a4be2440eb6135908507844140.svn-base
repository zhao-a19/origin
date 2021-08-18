/*******************************************************************************************
*文件:    opc-da.h
*描述:    接口&方法定义
*         方法定义值需根据继承关系和文档说明顺序+1，仅为猜测！！！
*         大部分都继承自IUnknown, 其占用了0,1,2的方法定义，
*         如定义处未做特殊声明，则默认继承IUnknown
*
*作者:    张冬波
*日期:    2016-05-12
*修改:    创建文件                            ------>     2016-05-12
*         根据文档，定义接口&方法             ------>     2016-05-17
*
*******************************************************************************************/
#include "datatype.h"

#ifndef __OPC_DA_H__
#define __OPC_DA_H__

#ifndef __UUID_SET__
#define __UUID_SET__

#define charnum(c) ((((c) >= 'a') && ((c) <= 'z')) ? ((c) - 'a' + 10) : ((c) - '0'))
#define ucharnum(c) ((((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 10) : ((c) - '0'))

//小写字符
#define uuid_l(ids) { \
    (charnum(*(ids))*16)+(charnum(*(ids+1))),   \
    (charnum(*(ids+2))*16)+(charnum(*(ids+3))),   \
    (charnum(*(ids+4))*16)+(charnum(*(ids+5))),   \
    (charnum(*(ids+6))*16)+(charnum(*(ids+7))),   \
    (charnum(*(ids+9))*16)+(charnum(*(ids+10))),   \
    (charnum(*(ids+11))*16)+(charnum(*(ids+12))),   \
    (charnum(*(ids+14))*16)+(charnum(*(ids+15))),   \
    (charnum(*(ids+16))*16)+(charnum(*(ids+17))),   \
    (charnum(*(ids+19))*16)+(charnum(*(ids+20))),   \
    (charnum(*(ids+21))*16)+(charnum(*(ids+22))),   \
    (charnum(*(ids+24))*16)+(charnum(*(ids+25))),   \
    (charnum(*(ids+26))*16)+(charnum(*(ids+27))),   \
    (charnum(*(ids+28))*16)+(charnum(*(ids+29))),   \
    (charnum(*(ids+30))*16)+(charnum(*(ids+31))),   \
    (charnum(*(ids+32))*16)+(charnum(*(ids+33))),   \
    (charnum(*(ids+34))*16)+(charnum(*(ids+35)))   \
}

//大写字符
#define uuid_u(ids) { \
    (ucharnum(*(ids))*16)+(ucharnum(*(ids+1))),   \
    (ucharnum(*(ids+2))*16)+(ucharnum(*(ids+3))),   \
    (ucharnum(*(ids+4))*16)+(ucharnum(*(ids+5))),   \
    (ucharnum(*(ids+6))*16)+(ucharnum(*(ids+7))),   \
    (ucharnum(*(ids+9))*16)+(ucharnum(*(ids+10))),   \
    (ucharnum(*(ids+11))*16)+(ucharnum(*(ids+12))),   \
    (ucharnum(*(ids+14))*16)+(ucharnum(*(ids+15))),   \
    (ucharnum(*(ids+16))*16)+(ucharnum(*(ids+17))),   \
    (ucharnum(*(ids+19))*16)+(ucharnum(*(ids+20))),   \
    (ucharnum(*(ids+21))*16)+(ucharnum(*(ids+22))),   \
    (ucharnum(*(ids+24))*16)+(ucharnum(*(ids+25))),   \
    (ucharnum(*(ids+26))*16)+(ucharnum(*(ids+27))),   \
    (ucharnum(*(ids+28))*16)+(ucharnum(*(ids+29))),   \
    (ucharnum(*(ids+30))*16)+(ucharnum(*(ids+31))),   \
    (ucharnum(*(ids+32))*16)+(ucharnum(*(ids+33))),   \
    (ucharnum(*(ids+34))*16)+(ucharnum(*(ids+35)))   \
}

typedef struct {
    const pchar ifname;
    uint8 uuid[16];
    const pchar opname; //""表示所有方法
    uint16 opnum;
    uint8 flag;     //处理标识，0：系统默认接口（用户不可过滤）
    int32 rw;       //读写配置
} OPCDATA, *POPCDATA;

#endif

static const OPCDATA OPCDASET[] = {
    //V1.0
    {"IOPCShutdown", uuid_u("F31DFDE1-07B6-11D2-B2D8-0060083BA1FB"), "ShutdownRequest", 3, 1, PROTO_WRITE},

    {"IOPCCommon", uuid_u("F31DFDE2-07B6-11D2-B2D8-0060083BA1FB"), "SetLocaleID", 3, 1, PROTO_WRITE},
    {"IOPCCommon", uuid_u("F31DFDE2-07B6-11D2-B2D8-0060083BA1FB"), "GetLocaleID", 4, 1, PROTO_READ},
    {"IOPCCommon", uuid_u("F31DFDE2-07B6-11D2-B2D8-0060083BA1FB"), "QueryAvailableLocaleIDs", 5, 1, PROTO_READ},
    {"IOPCCommon", uuid_u("F31DFDE2-07B6-11D2-B2D8-0060083BA1FB"), "GetErrorString", 6, 1, PROTO_READ},
    {"IOPCCommon", uuid_u("F31DFDE2-07B6-11D2-B2D8-0060083BA1FB"), "SetClientName", 7, 1, PROTO_WRITE},

    {"IOPCServerList", uuid_u("13486D50-4821-11D2-A494-3CB306C10000"), "EnumClassesOfCategories", 3, 1, PROTO_RWNULL},
    {"IOPCServerList", uuid_u("13486D50-4821-11D2-A494-3CB306C10000"), "GetClassDetails", 4, 1, PROTO_RWNULL},
    {"IOPCServerList", uuid_u("13486D50-4821-11D2-A494-3CB306C10000"), "CLSIDFromProgID", 5, 1, PROTO_RWNULL},

    //OPCCOMN 1.0 Type Library
    {"OPCCOMN", uuid_u("B28EEDB1-AC6F-11D1-84D5-00608CB8A7E9"), "", 0, 0, PROTO_RWNULL},

    //V2.02, 继承IDispatch，接口中相同方法名的值定义??
    {"IOPCServerEvent", uuid_u("28E68F90-8D75-11D1-8DC3-3C302A000000"), "ServerShutDown", 7, 1, PROTO_WRITE},
    {"IOPCGroupsEvent", uuid_u("28E68F9C-8D75-11D1-8DC3-3C302A000000"), "GlobalDataChange", 7, 1, PROTO_WRITE},

    {"IOPCGroupEvent", uuid_u("28E68F90-8D75-11D1-8DC3-3C302A000001"), "DataChange", 7, 1, PROTO_WRITE},
    {"IOPCGroupEvent", uuid_u("28E68F90-8D75-11D1-8DC3-3C302A000001"), "AsyncReadComplete", 8, 1, PROTO_READ},
    {"IOPCGroupEvent", uuid_u("28E68F90-8D75-11D1-8DC3-3C302A000001"), "AsyncWriteComplete", 9, 1, PROTO_WRITE},
    {"IOPCGroupEvent", uuid_u("28E68F90-8D75-11D1-8DC3-3C302A000001"), "AsyncCancelComplete", 10, 1, PROTO_WRITE},

    //OPC Automation 2.0
    {"OPCAutomation", uuid_u("28E68F91-8D75-11D1-8DC3-3C302A000000"), "", 0, 0, PROTO_RWNULL},

    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "StartTime", 7, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "CurrentTime", 8, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "LastUpdateTime", 9, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "MajorVersion", 10, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "MinorVersion", 11, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "BuildNumber", 12, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "VendorInfo", 13, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "ServerState", 14, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "ServerName", 15, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "ServerNode", 16, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "ClientName", 17, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "ClientName", 18, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "LocaleID", 19, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "LocaleID", 20, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "Bandwidth", 21, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "OPCGroups", 22, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "PublicGroupNames", 23, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "GetOPCServers", 24, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "Connect", 25, 1, PROTO_WRITE},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "Disconnect", 26, 1, PROTO_WRITE},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "CreateBrowser", 27, 1, PROTO_WRITE},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "GetErrorString", 28, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "QueryAvailableLocaleIDs", 29, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "QueryAvailableProperties", 30, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "GetItemProperties", 31, 1, PROTO_READ},
    {"IOPCAutoServer", uuid_u("28E68F92-8D75-11D1-8DC3-3C302A000000"), "LookupItemIDs", 32, 1, PROTO_READ},

    {"DIOPCServerEvent", uuid_u("28E68F93-8D75-11D1-8DC3-3C302A000000"), "ServerShutDown", 0, 0, PROTO_WRITE},

    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "Organization", 7, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "Filter", 8, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "Filter", 9, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "DataType", 10, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "DataType", 11, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "AccessRights", 12, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "AccessRights", 13, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "CurrentPosition", 14, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "Count", 15, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "_NewEnum", 16, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "Item", 17, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "ShowBranches", 18, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "ShowLeafs", 19, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "MoveUp", 20, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "MoveToRoot", 21, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "MoveDown", 22, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "MoveTo", 23, 1, PROTO_RWNULL},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "GetItemID", 24, 1, PROTO_READ},
    {"OPCBrowser", uuid_u("28E68F94-8D75-11D1-8DC3-3C302A000000"), "GetAccessPaths", 25, 1, PROTO_READ},

    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "Parent", 7, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupIsActive", 8, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupIsActive", 9, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupUpdateRate", 10, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupUpdateRate", 11, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupDeadband", 12, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupDeadband", 13, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupLocaleID", 14, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupLocaleID", 15, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupTimeBias", 16, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "DefaultGroupTimeBias", 17, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "Count", 18, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "_NewEnum", 19, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "Item", 20, 1, PROTO_RWNULL},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "Add", 21, 1, PROTO_WRITE},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "GetOPCGroup", 22, 1, PROTO_READ},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "RemoveAll", 23, 1, PROTO_WRITE},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "Remove", 24, 1, PROTO_WRITE},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "ConnectPublicGroup", 25, 1, PROTO_WRITE},
    {"IOPCGroups", uuid_u("28E68F95-8D75-11D1-8DC3-3C302A000000"), "RemovePublicGroup", 26, 1, PROTO_WRITE},

    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "Parent", 7, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "Name", 8, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "Name", 9, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "IsPublic", 10, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "IsActive", 11, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "IsActive", 12, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "IsSubscribed", 13, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "IsSubscribed", 14, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "ClientHandle", 15, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "ClientHandle", 16, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "ServerHandle", 17, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "LocaleID", 18, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "LocaleID", 19, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "TimeBias", 20, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "TimeBias", 21, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "DeadBand", 22, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "DeadBand", 23, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "UpdateRate", 24, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "UpdateRate", 25, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "OPCItems", 26, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "SyncRead", 27, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "SyncWrite", 28, 1, PROTO_WRITE},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "AsyncRead", 29, 1, PROTO_READ},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "AsyncWrite", 30, 1, PROTO_WRITE},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "AsyncRefresh", 31, 1, PROTO_RWNULL},
    {"IOPCGroup", uuid_u("28E68F96-8D75-11D1-8DC3-3C302A000000"), "AsyncCancel", 32, 1, PROTO_RWNULL},

    {"DIOPCGroupEvent", uuid_u("28E68F97-8D75-11D1-8DC3-3C302A000000"), "DataChange", 0, 0, PROTO_WRITE},
    {"DIOPCGroupEvent", uuid_u("28E68F97-8D75-11D1-8DC3-3C302A000000"), "AsyncReadComplete", 0, 0, PROTO_READ},
    {"DIOPCGroupEvent", uuid_u("28E68F97-8D75-11D1-8DC3-3C302A000000"), "AsyncWriteComplete", 0, 0, PROTO_WRITE},
    {"DIOPCGroupEvent", uuid_u("28E68F97-8D75-11D1-8DC3-3C302A000000"), "AsyncCancelComplete", 0, PROTO_WRITE},

    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "Parent", 7, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultRequestedDataType", 8, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultRequestedDataType", 9, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultAccessPath", 10, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultAccessPath", 11, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultIsActive", 12, 1, PROTO_READ},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "DefaultIsActive", 13, 1, PROTO_READ},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "Count", 14, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "_NewEnum", 15, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "Item", 16, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "GetOPCItem", 17, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "AddItem", 18, 1, PROTO_WRITE},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "AddItems", 19, 1, PROTO_WRITE},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "Remove", 20, 1, PROTO_WRITE},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "Validate", 21, 1, PROTO_RWNULL},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "SetActive", 22, 1, PROTO_WRITE},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "SetClientHandles", 23, 1, PROTO_WRITE},
    {"OPCItems", uuid_u("28E68F98-8D75-11D1-8DC3-3C302A000000"), "SetDataTypes", 24, 1, PROTO_WRITE},

    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "Parent", 7, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "ClientHandle", 8, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "ClientHandle", 9, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "ServerHandle", 10, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "AccessPath", 11, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "AccessRights", 12, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "ItemID", 13, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "IsActive", 14, 1, PROTO_READ},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "IsActive", 15, 1, PROTO_READ},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "RequestedDataType", 16, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "RequestedDataType", 17, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "Value", 18, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "Quality", 19, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "TimeStamp", 20, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "CanonicalDataType", 21, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "EUType", 22, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "EUInfo", 23, 1, PROTO_RWNULL},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "Read", 24, 1, PROTO_READ},
    {"OPCItem", uuid_u("28E68F99-8D75-11D1-8DC3-3C302A000000"), "Write", 25, 1, PROTO_WRITE},

    {"DIOPCGroupsEvent", uuid_u("28E68F9D-8D75-11D1-8DC3-3C302A000000"), "GlobalDataChange", 0, 0, PROTO_RWNULL},

    //V3.00

    //OPC Data Access Servers Version 1.0
    {"CATID_OPCDAServer10", uuid_u("63D5F430-CFE4-11D1-B2C8-0060083BA1FB"), "", 0, 0, PROTO_RWNULL},
    //OPC Data Access Servers Version 2.0
    {"CATID_OPCDAServer20", uuid_u("63D5F432-CFE4-11D1-B2C8-0060083BA1FB"), "", 0, 0, PROTO_RWNULL},
    //OPC Data Access Servers Version 3.0
    {"CATID_OPCDAServer30", uuid_u("CC603642-66D7-48F1-B69A-B625E73652D7"), "", 0, 0, PROTO_RWNULL},

    {"CATID_XMLDAServer10", uuid_u("3098EDA4-A006-48B2-A27F-247453959408"), "", 0, 0, PROTO_RWNULL},

    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "AddGroup", 3, 0, PROTO_RWNULL},
    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "GetErrorString", 4, 0, PROTO_RWNULL},
    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "GetGroupByName", 5, 0, PROTO_RWNULL},
    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "GetStatus", 6, 0, PROTO_RWNULL},
    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "RemoveGroup", 7, 0, PROTO_RWNULL},
    {"IOPCServer", uuid_l("39c13a4d-011e-11d0-9675-0020afd8adb3"), "CreateGroupEnumerator", 8, 0, PROTO_RWNULL},

    {"IOPCServerPublicGroups", uuid_l("39c13a4e-011e-11d0-9675-0020afd8adb3"), "GetPublicGroupByName", 3, 1, PROTO_READ},
    {"IOPCServerPublicGroups", uuid_l("39c13a4e-011e-11d0-9675-0020afd8adb3"), "RemovePublicGroup", 4, 1, PROTO_WRITE},

    {"IOPCBrowseServerAddressSpace", uuid_l("39c13a4f-011e-11d0-9675-0020afd8adb3"), "QueryOrganization", 3, 0, PROTO_READ},
    {"IOPCBrowseServerAddressSpace", uuid_l("39c13a4f-011e-11d0-9675-0020afd8adb3"), "ChangeBrowsePosition", 4, 0, PROTO_READ},
    {"IOPCBrowseServerAddressSpace", uuid_l("39c13a4f-011e-11d0-9675-0020afd8adb3"), "BrowseOPCItemIDs", 5, 0, PROTO_READ},
    {"IOPCBrowseServerAddressSpace", uuid_l("39c13a4f-011e-11d0-9675-0020afd8adb3"), "GetItemID", 6, 0, PROTO_READ},
    {"IOPCBrowseServerAddressSpace", uuid_l("39c13a4f-011e-11d0-9675-0020afd8adb3"), "BrowseAccessPaths", 7, 0, PROTO_READ},

    {"IOPCGroupStateMgt", uuid_l("39c13a50-011e-11d0-9675-0020afd8adb3"), "GetState", 3, 0, PROTO_RWNULL},
    {"IOPCGroupStateMgt", uuid_l("39c13a50-011e-11d0-9675-0020afd8adb3"), "SetState", 4, 0, PROTO_RWNULL},
    {"IOPCGroupStateMgt", uuid_l("39c13a50-011e-11d0-9675-0020afd8adb3"), "SetName", 5, 0, PROTO_RWNULL},
    {"IOPCGroupStateMgt", uuid_l("39c13a50-011e-11d0-9675-0020afd8adb3"), "CloneGroup", 6, 0, PROTO_RWNULL},

    {"IOPCPublicGroupStateMgt", uuid_l("39c13a51-011e-11d0-9675-0020afd8adb3"), "GetState", 3, 1, PROTO_READ},
    {"IOPCPublicGroupStateMgt", uuid_l("39c13a51-011e-11d0-9675-0020afd8adb3"), "MoveToPublic", 4, 1, PROTO_WRITE},

    {"IOPCSyncIO", uuid_l("39c13a52-011e-11d0-9675-0020afd8adb3"), "Read", 3, 1, PROTO_READ},
    {"IOPCSyncIO", uuid_l("39c13a52-011e-11d0-9675-0020afd8adb3"), "Write", 4, 1, PROTO_WRITE},

    {"IOPCAsyncIO", uuid_l("39c13a53-011e-11d0-9675-0020afd8adb3"), "Read", 3, 1, PROTO_READ},
    {"IOPCAsyncIO", uuid_l("39c13a53-011e-11d0-9675-0020afd8adb3"), "Write", 4, 1, PROTO_WRITE},
    {"IOPCAsyncIO", uuid_l("39c13a53-011e-11d0-9675-0020afd8adb3"), "Refresh", 5, 1, PROTO_RWNULL},
    {"IOPCAsyncIO", uuid_l("39c13a53-011e-11d0-9675-0020afd8adb3"), "Cancel", 6, 1, PROTO_WRITE},

    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "AddItems", 3, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "ValidateItems", 4, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "RemoveItems", 5, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "SetActiveState", 6, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "SetClientHandles", 7, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "SetDatatypes", 8, 0, PROTO_RWNULL},
    {"IOPCItemMgt", uuid_l("39c13a54-011e-11d0-9675-0020afd8adb3"), "CreateEnumerator", 9, 0, PROTO_RWNULL},

    {"IEnumOPCItemAttributes", uuid_l("39c13a55-011e-11d0-9675-0020afd8adb3"), "Next", 3, 1, PROTO_RWNULL},
    {"IEnumOPCItemAttributes", uuid_l("39c13a55-011e-11d0-9675-0020afd8adb3"), "Skip", 4, 1, PROTO_RWNULL},
    {"IEnumOPCItemAttributes", uuid_l("39c13a55-011e-11d0-9675-0020afd8adb3"), "Reset", 5, 1, PROTO_RWNULL},
    {"IEnumOPCItemAttributes", uuid_l("39c13a55-011e-11d0-9675-0020afd8adb3"), "Clone", 6, 1, PROTO_RWNULL},

    {"IOPCDataCallback", uuid_l("39c13a70-011e-11d0-9675-0020afd8adb3"), "OnDataChange", 3, 1, PROTO_RWNULL},
    {"IOPCDataCallback", uuid_l("39c13a70-011e-11d0-9675-0020afd8adb3"), "OnReadComplete", 4, 1, PROTO_RWNULL},
    {"IOPCDataCallback", uuid_l("39c13a70-011e-11d0-9675-0020afd8adb3"), "OnWriteComplete", 5, 1, PROTO_RWNULL},
    {"IOPCDataCallback", uuid_l("39c13a70-011e-11d0-9675-0020afd8adb3"), "OnCancelComplete", 6, 1, PROTO_RWNULL},

    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "Read", 3, 1, PROTO_READ},
    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "Write", 4, 1, PROTO_WRITE},
    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "Refresh2", 5, 1, PROTO_RWNULL},
    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "Cancel2", 6, 1, PROTO_WRITE},
    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "SetEnable", 7, 1, PROTO_WRITE},
    {"IOPCAsyncIO2", uuid_l("39c13a71-011e-11d0-9675-0020afd8adb3"), "GetEnable", 8, 1, PROTO_READ},

    {"IOPCItemProperties", uuid_l("39c13a72-011e-11d0-9675-0020afd8adb3"), "QueryAvailableProperties", 3, 1, PROTO_RWNULL},
    {"IOPCItemProperties", uuid_l("39c13a72-011e-11d0-9675-0020afd8adb3"), "GetItemProperties", 4, 1, PROTO_RWNULL},
    {"IOPCItemProperties", uuid_l("39c13a72-011e-11d0-9675-0020afd8adb3"), "LookupItemIDs", 5, 1, PROTO_RWNULL},

    {"IOPCItemDeadbandMgt", uuid_u("5946DA93-8B39-4EC8-AB3D-AA73DF5BC86F"), "SetItemDeadband", 3, 1, PROTO_WRITE},
    {"IOPCItemDeadbandMgt", uuid_u("5946DA93-8B39-4EC8-AB3D-AA73DF5BC86F"), "GetItemDeadband", 4, 1, PROTO_READ},
    {"IOPCItemDeadbandMgt", uuid_u("5946DA93-8B39-4EC8-AB3D-AA73DF5BC86F"), "ClearItemDeadband", 5, 1, PROTO_WRITE},

    {"IOPCItemSamplingMgt", uuid_u("3E22D313-F08B-41A5-86C8-95E95CB49FFC"), "SetItemSamplingRate", 3, 1, PROTO_WRITE},
    {"IOPCItemSamplingMgt", uuid_u("3E22D313-F08B-41A5-86C8-95E95CB49FFC"), "GetItemSamplingRate", 4, 1, PROTO_READ},
    {"IOPCItemSamplingMgt", uuid_u("3E22D313-F08B-41A5-86C8-95E95CB49FFC"), "ClearItemSamplingRate", 5, 1, PROTO_WRITE},
    {"IOPCItemSamplingMgt", uuid_u("3E22D313-F08B-41A5-86C8-95E95CB49FFC"), "SetItemBufferEnable", 6, 1, PROTO_WRITE},
    {"IOPCItemSamplingMgt", uuid_u("3E22D313-F08B-41A5-86C8-95E95CB49FFC"), "GetItemBufferEnable", 7, 1, PROTO_READ},

    {"IOPCBrowse", uuid_u("39227004-A18F-4B57-8B0A-5235670F4468"), "GetProperties", 3, 1, PROTO_READ},
    {"IOPCBrowse", uuid_u("39227004-A18F-4B57-8B0A-5235670F4468"), "Browse", 4, 1, PROTO_READ},

    {"IOPCItemIO", uuid_u("85C0B427-2893-4CBC-BD78-E5FC5146F08F"), "Read", 3, PROTO_READ},
    {"IOPCItemIO", uuid_u("85C0B427-2893-4CBC-BD78-E5FC5146F08F"), "WriteVQT", 4, 1, PROTO_WRITE},

    {"IOPCSyncIO2", uuid_u("730F5F0F-55B1-4C81-9E18-FF8A0904E1FA"), "ReadMaxAge", 5, 1, PROTO_READ},    //继承IOPCSyncIO
    {"IOPCSyncIO2", uuid_u("730F5F0F-55B1-4C81-9E18-FF8A0904E1FA"), "WriteVQT", 6, 1, PROTO_WRITE},

    {"IOPCAsyncIO3", uuid_u("0967B97B-36EF-423E-B6F8-6BFF1E40D39D"), "ReadMaxAge", 5, 1, PROTO_READ},   //继承IOPCAsyncIO2
    {"IOPCAsyncIO3", uuid_u("0967B97B-36EF-423E-B6F8-6BFF1E40D39D"), "WriteVQT", 6, 1, PROTO_WRITE},
    {"IOPCAsyncIO3", uuid_u("0967B97B-36EF-423E-B6F8-6BFF1E40D39D"), "RefreshMaxAge", 7, 1, PROTO_RWNULL},

    {"IOPCGroupStateMgt2", uuid_u("8E368666-D72E-4F78-87ED-647611C61C9F"), "SetKeepAlive", 7, 1, PROTO_WRITE},   //继承IOPCGroupStateMgt
    {"IOPCGroupStateMgt2", uuid_u("8E368666-D72E-4F78-87ED-647611C61C9F"), "GetKeepAlive", 8, 1, PROTO_READ},

    //OPC Data Access 3.00 Type Library
    {"OPCDA", uuid_u("3B540B51-0378-4551-ADCC-EA9B104302BF"), "", 0, 0, PROTO_RWNULL},

    //文档中未提及
    {"IOPCEnumGUID", uuid_u("55C382C8-21C7-4E88-96C1-BECFB1E3F483"), "Next", 3, 0, PROTO_RWNULL},
    {"IOPCEnumGUID", uuid_u("55C382C8-21C7-4E88-96C1-BECFB1E3F483"), "Skip", 4, 0, PROTO_RWNULL},
    {"IOPCEnumGUID", uuid_u("55C382C8-21C7-4E88-96C1-BECFB1E3F483"), "Reset", 5, 0, PROTO_WRITE},
    {"IOPCEnumGUID", uuid_u("55C382C8-21C7-4E88-96C1-BECFB1E3F483"), "Clone", 6, 0, PROTO_RWNULL},

    {"IOPCServerList2", uuid_u("9DD0B56C-AD9E-43EE-8305-487F3188BF7A"), "EnumClassesOfCategories", 3, 1, PROTO_RWNULL},
    {"IOPCServerList2", uuid_u("9DD0B56C-AD9E-43EE-8305-487F3188BF7A"), "GetClassDetails", 4, 1, PROTO_READ},
    {"IOPCServerList2", uuid_u("9DD0B56C-AD9E-43EE-8305-487F3188BF7A"), "CLSIDFromProgID", 5, 1, PROTO_RWNULL},

    //结束标志
    {NULL, {0}, NULL, 0, 0, PROTO_RWNULL},
};

#endif

