/*******************************************************************************************
*文件:    dcom.h
*描述:    接口&方法定义，此部分无法保护所有window的标准定义
*
*作者:    张冬波
*日期:    2016-05-12
*修改:    创建文件                            ------>     2016-05-12
*         根据文档，定义接口&方法             ------>     2016-05-17
*
*******************************************************************************************/
#include "datatype.h"

#ifndef __DCOM_H__
#define __DCOM_H__

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

static const OPCDATA DCOMSET[] = {
    {"CLSID_ActivationContextInfo", uuid_l("000001a5-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ActivationPropertiesIn", uuid_l("00000338-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ActivationPropertiesOut", uuid_l("00000339-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_CONTEXT_EXTENSION", uuid_l("00000334-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ContextMarshaler", uuid_l("0000033b-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ERROR_EXTENSION", uuid_l("0000031c-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ErrorObject", uuid_l("0000031b-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_InstanceInfo", uuid_l("000001ad-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_InstantiationInfo", uuid_l("000001ab-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_PropsOutInfo", uuid_l("00000339-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ScmReplyInfo", uuid_l("000001b6-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ScmRequestInfo", uuid_l("000001aa-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_SecurityInfo", uuid_l("000001a6-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ServerLocationInfo", uuid_l("000001a4-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_SpecialSystemProperties", uuid_l("000001b9-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_ActivityUnmarshal", uuid_l("ecabafaa-7f19-11d2-978e-0000f8757e2a"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_SecurityEnvoy", uuid_l("ecabafab-7f19-11d2-978e-0000f8757e2a"), "", 0, 0, PROTO_RWNULL},
    {"CLSID_TransactionEnvoy", uuid_l("ecabafad-7f19-11d2-978e-0000f8757e2a"), "", 0, 0, PROTO_RWNULL},

    //native RPC interface
    {"IID_IActivation", uuid_l("4d9f4ab8-7d1c-11cf-861e-0020af6e7c57"), "RemoteActivation", 0, 0, PROTO_RWNULL},
    {"IID_IRemoteActivation", uuid_l("4d9f4ab8-7d1c-11cf-861e-0020af6e7c57"), "RemoteActivation", 0, 0, PROTO_RWNULL},

    {"IID_IActivationPropertiesIn", uuid_l("000001a2-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},
    {"IID_IActivationPropertiesOut", uuid_l("000001a3-0000-0000-c000-000000000046"), "", 0, 0, PROTO_RWNULL},

    {"IID_IContext", uuid_l("000001c0-0000-0000-c000-000000000046"), "EnumContextProps", 3, 0, PROTO_READ},
    {"IID_IContext", uuid_l("000001c0-0000-0000-c000-000000000046"), "GetProperty", 4, 0, PROTO_READ},
    {"IID_IContext", uuid_l("000001c0-0000-0000-c000-000000000046"), "RemoveProperty", 5, 0, PROTO_RWNULL},
    {"IID_IContext", uuid_l("000001c0-0000-0000-c000-000000000046"), "SetProperty", 6, 0, PROTO_WRITE},

    //native RPC interface
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "ResolveOxid", 0, 0, PROTO_RWNULL},
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "SimplePing", 1, 0, PROTO_RWNULL},
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "ComplexPing", 2, 0, PROTO_RWNULL},
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "ServerAlive", 3, 0, PROTO_RWNULL},
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "ResolveOxid2", 4, 0, PROTO_RWNULL},
    {"IID_IObjectExporter", uuid_l("99fcfec4-5260-101b-bbcb-00aa0021347a"), "ServerAlive2", 5, 0, PROTO_RWNULL},

    {"IID_IRemoteSCMActivator", uuid_l("000001a0-0000-0000-c000-000000000046"), "RemoteGetClassObject", 3, 0, PROTO_READ},
    {"IID_IRemoteSCMActivator", uuid_l("000001a0-0000-0000-c000-000000000046"), "RemoteCreateInstance", 4, 0, PROTO_WRITE},

    {"IID_IRemUnknown", uuid_l("00000131-0000-0000-c000-000000000046"), "RemQueryInterface", 3, 0, PROTO_READ},
    {"IID_IRemUnknown", uuid_l("00000131-0000-0000-c000-000000000046"), "RemAddRef", 4, 0, PROTO_RWNULL},
    {"IID_IRemUnknown", uuid_l("00000131-0000-0000-c000-000000000046"), "RemRelease", 5, 0, PROTO_RWNULL},

    {"IID_IRemUnknown2", uuid_l("00000143-0000-0000-c000-000000000046"), "RemQueryInterface2", 6, 0, PROTO_READ},

    {"IID_IUnknown", uuid_l("00000000-0000-0000-c000-000000000046"), "QueryInterface", 0, 0, PROTO_READ},
    {"IID_IUnknown", uuid_l("00000000-0000-0000-c000-000000000046"), "AddRef", 1, 0, PROTO_WRITE},
    {"IID_IUnknown", uuid_l("00000000-0000-0000-c000-000000000046"), "Release", 2, 0, PROTO_RWNULL},

    //COM+
    {"IID_ITransactionStream", uuid_l("97199110-db2e-11d1-a251-0000f805ca53"), "GetSeqAndTxViaExport", 3, 0, PROTO_READ},
    {"IID_ITransactionStream", uuid_l("97199110-db2e-11d1-a251-0000f805ca53"), "GetSeqAndTxViaTransmitter", 4, 0, PROTO_READ},
    {"IID_ITransactionStream", uuid_l("97199110-db2e-11d1-a251-0000f805ca53"), "GetTxViaExport", 5, 0, PROTO_READ},
    {"IID_ITransactionStream", uuid_l("97199110-db2e-11d1-a251-0000f805ca53"), "GetTxViaTransmitter", 6, 0, PROTO_READ},

    //COM
    {"IID_IConnectionPointContainer", uuid_u("B196B284-BAB4-101A-B69C-00AA00341D07"), "EnumConnectionPoints", 3, 0, PROTO_READ},
    {"IID_IConnectionPointContainer", uuid_u("B196B284-BAB4-101A-B69C-00AA00341D07"), "FindConnectionPoint", 4, 0, PROTO_READ},

    {"IID_IConnectionPoint", uuid_u("B196B286-BAB4-101A-B69C-00AA00341D07"), "GetConnectionInterface", 3, 0, PROTO_READ},
    {"IID_IConnectionPoint", uuid_u("B196B286-BAB4-101A-B69C-00AA00341D07"), "GetConnectionPointContainer", 4, 0, PROTO_READ},
    {"IID_IConnectionPoint", uuid_u("B196B286-BAB4-101A-B69C-00AA00341D07"), "Advise", 5, 0, PROTO_RWNULL},
    {"IID_IConnectionPoint", uuid_u("B196B286-BAB4-101A-B69C-00AA00341D07"), "Unadvise", 6, 0, PROTO_RWNULL},
    {"IID_IConnectionPoint", uuid_u("B196B286-BAB4-101A-B69C-00AA00341D07"), "EnumConnections", 7, 0, PROTO_READ},

    {"IID_IAdviseSink", uuid_u("0000010F-0000-0000-C000-000000000046"), "OnClose", 3, 0, PROTO_RWNULL},
    {"IID_IAdviseSink", uuid_u("0000010F-0000-0000-C000-000000000046"), "OnDataChange", 4, 0, PROTO_RWNULL},
    {"IID_IAdviseSink", uuid_u("0000010F-0000-0000-C000-000000000046"), "OnRename", 5, 0, PROTO_RWNULL},
    {"IID_IAdviseSink", uuid_u("0000010F-0000-0000-C000-000000000046"), "OnSave", 6, 0, PROTO_RWNULL},
    {"IID_IAdviseSink", uuid_u("0000010F-0000-0000-C000-000000000046"), "OnViewChange", 7, 0, PROTO_RWNULL},

    {"IID_IPersist", uuid_u("0000010C-0000-0000-C000-000000000046"), "GetClassID", 3, 0, PROTO_READ},

    {"IID_IPersistFile", uuid_u("0000010B-0000-0000-C000-000000000046"), "GetCurFile", 4, 0, PROTO_READ},   //继承IID_IPersist
    {"IID_IPersistFile", uuid_u("0000010B-0000-0000-C000-000000000046"), "IsDirty", 5, 0, PROTO_READ},
    {"IID_IPersistFile", uuid_u("0000010B-0000-0000-C000-000000000046"), "Load", 6, 0, PROTO_RWNULL},
    {"IID_IPersistFile", uuid_u("0000010B-0000-0000-C000-000000000046"), "Save", 7, 0, PROTO_RWNULL},
    {"IID_IPersistFile", uuid_u("0000010B-0000-0000-C000-000000000046"), "SaveCompleted", 8, 0, PROTO_RWNULL},

    {"IID_IEnumGUID", uuid_u("0002E000-0000-0000-C000-000000000046"), "Next", 3, 0, PROTO_RWNULL},
    {"IID_IEnumGUID", uuid_u("0002E000-0000-0000-C000-000000000046"), "Skip", 4, 0, PROTO_RWNULL},
    {"IID_IEnumGUID", uuid_u("0002E000-0000-0000-C000-000000000046"), "Reset", 5, 0, PROTO_WRITE},
    {"IID_IEnumGUID", uuid_u("0002E000-0000-0000-C000-000000000046"), "Clone", 6, 0, PROTO_RWNULL},

    {"IID_IEnumString", uuid_u("00000101-0000-0000-C000-000000000046"), "Next", 3, 0, PROTO_RWNULL},
    {"IID_IEnumString", uuid_u("00000101-0000-0000-C000-000000000046"), "Skip", 4, 0, PROTO_RWNULL},
    {"IID_IEnumString", uuid_u("00000101-0000-0000-C000-000000000046"), "Reset", 5, 0, PROTO_WRITE},
    {"IID_IEnumString", uuid_u("00000101-0000-0000-C000-000000000046"), "Clone", 6, 0, PROTO_RWNULL},

    {"IID_IDispatch", uuid_u("00020400-0000-0000-C000-000000000046"), "GetTypeInfoCount", 3, 0, PROTO_READ},
    {"IID_IDispatch", uuid_u("00020400-0000-0000-C000-000000000046"), "GetTypeInfo", 4, 0, PROTO_READ},
    {"IID_IDispatch", uuid_u("00020400-0000-0000-C000-000000000046"), "GetIDsOfNames", 5, 0, PROTO_READ},
    {"IID_IDispatch", uuid_u("00020400-0000-0000-C000-000000000046"), "Invoke", 6, 0, PROTO_RWNULL},


    //结束标志
    {NULL, {0}, NULL, 0, 0, PROTO_RWNULL},
};

#endif

