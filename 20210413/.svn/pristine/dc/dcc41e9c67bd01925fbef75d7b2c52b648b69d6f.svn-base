/*******************************************************************************************
*文件:  FCDCSOPCSingle.h
*描述:  OPC模块
*作者:  王君雷
*日期:  2016-03
*修改:
*         添加函数getport                                           ------> 2018-02-28
*         根据五元组追踪每一个连接,解决读写控制不住的问题,日志易读  ------> 2018-03-30
*         命令和参数长度使用宏表示                                  ------> 2018-12-21
*         解决OPC动态端口使用short类型的错误                        ------> 2019-06-25
*******************************************************************************************/
#ifndef __FC_DCSOPCSINGLE_H__
#define __FC_DCSOPCSINGLE_H__

#include "FCSingle.h"
#include <vector>

//必须定义，因为引用了库libsuricata.a的编译为C格式定义
#ifdef __cplusplus
extern "C" {
#endif

#include "zdb_porting.h"
#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"
#include "pcre.h"

#define MAX_OPC_DYNAMIC_SIZE 1000
#define MAX_OPC_STATIC_SIZE 500
#define OPC_TIME_OUT_SECOND (10 * 60)  //超时X秒，复用结构

#define BIN2IP(ip, data) {memcpy(&(ip), data, 4);}
//#define BIN2PORT(port, data) {port = ((data)[0] * 256) + (data)[1];}
#define uuidequal(s1, s2) (memcmp(s1, s2, 16) == 0)

#define _DCEMEM_(h, m)      ((h).dcerpc.m)
#define _DCEMEM_H_(h, m)    ((h).dcerpc.dcerpchdr.m)
#define _DCEMEM_REQ_(h, m)  ((h).dcerpc.dcerpcrequest.m)
#define _DCEMEM_RSP_(h, m)  ((h).dcerpc.dcerpcresponse.m)

typedef struct _datanetaddr {
    uint32 srcaddr;     //源IP
    uint16 srcport;   //源端口
    uint32 dstaddr;     //目的IP
    uint16 dstport;   //目的端口
} DATANETADDR, *PDATANETADDR;

typedef struct OPCDATAFLOW {
    DATANETADDR addr;
    time_t timestamp;
    DCERPCState dcerpchandle;
} OPCDATAFLOW;

class CDCSOPCSINGLE : public CSINGLE
{
public:
    CDCSOPCSINGLE();
    ~CDCSOPCSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool IfMatchDynamic(unsigned char *sdata, int &index);
    bool DoMsgDY(unsigned char *sdata, int slen, char *cherror, int *pktchange, int index);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror, DCERPCState *phandle);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    int printstrUUID(const unsigned char *uuid, char *strout, int lstrout);
    void AddDynamicInfo(PDATANETADDR paddr);
    void setiptables(PDATANETADDR paddr, bool badd);
    bool getusrfilter(DCERPCUuidEntry *item, DCERPCState *phandle);
    bool AnalyseCmdRule(char *cherror);
    uint16 getport(unsigned char *data, int len);
    DCERPCState *GetStaticHandle(unsigned char *sdata, int slen);
    uint16 getport(DCERPCUuidEntry *item, DCERPCState *phandle);
    bool CmdMatch(const CCMDCONF *pcmd);

private:
    OPCDATAFLOW m_dynamicflow[MAX_OPC_DYNAMIC_SIZE];
    OPCDATAFLOW m_staticflow[MAX_OPC_STATIC_SIZE];

    char m_uuid[16];
    char m_uuidstr[48];
    int m_opnum;
    char m_chcmd[MAX_CMD_NAME_LEN];
    char m_chpara[MAX_PARA_NAME_LEN];
    int m_rw;
    bool m_bsys;
};

#ifdef __cplusplus
}
#endif

#endif
