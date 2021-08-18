/*******************************************************************************************
*文件: FCFgapCmd.h
*描述: 与光闸视频联动  使用该类的对象与光闸通信
*作者: 王君雷
*日期: 2018-04-15
*修改:
*      使用zlog记录更详细的出错信息，修改Add Del等函数返回值类型，开发过程版 ----> 20180521
*      编写Add、Del等函数；协议字段的命名尽量与单向保持一致；协议格式有调整  ----> 20180608
*******************************************************************************************/
#ifndef __FC_FGAP_CMD_H__
#define __FC_FGAP_CMD_H__

#include "datatype.h"
#include "FCBSTX.h"
#include "define.h"

#define CHECK_KEYWORD "SU_SIP"
#define FGAP_CMD_BUFF_LEN 4096

enum CMDTYPE {
    TYPE_ONLINE = 1, TYPE_CLEAR, TYPE_ADD, TYPE_DELETE
};

#define RESULT_OK          0
#define RESULT_HEAD_ERROR  -1
#define RESULT_VER_ERROR   -2
#define RESULT_OTHER_ERROR -10
#define SECOND_TIMEOUT     5
#define CURRENT_VER        1

#pragma pack(push, 1)
typedef struct FGAP_REQUEST_HEAD {
    int8 check[32];
    int32 version;
    int32 id;
    int32 cmd;
    int32 bodylen;
} FGAP_REQUEST_HEAD;

typedef struct FGAP_REQUEST_BODY {
    int8 rulename[64];
    int8 fgap_recvip[16];
    uint16 fgap_recvport;
    int8 fgap_sendip[16];
    int8 recvip[16];
    uint16 recvport;
} FGAP_REQUEST_BODY;

typedef struct FGAP_RESPONSE_HEAD {
    int8 check[32];
    int32 version;
    int32 id;
    int32 cmd;
    union {
        int32 result;
        int32 bodylen;
    };
} FGAP_RESPONSE_HEAD;

#pragma pack(pop)

class CFgapCmd
{
public:
    CFgapCmd(const char *ip, unsigned short port);
    virtual ~CFgapCmd();

    int Clear();
    int Del(const char *rname,
            const char *fgap_recvip, const char *fgap_sendip,
            const char *fgap_recvport,
            const char *realip, const char *realport);
    int Add(const char *rname,
            const char *fgap_recvip, const char *fgap_sendip,
            const char *fgap_recvport,
            const char *realip, const char *realport);
    int Online();

private:
    void Decode(void *buff, int bufflen);
    int ReqNoBody(int cmd);
    int ReqWithBody(const char *rname,
                    const char *fgap_recvip, const char *fgap_sendip,
                    const char *fgap_recvport,
                    const char *realip, const char *realport, int cmd);

private:
    char m_ip[IP_STR_LEN];
    unsigned short m_port;
    CBSTcpSockClient sockcli;
};

#endif
