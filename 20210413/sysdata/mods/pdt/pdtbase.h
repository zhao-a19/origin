/*******************************************************************************************
*文件: pdtbase.h
*描述: PDT互联 基类
*作者: 王君雷
*日期: 2018-07-31
*修改:
*      根据review的讨论，把recvCenterPSIP从类中移出，使用友元函数      ------> 2018-08-25
*      安全通道使用SEC_WAY类                                           ------> 2019-01-02
*      SIP代码优化，添加SIP信息结构体，封装接口                        ------> 2019-06-24 --dzj
*      SIP代码优化，修改SIP信息结构体，封装接口                        ------> 2019-06-25 --dzj
*      修改SIP没有content_len字段时的处理                              ------> 2019-06-27 --dzj
*      修改PDT代码回退时编译不过问题                                   ------> 2019-08-26 --dzj
*******************************************************************************************/
#ifndef __PDT_BASE_H__
#define __PDT_BASE_H__

#include "define.h"
#include "const.h"
#include "FCServiceConf.h"
#include "secway.h"
#include "pdtparser.h"

#define PDT_CALL_ID_LEN 128        //网闸处理过程中允许的callid长度
#define PDT_MAX_PACKET (64 * 1024) //UDP包最大不会超过64K
#define PDT_LINE_LEN_CHANGE 8      //每行内容，因替换内容，可能会变长，预留字节
#define PDT_MAX_LINE_SIZE 8192     //分析出的每行内容最大支持长度
#define PDT_MAX_LINE_NUM 10000     //接收到的数据包 最多允许包含的行数

typedef void *(*threadfunc)(void *);

class CPDTBase;

enum {
    AREA_IN_CENTER = 0,
    AREA_OUT_CENTER
};

#pragma pack(push, 1)
typedef struct PDTTASK {
    int recvsock;
    int sendsock;
    int recvarea;
    class CPDTBase *ppdt;
} PDTTASK, *PPDTTASK;

typedef struct _pdt_Info {
    bool isresp;//是否为响应
    int contlen;//该报文变更后的长度
    method_type mtype;//请求mothod
    char originip[IP_STR_LEN];
    char callid[PDT_CALL_ID_LEN];
} PDT_SIP_INFO;

typedef struct PDTCHANNEL {
    char callid[PDT_CALL_ID_LEN];      //会话ID
    char proxyport[PORT_STR_LEN];      //网闸代理收语音的端口，网闸代理发送语音的端口
    char inmsip[IP_STR_LEN];           //内网手台IP
    char outmsip[IP_STR_LEN];          //外网手台IP
    char inmsport[PORT_STR_LEN];       //内网手台端口
    char outmsport[PORT_STR_LEN];      //外网手台端口
    time_t activetime;                 //使用通道的时间
    bool enable;                       //通道可用
} PDTCHANNEL, *PPDTCHANNEL;
#pragma pack(pop)

class CPDTBase
{
protected:
    char m_name[PDT_RULE_NAME_LEN];
    SEC_WAY m_secway;
    char m_gapinip[IP_STR_LEN];
    char m_gapoutip[IP_STR_LEN];
    char m_incenter[IP_STR_LEN];
    char m_outcenter[IP_STR_LEN];
    char m_inport[PORT_STR_LEN];
    char m_outport[PORT_STR_LEN];
    char m_proto[16];
    int m_inbrandid;
    int m_outbrandid;
    bool m_defaultaction;
    int m_cmdnum;
    CCMDCONF *m_cmd[C_MAX_CMD];

    char m_innerinip[IP_STR_LEN]; //SIP信令网闸内部口，内网使用的IP
    char m_inneroutip[IP_STR_LEN];//SIP信令网闸内部口，外网使用的IP
    int m_taskid;

public:
    CPDTBase(int taskid);
    virtual ~CPDTBase(void);

    const char *getGapInIp(void);
    const char *getGapOutIp(void);
    SEC_WAY &getSecway(void);

    bool setInnerInIp(const char *ip);
    bool setInnerOutIp(const char *ip);

    bool loadConf(const char *filename);
    bool isProtoPSIP(void);
    virtual void inStart(void);
    virtual void outStart(void);

protected:
    void systemCmd(const char *cmd, bool self = true);
    virtual void showConf(void);
    virtual int initChannel(void) = 0;
    virtual void deleteChannelByCallID(const char *callid) = 0;
    virtual int getChannelProxyIP(const char *callid, int area, char *channelproxyip) = 0;
    virtual int getChannelProxyPort(const char *callid, int area, const char *originip, const char *mediaport,
                                    bool isresp, char *channelport) = 0;

private:
    void setInIptables(void);
    void setOutIptables(void);

    void startTaskThreads(void);
    bool createThread(threadfunc func, PPDTTASK ptask);
    int processData(const char *src, int len, char *dst, int area);
    static bool isResponse(const char *line);
    bool fileterCmd(const char *chcmd);
    void recordCallLog(const char *chcmd, bool result, int area);

    static method_type getMethodType(const char *line);
    static header_type getHeaderType(const char *line);
    static int getCallID(const char *line, char *callid, int clen);
    static int getOriginIP(const char *line, char *originip);
    static int getMediaPort(const char *line, char *port);

    void replaceIP(char *line, header_type htype, int area);
    static int replaceOriginIP(char *line, const char *originip, const char *channelproxyip);
    static int replaceMediaPort(char *line, const char *mediaport, const char *channelport);

#ifdef RESEAL_SIP_INTERFACE
    int replaceMethodLine(char *line, method_type mtype, int area);
    static int getContentLen(char *line, int *clen);
    int pdtReplaceSipHeader(char *recvstr, PDT_SIP_INFO *pdt_sip_info, int area);
    static int findCharByKey(const char *src, char *tmpdst, int offset, char key);
#else
    void replaceMethodLine(char *line, method_type mtype, int area);
    static int getContentLen(const char *line, int *clen, int *shift);
    int separateLines(const char *src, int len, char **strarray, int arraysize);
    static int findCharByKey(const char *src, const char *limit, int offset, char key);
#endif

    friend void *recvCenterPSIP(void *para);
};

void *recvCenterPSIP(void *para);
#endif
