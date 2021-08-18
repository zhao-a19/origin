/*******************************************************************************************
*文件: SipInterConnectBase.h
*描述: 平台互联互联 基类
*作者: dzj
*日期: 2019-07-05
*修改:
*        封装平台级联和视频代理sip的iptables添加接口                   ------> 2019-08-03
*        添加平台级联和视频代理区分上下级执行时替换信息接口            ------> 2019-08-07
*        添加视频代理客户端登记接口和设置靠近下级媒体流iptables接口    ------> 2019-08-14
*        解决传输媒体流时每次都使用同一端口问题                        ------> 2019-11-21
*        变量名称拼写错误                                              ------> 2019-12-09-dzj
*        使用select函数处理TCP连接                                     ------> 2020-11-30
*******************************************************************************************/
#ifndef __SIP_INTERCONNECT_BASE_H__
#define __SIP_INTERCONNECT_BASE_H__

#include "FCBSTX.h"
#include "define.h"
#include "const.h"
#include "FCServiceConf.h"
#include "secway.h"
//#include "SipInterConnectparse.h"
#include "sip_struct.h"
#include <semaphore.h>

#define C_MAX_THREAD 100    //每个任务允许的最大 TCP 线程数
#define SIP_PORT_STR_LEN 8
#define SIP_IP_STR_LEN 16
enum {
    SIP_IN_CENTER = 0, //SIP内到外
    SIP_OUT_CENTER,    //SIP外到内
};

enum {
    MEDIA_IN_CENTER = 0, //媒体流内到外
    MEDIA_OUT_CENTER,    //媒体流外到内
};

enum {
    SIP_FUN_INTERCONNECT_MODE = 0, //平台互联
    SIP_FUN_CASCADE_MODE, //平台级联
    SIP_FUN_PROXY_MODE, //视频代理
};

enum {
    SIP_NULL_PORT = 0,
    SIP_AUDIO_PORT,
    SIP_VIDEO_PORT,
    SIP_VIDEO_AND_AUDIO_PORT
};
typedef void *(*threadfunc)(void *);

class CSipInterConnectBase;

#pragma pack(push, 1)
typedef struct SipInterConnectTASK {
    int recvsock;
    int sendsock;
    int thid;//使用TCP方式时才用得到
    int regid;//视频代理客户端信息ID
    int recvarea;
    class CSipInterConnectBase *pSipInterConnect;
} SipInterConnectTASK, *PSipInterConnectTASK;

typedef struct _SipInterConnect_Info {
    bool b_bye;
    bool isresp;
    bool is_udp;
    bool transfer; // 0:active 1:passive
    int key_flag;//报文里关键字对应标志
    int port_flag;//端口标志，1:音频支持，2:视频支持，3:音视频都支持
    int area;
    int contlen;//该报文变更后的长度
    int channel_id;
    char originip[IP_STR_LEN];
    char callid[SIP_CALL_ID_LEN];
    char audioport[PORT_STR_LEN];
    char videoport[PORT_STR_LEN];
} SipInterConnect_INFO;

typedef struct SipInterConnectCHANNEL {
    bool is_udp;                       //媒体流传输层协议
    bool transfer; // 0:active 1:passive
    bool area;      //请求方向
    char *callid;      //会话ID
    char proxyport[SIP_PORT_STR_LEN];      //网闸代理收语音的端口，网闸代理发送语音的端口
    char *inmsip;           //内网手台IP
    char *outmsip;          //外网手台IP
    char in_audioport[SIP_PORT_STR_LEN];   //内网手台端口
    char in_videoport[SIP_PORT_STR_LEN];       //内网手台端口
    char out_audioport[SIP_PORT_STR_LEN];      //外网手台端口
    char out_videoport[SIP_PORT_STR_LEN];      //外网手台端口
    time_t activetime;                 //使用通道的时间
    int port_flag;                     //端口标志，1:音频支持，2:视频支持，3:音视频都支持
} SipInterConnectCHANNEL, *PSipInterConnectCHANNEL;
#pragma pack(pop)

class CSipInterConnectBase
{
protected:
    char m_name[SIP_RULE_NAME_LEN];
    SEC_WAY m_secway;
    char m_gapinip[IP_STR_LEN];
    char m_gapoutip[IP_STR_LEN];
    char m_incenter[IP_STR_LEN];
    char m_outcenter[IP_STR_LEN];
    char m_inport[PORT_STR_LEN];
    char m_outport[PORT_STR_LEN];
    char m_proto[PORT_STR_LEN];
    int m_inbrandid;
    int m_outbrandid;
    bool m_defaultaction;
    bool m_via;
    bool m_from;
    bool m_to;
    int m_mode;
    int m_area;
    int m_cmdnum;
    CCMDCONF *m_cmd[C_MAX_CMD];

    char m_innerinip[IP_STR_LEN]; //SIP信令网闸内部口，内网使用的IP
    char m_inneroutip[IP_STR_LEN];//SIP信令网闸内部口，外网使用的IP
    int m_taskid;
    int m_tcpstate[C_MAX_THREAD];//1表示正在使用  0表示空闲  2表示正在清理中
    sem_t *m_tcp_sem;
    CBSTcpSockClient m_cli[C_MAX_THREAD];
    SIP_CLIENT_REGTAB m_regtable[MAX_SIP_CLIENT];//客户端登记表

public:
    CSipInterConnectBase(int taskid);
    virtual ~CSipInterConnectBase(void);

    const char *getGapInIp(void);
    const char *getGapOutIp(void);
    SEC_WAY &getSecway(void);
    int getMode();
    int getArea();
    void swapInfo();

    bool setInnerInIp(const char *ip);
    bool setInnerOutIp(const char *ip);

    bool loadConf(const char *filename);
    bool isProtoSIP(void);
    virtual void inStart(void);
    virtual void outStart(void);

protected:
    void systemCmd(const char *cmd, bool self = true);
    virtual void showConf(void);
    virtual int initChannel(void) = 0;
    virtual void dstVideoPrepare() = 0;
    virtual void setMediaTransfer(int channel_id, bool tansfer) = 0;
    virtual void deleteChannelByCallID(const char *callid) = 0;
    virtual int getChannelProxyPort(SipInterConnect_INFO *sip_info, char *channelport) = 0;

private:
    void setInterConnectInIptables(void);
    void setInterConnectOutIptables(void);
    void setCascadeInIptables(void);
    void setCascadeOutIptables(void);
    void setProxyInIptables(void);
    void setProxyOutIptables(void);
    int regClient(sockaddr_in &addr, int fd1, int &fd2);
    static void *recvServerThread(void *para);
    static void *SipTcpSendAndRecvTask(void *para);
    void startTaskThreads(void);
    int getTCPThreadID();
    bool createThread(threadfunc func, PSipInterConnectTASK ptask);
    int processData(const char *src, int len, char *dst, int area);
    void recordCallLog(const char *chcmd, bool result, int area);
    bool filterSipCmd(const char *chcmd, int area);
    static bool isResponse(const char *line);
    bool getCmd(char *chcmd, int cmdsize, const char *cmdline);
    int findStrByKey(const char *src, char *dst, int spos, char ikey);
    void sipKeywordHandle(const char *recvstr, SipInterConnect_INFO *sip_info);
    void replaceCall(char *line, int area);
    void replaceContact(char *line, int area);
    bool getCallID(const char *line, char *callidbuf, int buflen);
    void replaceContentLen(char *line, SipInterConnect_INFO *sip_info);
    void replaceCinip4(char *line, SipInterConnect_INFO *sip_info);
    void replaceOinip4(char *line, SipInterConnect_INFO *sip_info);
    void replaceCinip6(char *line, SipInterConnect_INFO *sip_info);
    int getMediaPort(char *line, bool ifvideo, SipInterConnect_INFO *sip_info);
    int getTransferMode(char *line, SipInterConnect_INFO *sip_info);
    void replaceFrom(char *line, int area);
    void replaceTo(char *line, int area);
    void replaceVia(char *line, int area);
    int replaceSipInfo(char *recvstr, SipInterConnect_INFO *sip_info);
    bool doRecv(int sock1, int sock2, int recvarea);

    friend void *recvCenterSIP(void *para);
    friend void *SipTcpListenTask(void *para);
};

void *recvCenterSIP(void *para);
void *SipTcpListenTask(void *para);

#endif
