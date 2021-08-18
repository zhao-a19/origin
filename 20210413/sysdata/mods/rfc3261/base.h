/*******************************************************************************************
*文件: base.h
*描述: 平台互联基类
*作者: 王君雷
*日期: 2020-08-18
*修改:
*      使用的第一个通道端口号以及通道最大支持数可以通过配置文件配置 ------> 2020-09-03
*      流媒体通道传输层协议，可以自动识别也可以通过配置指定        ------> 2020-09-15
*      开通通道以后可以通过配置决定是否需要清空连接追踪表，默认不开启 ------> 2020-09-16
*******************************************************************************************/
#ifndef __BASE_H__
#define __BASE_H__

#include <vector>
using namespace std;

#include <semaphore.h>
#include "define.h"
#include "const.h"
#include "FCBSTX.h"
#include "FCServiceConf.h"
#include "secway.h"
#include "sip_struct.h"

#define MAX_PACKET (64 * 1024)
#define MAX_THREAD 100    //每个任务允许的最大 TCP 线程数
#define SELF_SIDE true
#define PEER_SIDE false

#define LAST_CHANNEL_PORT(fport, total)  ((fport) + total * 4 - 1)
#define MAX_BOUNDARY       128

#define PROXY_AUDIO_RTP_PORT(port)  ((port) + 0)
#define PROXY_AUDIO_RTCP_PORT(port) ((port) + 1)
#define PROXY_VIDEO_RTP_PORT(port)  ((port) + 2)
#define PROXY_VIDEO_RTCP_PORT(port) ((port) + 3)

typedef void *(*threadfunc)(void *);

class base;
/**
 * 线程任务参数
 */
typedef struct _task {
    int recvsock;
    int sendsock;
    int threadid;  //使用TCP方式时才用得到
    int recvarea;  //接收的位置
    class base *psip;
} BTASK, *PBTASK;

enum {
    RECV_IN_CENTER = 0,  //接收内网交换中心 SIP
    RECV_OUT_CENTER = 1, //接收外网交换中心 SIP
    LISTEN_IN_CENTER,    //监听靠近内网交换中心一侧的TCP端口
    LISTEN_OUT_CENTER,   //监听靠近外网交换中心一侧的TCP端口（即内网内部IP 端口）
};

/**
 * 媒体流通道
 */
typedef struct _channel {
    char callid[SIP_CALL_ID_LEN];    //会话ID
    int proxyport;                   //网闸代理收发流媒体的端口 从proxyport到proxyport+3 都属于这个通道的端口
    char inmsip[IP_STR_LEN];         //内网流媒体相关IP
    char outmsip[IP_STR_LEN];        //外网流媒体相关IP
    char in_vport[PORT_STR_LEN];     //内网video端口
    char in_aport[PORT_STR_LEN];     //内网audio端口
    char out_vport[PORT_STR_LEN];    //外网video端口
    char out_aport[PORT_STR_LEN];    //外网audio端口
    bool vtcp;                       //video TCP传输
    bool atcp;                       //audio TCP传输
    bool enable;                     //通道可用
    time_t activetime;               //操作通道的时间
} BCHANNEL, *PBCHANNEL;

typedef struct _block {
    const char *begin;
    int len;
    bool bmalloc;
    char *nbegin;
    int nlen;
} BLOCK, *PBLOCK;

/**
 * 存放一个完整SIP包的关键信息
 */
typedef struct _packet_Info {
    bool isresponse;                      //false:表示请求  true:表示响应
    int retcode;                          //返回码 只在响应时使用
    char chcmd[C_SIP_KEY_WORLD_LEN];      //信令名称
    int recvarea;                         //请求来自哪个平台 0：内网平台  1：外网平台
    char callid[SIP_CALL_ID_LEN];         //会话ID
    char msip[IP_STR_LEN];                //流媒体相关IP
    bool vtcp;                            //video TCP传输
    bool atcp;                            //audio TCP传输
    char vport[PORT_STR_LEN];             //video端口
    char aport[PORT_STR_LEN];             //audio端口
    int content_len_index;                //所在VECTOR下标
    int content_len_change;               //因替换信息而导致长度的变化
    bool find_rn;                         //已经发现\r\n\r\n

    bool multipart;                       //是否有多块
    bool subsdp;                          //在子块中发现了sdp
    char boundary[MAX_BOUNDARY];          //子块分界符
    int sub_content_len_index;            //子块所在VECTOR下标
    int sub_content_len_change;           //子块因替换信息而导致长度的变化

} PACKET_INFO, *PPACKET_INFO;

/**
 * 流媒体通道类型
 */
enum {
    STREAM_TYPE_AUTO = 0,//自动识别 默认
    STREAM_TYPE_UDP,     //UDP
    STREAM_TYPE_TCP,     //TCP
    STREAM_TYPE_UDPTCP,  //同时打开UDP TCP
};

class base
{
public:
    base(int taskid, bool siptcp);
    virtual ~base(void);

    virtual void inStart(void);
    virtual void outStart(void);
    virtual bool loadConf(const char *filename) = 0;
    virtual bool checkProto(void) = 0;

    SEC_WAY &getSecway(void);
    const char *getGapInIp(void);
    const char *getGapOutIp(void);
    bool setInnerInIp(const char *ip);
    bool setInnerOutIp(const char *ip);

protected:
    virtual const char *getTypeDesc(void);
    virtual bool doMethodLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec) = 0;
    virtual bool doHeaderLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec) = 0;
    virtual bool doBodyLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec) = 0;

    bool doReplaceIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                     vector<BLOCK> &bvec, const char *repip);
    bool doReplaceIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                     vector<BLOCK> &bvec, const char *oriip, const char *repip);
    bool doReplaceIPPort(const char *begin, const char *end, PACKET_INFO &pinfo,
                         vector<BLOCK> &bvec, const char *repip, const char *repport);
    bool doReplaceLength(const char *begin, const char *end, PACKET_INFO &pinfo,
                         vector<BLOCK> &bvec, bool bsub = false);
    bool doReplaceCallIDIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                           vector<BLOCK> &bvec);
    bool doReplaceO(const char *begin, const char *end, PACKET_INFO &pinfo,
                    vector<BLOCK> &bvec);
    bool doReplaceC(const char *begin, const char *end, PACKET_INFO &pinfo,
                    vector<BLOCK> &bvec);
    bool doReplaceAudio(const char *begin, const char *end, PACKET_INFO &pinfo,
                        vector<BLOCK> &bvec);
    bool doReplaceVideo(const char *begin, const char *end, PACKET_INFO &pinfo,
                        vector<BLOCK> &bvec);
    bool doReplacePort(const char *begin, const char *end, PACKET_INFO &pinfo,
                       vector<BLOCK> &bvec, bool baudio);

    bool getProxyPort(char *proxyport, PACKET_INFO &pinfo, bool baudio);
    int getChannelID(PACKET_INFO &pinfo, bool baudio);
    int getChannelIDRequest(PACKET_INFO &pinfo, bool baudio);
    int getChannelIDRequestExist(PACKET_INFO &pinfo, bool baudio);
    int getChannelIDResponse(PACKET_INFO &pinfo, bool baudio);
    void delChannel(int id);
    void delChannel(const char *callid);
    void clearChannel(int id);
    void fillChannel(PACKET_INFO &pinfo, bool baudio, int id);
    void operChannelAudio(int id, bool add);
    void operChannelVideo(int id, bool add);
    void operChannel(const char *inmsip, const char *outmsip, const char *inport, const char *outport,
                     int proxyport, bool add, const char *proto);
    void lockChannel(void);
    void unlockChannel(void);

    void setInIptables(void);
    void setOutIptables(void);
    bool doLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec);
    bool doStartLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec);
    BLOCK &makeBlock1(BLOCK &block, const char *begin, int len);
    BLOCK &makeBlock2(BLOCK &block, const char *begin, int len);
    bool getCallID(const char *line, char *callidbuf, int buflen);
    bool parserContentType(const char *begin, const char *end, PACKET_INFO &pinfo);

    int processData(const char *src, int len, char *dst, int recvarea);
    void showConf(void);
    bool getCmd(char *chcmd, int cmdsize, const char *cmdline);
    bool filterCmd(const char *chcmd, int recvarea);
    void startTCPThreads(void);
    void startUDPThreads(void);
    bool createThread(threadfunc func, PBTASK ptask);
    int initChannel(void);
    static bool isResponse(const char *line, int &retcode);
    void recordCallLog(const char *chcmd, bool result, int recvarea);
    void systemCmd(const char *cmd, bool side = SELF_SIDE);
    void clearVec(vector<BLOCK> &bvec);
    bool adjustLen(PACKET_INFO &pinfo, vector<BLOCK> &bvec);
    int combineMsg(char *dst, vector<BLOCK> &bvec);
    bool channelUDP(bool flag);
    bool channelTCP(bool flag);

    //TCP传输SIP相关函数
    int initTCPMember(void);
    int getTCPThreadID(void);
    bool releaseTCPThread(int threadid, int ssock, int rsock);
    bool doRecv(int sock1, int sock2, int area);
    //友元函数
    friend void *UDPThread(void *para);
    friend void *TCPThread(void *para);
    friend void *TCPThread_RS(void *para);

protected:
    char m_name[RULE_NAME_LEN];
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
    char m_innerinip[IP_STR_LEN];
    char m_inneroutip[IP_STR_LEN];
    int m_taskid;

    //启用TCP传输SIP时用到的变量
    bool m_siptcp;
    int m_tcpstate[MAX_THREAD]; //1表示正在使用  0表示空闲  2表示正在清理中
    sem_t m_tcplock;
    CBSTcpSockClient m_tcpcli[MAX_THREAD];

    int m_max_channel;
    int m_lastid;
    PBCHANNEL m_pchannel;
    sem_t m_channellock;
    int m_first_chport;
    int m_stream_type;
    int m_clean_track;
};

void *UDPThread(void *para);
void *TCPThread(void *para);
void *TCPThread_RS(void *para);
const char *strnchr(const char *begin, const char *end, char c);
const char *strncasestr(const char *begin, const char *end, const char *str);

#endif
