/*******************************************************************************************
*文件:    FCSip.h
*描述:    平台级联（基类）
*作者:    王君雷
*日期:    2016-02-19
*修改:    可以对命令进行过滤并记录日志                                  ------>   2016-02-19
*         分析SIP包时，每行内容长度放大到8192字节                       ------>   2018-04-10
*         函数命名统一风格                                              ------>   2018-04-23
*         把replaceClientInfo和replaceServerInfo整合到一起，都使用replaceInfo
*         因为他们有太多的重复代码;全文件统一使用zlog                   ------>   2018-05-22
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*         设置内部nat ip的函数返回值类型改为bool                        ------>   2018-08-15
*         添加对东方电子厂商支持；部分厂商可以支持替换from to字段       ------>   2018-11-19
*         安全通道使用SEC_WAY类                                         ------> 2019-01-02
*         SIP替换IP代码接口封装，针对厂家接口封装                       ------> 2019-06-03
*         将SIP代码回滚开关放在编辑选项里                               ------> 2019-06-04
*         将sipTCPsocket连接状态宏修改到sip_struct中和平台互联共用      ------> 2019-07-31
*         使用select函数处理TCP连接                                   ------> 2020-11-30
*******************************************************************************************/
#ifndef __FC_SIP_H__
#define __FC_SIP_H__

#include "FCBSTX.h"
#include "const.h"
#include "FCServiceConf.h"
#include "sip_struct.h"
#include "secway.h"
#include <semaphore.h>

#define C_MAX_THREAD 100    //每个任务允许的最大 TCP 线程数

class CSYSRULESBUSINESS;
class CSipBase
{
protected:
    char m_name[SIP_RULE_NAME_LEN];
    int m_brandID;
    SEC_WAY m_secway;
    char m_upplatip[IP_STR_LEN];//上级平台IP
    char m_gapinip[IP_STR_LEN];//网闸内网侧IP
    char m_gapoutip[IP_STR_LEN];//网闸外网侧IP
    char m_downplatip[IP_STR_LEN];//下级平台IP
    char m_downplatport[PORT_STR_LEN];//下级平台端口
    char m_upplatport[PORT_STR_LEN];//上级平台端口
    char m_proto[16];
    int m_cmdnum;
    bool m_ifexec;
    CCMDCONF *m_cmd[C_MAX_CMD];//命令
    char m_tmpip1[IP_STR_LEN];//网闸靠近上级平台的一端，向网闸另一端发送信息时本端bind的ip
    char m_tmpip2[IP_STR_LEN];//网闸靠近下级平台的一端，向网闸另一端发送信息时本端bind的ip

    int m_taskno;
    int m_tcpstate[C_MAX_THREAD];//1表示正在使用  0表示空闲  2表示正在清理中
    sem_t *m_tcp_sem;
    CBSTcpSockClient m_cli[C_MAX_THREAD];
    CSipVendorsHandleInterface handelInterface;//根据厂家不同处理不同信息

public:
    CSipBase(int taskno);
    virtual ~CSipBase();
    virtual int srcStart();
    virtual int dstStart();
    bool isProtoSIP();
    const char *getUpPlatIp();
    const char *getDownPlatIp();
    int getArea();
    const char *getGapInIp();
    const char *getGapOutIp();
    const char *getDownPlatPort();
    bool setTmpIp2(const char *ip);
    bool setTmpIp1(const char *ip);
    void swapGapIp();
    friend class CSYSRULESBUSINESS;

protected:
    virtual void initChannel() = 0;//通道初始化
    virtual int getOneChannelID(const char *mrecvip, const char *mrecvport,
                                int &find, const char *callid, int &nodeid) = 0; //获取一个可以使用的通道的下标
    virtual void addOneChannel(int nodeid, int chanid) = 0;//增加一个通道
    virtual const char *getChannelProxyPort(int nodeid, int chanid) = 0;//获取通道的视频流代理端口
    virtual const char *getChannelProxyIP(const char *callid) = 0;//获取通道的视频流代理IP
    virtual const char *getChannelOutIP(const char *callid) = 0;//获取通道的视频流出口IP；转发节点通过该IP把视频流发送给最终接收者
    virtual const char *getTypeDesc() = 0;//获取类型描述
    virtual void delChannelByCallID(const char *callid) = 0;//根据会话ID删除视频流通道
    void recordSysLog(const char *logtype, const char *result, const char *remark);

private:
    int init();
    static void *clientInfoTask(void *para);
    static void *serverInfoTask(void *para);
    static void *TCPListenTask(void *para);
    static void *TCPSendAndRecvTask(void *para);
    int replaceClientInfo(const char *src, int ilen, char *dst);
    int replaceServerInfo(const char *src, int ilen, char *dst);
    int replaceInfo(const char *src, int ilen, char *dst, bool fromUpplat);
    bool getCmd(char *chcmd, int cmdsize, const char *cmdline);
    bool filterSipCmd(const char *chcmd, bool fromUpplat);
    void recordCallLog(const char *chcmd, bool result, bool fromUpplat);
    int findStrByKey(const char *src, char *dst, int spos, char ikey);
    int regStatusReq(char *cinput, const char *mediarecvip, bool ifvideo, const char *callid);
    int getTCPThreadID();
    void replaceCall(char *line, const char *ip);
    void dstSipPrepare();
    bool getCallID(const char *line, char *callidbuf, int buflen);
    bool doRecv(int sock1, int sock2, int flag);
#ifdef RESEAL_SIP_INTERFACE
    bool handleDiffVendors(char *recvstr, struct SIP_INFO *sip_info);
    int replaceSipReqInfo(char *tmpstr, struct SIP_INFO *sip_info);
    int replaceSipResInfo(char *tmpstr, struct SIP_INFO *sip_info);
    void sipKeywordHandle(const char *recvstr, struct SIP_INFO *sip_info);
    void replaceContact(char *line, struct SIP_INFO *sip_info);
    void replaceContentLen(char *line, struct SIP_INFO *sip_info);
    void replaceCinip4(char *line, struct SIP_INFO *sip_info);
    void replaceOinip4(char *line, struct SIP_INFO *sip_info);
    void replaceCinip6(char *line, struct SIP_INFO *sip_info);
    void replaceMvedio(char *line, struct SIP_INFO *sip_info);
    void replaceMaudio(char *line, struct SIP_INFO *sip_info);
#else
    bool needReplaceVIA();
    bool needReplaceFromTo();
    void replaceFrom(char *line, bool fromUpplat);
    void replaceTo(char *line, bool fromUpplat);
#endif
};

struct SOCKTASK {
    int recvsock;
    int sendsock;
    int thid;//使用TCP方式时才用得到
    //
    //flag
    //在tcp方式时使用。wjl add 20141014
    //1:表示是网闸靠近上级平台的一端，监听gapinip
    //2:表示是网闸靠近上级平台的一端，监听tmpip1
    //5:表示是网闸靠近上级平台的一端，接收上级平台向gapinip发来的信息,转发到tmpip2
    //6:表示是网闸靠近上级平台的一端，接收tmpip2从已建连接发来的信息,转发到上级平台
    //7:表示是网闸靠近上级平台的一端，接收另一端向tmpip1发来的信息,转发到上级平台
    //8:表示是网闸靠近上级平台的一端，接收上级平台从已建连接发来的信息,转发到另一端
    //
    int flag;
    class CSipBase *psip;
};

#endif
