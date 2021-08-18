/*******************************************************************************************
*文件:  FCClientSip.h
*描述:  视频代理类
*作者:  王君雷
*日期:  2016-03
*修改:
*       源码改用linux风格,添加ReplaceClientCall函数             ------> 2018-03-07
*       函数命名统一风格                                        ------> 2018-04-23
*       编码实现视频代理联动                                    ------> 2018-06-06
*       日志中能区分视频的类型                                  ------> 2018-06-22
*       可通过会话ID清空、复用视频通道;支持多节点视频联动       ------> 2018-07-14
*       设置内部nat ip的函数返回值类型改为bool                  ------> 2018-08-15
*       安全通道使用SEC_WAY类                                   ------> 2019-01-02
*       SIP替换IP代码接口封装，针对厂家接口封装                 ------> 2019-06-03
*       将SIP代码回滚的开关放在makefile里                       ------> 2019-06-04
*       移动视频代理客户端登记结构移动到共用的.h文件中          ------> 2019-08-07
*******************************************************************************************/
#ifndef __FC_CLINET_SIP_H__
#define __FC_CLINET_SIP_H__

#include "FCBSTX.h"
#include "FCServiceConf.h"
#include "secway.h"
#include "const.h"
#include "sip_struct.h"

class CSYSRULESBUSINESS;
class CClientSipBase
{
protected:
    char m_name[SIP_RULE_NAME_LEN];
    int m_brandID;
    SEC_WAY m_secway;
    char m_cliip[IP_STR_LEN];//客户端IP
    char m_gapinip[IP_STR_LEN];//网闸接收IP
    char m_gapoutip[IP_STR_LEN];//网闸发送IP
    char m_videoip[IP_STR_LEN];//视频平台IP
    char m_port[PORT_STR_LEN];//视频平台使用端口
    char m_tmpip1[IP_STR_LEN];//网闸靠近客户端的一端，向网闸另一端发送信息时本端bind的ip
    char m_tmpip2[IP_STR_LEN];//网闸靠近视频平台的一端，向网闸另一端发送信息时本端bind的ip
    char m_proto[16];
    int m_cmdnum;
    bool m_ifexec;
    CCMDCONF *m_cmd[C_MAX_CMD];
    int m_taskno;
    SIP_CLIENT_REGTAB m_regtable[MAX_SIP_CLIENT];//客户端登记表

public:
    CClientSipBase(int taskno);
    virtual ~CClientSipBase();
    virtual int srcStart();
    virtual int dstStart();
    bool isProtoSIP();
    const char *getVideoIp();
    int getArea();
    void swapGapIp();
    const char *getGapInIp();
    const char *getGapOutIp();
    const char *getPort();
    bool setTmpIp2(const char *ip);
    bool setTmpIp1(const char *ip);
    friend class CSYSRULESBUSINESS;

protected:
    virtual void initChannel() = 0;//通道初始化
    virtual int getOneChannelID(const char *mrecvip, const char *mrecvport,
                                int &find, const char *callid, int &nodeid) = 0;//获取一个可以使用的通道的下标
    virtual void addOneChannel(int nodeid, int chanid) = 0;//增加一个通道
    virtual void delChannelByCallID(const char *callid) = 0;//根据会话ID删除视频流通道
    virtual const char *getChannelProxyPort(int nodeid, int chanid) = 0;//获取通道的视频流代理端口
    virtual const char *getChannelProxyIP(const char *callid) = 0;//获取通道的视频流代理IP
    virtual const char *getChannelOutIP(const char *callid) = 0;//获取通道的视频流出口IP；转发节点通过该IP把视频流发送给最终接收者
    virtual const char *getTypeDesc() = 0;//获取类型描述
    void recordSysLog(const char *logtype, const char *result, const char *remark);

private:
    int init();
    static void *fromClientInfoTask(void *para);
    static void *recvServerThread(void *para);
    int regClient(sockaddr_in &addr, int fd1, int &fd2);
    int replaceClientInfo(const char *src, int ilen, char *dst, int regid);
    int replaceServerInfo(const char *src, int ilen, char *dst, int regid);
    bool getCmd(char *chcmd, int cmdsize, const char *cmdline);
    bool filterCliSipCmd(const char *chcmd, bool fromCli, int regid);
    void recordCallLog(const char *chcmd, bool result, bool fromCli, int regid);
    int findStrByKey(const char *src, char *dst, int spos, char ikey);
    int regStatusReq(char *cinput, const char *mediarecvip, bool ifvideo, const char *callid);
    void replaceClientCall(char *line);
    void dstSipPrepare();
    bool getCallID(const char *line, char *callidbuf, int buflen);
#ifdef RESEAL_SIP_INTERFACE
    void sipKeywordHandle(const char *recvstr, struct SIP_INFO *sip_info);
    int replaceClientReqInfo(char *tmpstr, struct SIP_INFO *sip_info);
    int replaceClientResInfo(char *tmpstr, struct SIP_INFO *sip_info);
    void replaceClientContact(char *line, struct SIP_INFO *sip_info);
    void replaceClientMessage(char *line, struct SIP_INFO *sip_info);
    void replaceClientContentLen(char *line, struct SIP_INFO *sip_info);
    void replaceClientCinip4(char *line, struct SIP_INFO *sip_info);
    void replaceClientOinip4(char *line, struct SIP_INFO *sip_info);
    void replaceClientCinip6(char *line, struct SIP_INFO *sip_info);
    void replaceClientMvedio(char *line, struct SIP_INFO *sip_info);
    void replaceClientMaudio(char *line, struct SIP_INFO *sip_info);
    void replaceVia(char *line, struct SIP_INFO *sip_info);
    //void replaceFrom(char *line, struct SIP_INFO *sip_info);
    //void replaceTo(char *line, struct SIP_INFO *sip_info);
#endif
};

struct CLISOCKTASK {
    int recvsock;
    int sendsock;
    int regid;
    class CClientSipBase *psip;
};

#endif
