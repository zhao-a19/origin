/*******************************************************************************************
*文件:  FCWebProxy.h
*描述:  WEB代理模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       时间模式封装为单独的类;使用zlog                                ------> 2018-11-03
*       修改匹配函数参数类型                                           ------> 2018-12-27
*       WEB代理支持IPV6                                                ------> 2019-05-21
*       添加generateFile、startRun等成员函数                           ------> 2019-06-19
*       添加服务IP对应的网卡号成员变量，及相关接口函数，支持双机热备   ------> 2019-12-17
*       WEB代理支持分模块生效                                           ------> 2020-11-18
*******************************************************************************************/
#ifndef __FC_WEB_PROXY_H__
#define __FC_WEB_PROXY_H__

#include "const.h"
#include "FCObjectBS.h"
#include "common.h"
#include "timemod.h"
#include "stringex.h"
#include <semaphore.h>
#include <vector>
#include <string>
using namespace std;

#define WEBPROXY_NAT_START_PORT 42000 //内部跳转使用的首个端口 每多一个任务就加一

/**
 * WEB代理任务 读取策略信息到该类
 */
class WebProxyTask
{
public:
    WebProxyTask(int taskno);
    virtual ~WebProxyTask(void);
    const char *timestring(void);
    bool setLinkIP(const char *ip);
    int getAreaway(void);
    const char *getListenIP(void);
    const char *getListenPort(void);
    const char *getLinkIP(void);
    const char *getLinkPort(void);
    int getUrlFlag(void);
    const char *getUrls(void);
    bool jumpQueue(void);
private:

public:
    int m_taskno;
    int m_areaway;
    char m_listenip[IP_STR_LEN];
    char m_listenport[PORT_STR_LEN];
    int m_sobjnum;
    COBJECT *m_sobj[C_OBJECT_MAXNUM];
    TIME_MOD m_timemod;
    int m_urlflag;//0不过滤 1白名单 2黑名单
    char m_urls[C_MAX_LINE_BUF];

private:
    char m_linkip[IP_STR_LEN];
    char m_linkport[PORT_STR_LEN];
};

/**
 * WEB代理处理对象 负责解析过滤从QUEUE中取出的数据包
 */
class CWEBPROXYSINGLE
{
public:
    CWEBPROXYSINGLE(void);
    virtual ~CWEBPROXYSINGLE(void);
    bool IfMatch(unsigned short port, struct in_addr ip);
    bool IfMatchIPv6(unsigned short dport, struct in6_addr dip);
    bool DoMsg(unsigned char *sdata, int slen);
    bool DoMsgIPv6(unsigned char *sdata, int slen, int offsetlen);
    bool GetUrlList(const char *list);

private:
    int GetHeadLen(unsigned char *sdata);
    int GetHeadLenIPv4(unsigned char *sdata);
    int GetHeadLenIPv6(unsigned char *sdata);
    bool DoSrcMsg(unsigned char *sdata, int slen);
    bool DecodeRequest(unsigned char *data, int datasize);
    static bool IfRequest(char *chrequest);
    bool FilterUrls(void);
    void WebRecordCallLog(unsigned char *sdata, bool result);

public:
    char m_listenip[IP_STR_LEN];
    char m_listenport[PORT_STR_LEN];
    char m_linkip[IP_STR_LEN];
    char m_linkport[PORT_STR_LEN];
    int m_urlflag;
    vector<string> m_urlsvec;
    unsigned long m_tmpip;
    ip6addr_t m_ipv6tmpip;
private:
    int m_offsetlen;
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_url[MAX_PARA_NAME_LEN];
    CCommon m_common;
};

/**
 * web代理管理类
 */
class WebProxyMG
{
public:
    WebProxyMG(void);
    virtual ~WebProxyMG(void);
    int loadConf(void);
    int taskNum(void);
    bool setTmpIP(int innum, int outnum);
    bool setDns(const char *dns, const char *dnsipv6);
    bool setTmpIP(void);
    void run(void);
    int getAreaway(int i);
    const char *getListenIP(int i);
    bool clear(void);

private:
    WebProxyTask *addTask(void);
    bool clearWebproxyIptables(void);
    bool setWebproxyIptables(void);
    bool deleteSingle(void);
    bool createSingle(void);
    bool modNginxMG(void);
    bool ipTypeCheck(const char *ip, int iptype);

private:
    char m_in_tmpip4[IP_STR_LEN];
    char m_out_tmpip4[IP_STR_LEN];
    char m_in_tmpip6[IP_STR_LEN];
    char m_out_tmpip6[IP_STR_LEN];
    char m_dns[IP_STR_LEN];
    char m_dnsipv6[IP_STR_LEN];
    int m_task_num;
    WebProxyTask *m_task[C_WEB_PROXY_MAXNUM];
};

extern CWEBPROXYSINGLE *g_webapp[];
extern volatile int g_webappnum;
extern sem_t g_weblock;

#endif
