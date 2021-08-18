/*******************************************************************************************
*文件:  FCWebProxy.cpp
*描述:  WEB代理模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       时间模式封装为单独的类;使用zlog                                ------> 2018-11-03
*       修改匹配函数参数类型                                           ------> 2018-12-27
*       不使用全局的数据库操作对象                                     ------> 2019-01-09
*       WEB代理支持IPV6                                                ------> 2019-05-21
*       把生成WEB代理配置文件逻辑移动到WebProxyTask类中                ------> 2019-06-19
*       添加服务IP对应的网卡号成员变量，及相关接口函数，支持双机热备   ------> 2019-12-17
*       WEB代理是否记录日志，可以受全局开关的控制;不再阻塞串行写日志   ------> 2020-01-07
*       访问日志接口添加MAC相关字段                                    ------> 2020-01-16
*       WEB代理支持分模块生效                                           ------> 2020-11-18
*******************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "FCYWBS.h"
#include "fileoperator.h"
#include "FCWebProxy.h"
#include "quote_global.h"
#include "simple.h"
#include "FCLogContainer.h"
#include "debugout.h"
#include "network.h"
#include "readcfg.h"
#include "card_mg.h"

CWEBPROXYSINGLE *g_webapp[C_WEB_PROXY_MAXNUM];
volatile int g_webappnum = 0;
sem_t g_weblock;

extern CardMG g_cardmg;
extern sem_t *g_iptables_lock;

WebProxyTask::WebProxyTask(int taskno)
{
    m_areaway = 0;
    BZERO(m_listenip);
    BZERO(m_listenport);
    m_sobjnum = 0;
    BZERO(m_sobj);
    m_urlflag = 0;
    BZERO(m_urls);
    m_taskno = taskno;
    sprintf(m_linkport, "%d", WEBPROXY_NAT_START_PORT + taskno);
    BZERO(m_linkip);
}

WebProxyTask::~WebProxyTask(void)
{
    DELETE_N(m_sobj, m_sobjnum);
}

/**
 * [WebProxyTask::timestring 获取时间模式iptables字符串]
 * @return  [失败返回NULL]
 */
const char *WebProxyTask::timestring(void)
{
    return m_timemod.tostring();
}

/**
 * [WebProxyTask::setLinkIP 设置内部跳转IP]
 * @param  ip [IP]
 * @return    [成功返回true]
 */
bool WebProxyTask::setLinkIP(const char *ip)
{
    if ((ip == NULL) || strlen(ip) == 0) {
        PRINT_ERR_HEAD
        print_err("set link ip para error[%s]", ip);
        return false;
    }
    strncpy(m_linkip, ip, sizeof(m_linkip) - 1);
    return true;
}

/**
 * [WebProxyTask::jumpQueue 请求是否需要进队列]
 * @return  [需要进返回true]
 */
bool WebProxyTask::jumpQueue(void)
{
    return (g_iflog || (m_urlflag != 0));
}

/**
 * [WebProxyTask::getAreaway 获取策略方向]
 * @return  [策略方向]
 */
int WebProxyTask::getAreaway(void)
{
    return m_areaway;
}

/**
 * [WebProxyTask::getListenIP 获取监听IP]
 * @return  [监听IP]
 */
const char *WebProxyTask::getListenIP(void)
{
    return m_listenip;
}

/**
 * [WebProxyTask::getListenPort 获取监听端口]
 * @return  [监听端口]
 */
const char *WebProxyTask::getListenPort(void)
{
    return m_listenport;
}

/**
 * [WebProxyTask::getLinkIP 获取内部跳转IP]
 * @return  [内部跳转IP]
 */
const char *WebProxyTask::getLinkIP(void)
{
    return m_linkip;
}

/**
 * [WebProxyTask::getLinkPort 获取内部跳转端口]
 * @return  [内部跳转端口]
 */
const char *WebProxyTask::getLinkPort(void)
{
    return m_linkport;
}

/**
 * [WebProxyTask::getUrlFlag 获取过滤标志]
 * @return  [过滤标志]
 */
int WebProxyTask::getUrlFlag(void)
{
    return m_urlflag;
}

/**
 * [WebProxyTask::getUrls 获取URL列表]
 * @return  [URL列表]
 */
const char *WebProxyTask::getUrls(void)
{
    return m_urls;
}

CWEBPROXYSINGLE::CWEBPROXYSINGLE(void)
{
    BZERO(m_listenip);
    BZERO(m_listenport);
    BZERO(m_linkip);
    m_urlflag = 0;
    m_tmpip = 0;
    BZERO(ch_cmd);
    BZERO(ch_url);
}

CWEBPROXYSINGLE::~CWEBPROXYSINGLE(void)
{
}

/**
 * [CWEBPROXYSINGLE::IfMatch 是否匹配这个WEB代理任务]
 * @param  port [端口]
 * @param  ip   [ip]
 * @return      [匹配返回true]
 */
bool CWEBPROXYSINGLE::IfMatch(unsigned short port, struct in_addr ip)
{
    return (port == atoi(m_linkport)) && (ntohl(ip.s_addr) == m_tmpip);
}

/**
 * [CWEBPROXYSINGLE::IfMatchIPv6 是否匹配这个WEB代理任务]
 * @param  dport [目的端口]
 * @param  dip   [目的IP]
 * @return       [匹配返回true]
 */
bool CWEBPROXYSINGLE::IfMatchIPv6(unsigned short dport, struct in6_addr dip)
{
    return (dport == atoi(m_linkport)) && (ip6cmp(&dip, &m_ipv6tmpip) == 0);
}

/**
 * [CWEBPROXYSINGLE::DoMsg 处理数据包]
 * @param  sdata [数据包]
 * @param  slen  [数据包长度]
 * @return       [允许通过返回true]
 */
bool CWEBPROXYSINGLE::DoMsg(unsigned char *sdata, int slen)
{
    return DoSrcMsg(sdata, slen);
}

/**
 * [CWEBPROXYSINGLE::DoMsgIPv6 处理数据包]
 * @param  sdata     [数据包]
 * @param  slen      [数据包长度]
 * @param  offsetlen [TCP头相对于IPV6头部的偏移]
 * @return           [允许通过返回true]
 */
bool CWEBPROXYSINGLE::DoMsgIPv6(unsigned char *sdata, int slen, int offsetlen)
{
    PRINT_DBG_HEAD
    print_dbg("do msg ipv6. slen[%d] offsetlen[%d]", slen, offsetlen);

    m_offsetlen = offsetlen;
    return DoSrcMsg(sdata, slen);
}

/**
 * [CWEBPROXYSINGLE::DoSrcMsg 处理数据包]
 * @param  sdata [数据包]
 * @param  slen  [数据包长度]
 * @return       [允许通过返回true]
 */
bool CWEBPROXYSINGLE::DoSrcMsg(unsigned char *sdata, int slen)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0) {
        return true;
    }

    if (DecodeRequest(sdata + hdflag, slen - hdflag)) {
        if (FilterUrls()) {
            WebRecordCallLog(sdata, true);
            return true;
        } else {
            WebRecordCallLog(sdata, false);
            return false;
        }
    } else {
        return true;
    }
}

/**
 * [CWEBPROXYSINGLE::DecodeRequest 解码请求信息]
 * @param  data     [数据包 应用层开始的]
 * @param  datasize [数据包长度]
 * @return          [解码成功返回true]
 */
bool CWEBPROXYSINGLE::DecodeRequest(unsigned char *data, int datasize)
{
    PRINT_DBG_HEAD
    print_dbg("decode request begin. datasize[%d]", datasize);

    unsigned char ucflag[2] = {0x0d, 0x0a};
    unsigned char tucflag[1] = {0x20};
    int offset_0d0a = 0;
    int cmd_len = 0;
    int url_len = 0;

    BZERO(ch_cmd);
    BZERO(ch_url);

    if ((data == NULL) || (datasize <= 0)) {
        PRINT_ERR_HEAD
        print_err("datasize[%d]", datasize);
        return false;
    }

    //查找第一个0d0a的偏移量
    for (offset_0d0a = 0; offset_0d0a < datasize - 1; offset_0d0a++) {
        if (memcmp(data + offset_0d0a, ucflag, 2) == 0) {
            break;
        }
    }
    if (offset_0d0a == datasize - 1) {
        //PRINT_INFO_HEAD
        //print_info("not find 0d0a. datasize[%d]", datasize);
        return false;
    }

    //取出命令
    for (cmd_len = 0; cmd_len < offset_0d0a; cmd_len++ ) {
        if (data[cmd_len] == tucflag[0]) {
            break;
        }
    }
    if (cmd_len == offset_0d0a) {
        return false;
    }

    memcpy(ch_cmd, data, cmd_len < 10 ? cmd_len : 10);

    PRINT_DBG_HEAD
    print_dbg("get cmd[%s]", ch_cmd);

    //检查命令是否为正确的HTTP命令
    if (!IfRequest(ch_cmd)) {
        return false;
    }

    //取URL
    for (url_len = cmd_len + 1; url_len < offset_0d0a; url_len++ ) {
        if (data[url_len] == tucflag[0]) {
            break;
        }
    }
    if (url_len == offset_0d0a) {
        return false;
    }

    memcpy(ch_url, data + cmd_len + 1, (url_len - cmd_len - 1) < (int)sizeof(ch_url) - 1 ?
           (url_len - cmd_len - 1) : (int)sizeof(ch_url) - 1);

    //如果url中有单引号,替换为空格 否则后面组装sql语句时可能会出错
    for (int i = 0; i < (int)strlen(ch_url); i++) {
        if (ch_url[i] == '\'') {
            ch_url[i] = ' ';
        }
    }

    PRINT_DBG_HEAD
    print_dbg("decode request over. [%s][%s]", ch_cmd, ch_url);
    return true;
}

/**
 * [CWEBPROXYSINGLE::IfRequest 判断是不是http命令]
 * @param  chrequest [请求]
 * @return           [是请求返回true]
 */
bool CWEBPROXYSINGLE::IfRequest(char *chrequest)
{
    char m_RequestCmd[][10] = {
        "OPTIONS", "TRACE", "GET", "HEAD", "DELETE",
        "PUT", "POST", "COPY", "MOVE", "MKCOL",
        "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK", "SEARCH",
        "CONNECT"
    };
    for (int i = 0; i < (int)(ARRAY_SIZE(m_RequestCmd)); i++) {
        if (strcasecmp(chrequest, m_RequestCmd[i]) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * [CWEBPROXYSINGLE::GetUrlList 从参数中解析出URL列表 存入成员变量]
 * @param  list [URL列表]
 * @return      [成功返回true]
 */
bool CWEBPROXYSINGLE::GetUrlList(const char *list)
{
    char urlbuf[500] = {0};

    if ((list != NULL) && strlen(list) > 0) {
        const char *p = list;
        while (1) {
            if (*p == '\0') {
                if (strlen(urlbuf) != 0) {
                    m_urlsvec.push_back(string(urlbuf));
                }
                break;
            } else if (*p == ',') {
                if (strlen(urlbuf) != 0) {
                    m_urlsvec.push_back(string(urlbuf));
                }
                BZERO(urlbuf);
                p++;
            } else {
                int len = strlen(urlbuf);
                if (len < (int)sizeof(urlbuf) - 1) {
                    urlbuf[len] = *p;
                }
                p++;
            }
        }
        PRINT_INFO_HEAD
        print_info("GetUrlList ok. size[%d]", (int)m_urlsvec.size());
        return true;
    }
    PRINT_ERR_HEAD
    print_err("GetUrlList para err[%s]", list);
    return false;
}

/**
 * [CWEBPROXYSINGLE::FilterUrls 按规则过滤URL]
 * @return  [允许通过返回true]
 */
bool CWEBPROXYSINGLE::FilterUrls(void)
{
    switch (m_urlflag) {
    case 0:
        break;
    case 1: {
        for (int i = 0; i < (int)m_urlsvec.size(); i++) {
            if (m_common.casestrstr((const unsigned char *)ch_url,
                                    (const unsigned char *)m_urlsvec[i].c_str(),
                                    0, strlen(ch_url)) == E_COMM_OK) {
                return true;
            }
        }
        return false;
        break;
    }
    case 2: {
        for (int i = 0; i < (int)m_urlsvec.size(); i++) {
            if (m_common.casestrstr((const unsigned char *)ch_url,
                                    (const unsigned char *)m_urlsvec[i].c_str(),
                                    0, strlen(ch_url)) == E_COMM_OK) {
                return false;
            }
        }
        return true;
        break;
    }
    default:
        PRINT_ERR_HEAD
        print_err("unknown flag[%d]", m_urlflag);
        break;
    }
    return true;
}

/**
 * [CWEBPROXYSINGLE::WebRecordCallLog 写访问日志]
 * @param sdata  [数据包]
 * @param result [成功或失败]
 */
void CWEBPROXYSINGLE::WebRecordCallLog(unsigned char *sdata, bool result)
{
    if (g_iflog || g_syslog) {
        char authname[AUTH_NAME_LEN] = {0};
        char tmpsip[IP_STR_LEN] = {0};
        char tmpsport[PORT_STR_LEN] = {0};

        if (_ipv4(sdata)) {
            inet_ntop(AF_INET, IPV4_SIP(sdata), tmpsip, sizeof(tmpsip));
            PTCP_HEADER ptcp = _tcpipdata(sdata);
            sprintf(tmpsport, "%d", ntohs(ptcp->th_sport));
        } else if (_ipv6(sdata)) {
            inet_ntop(AF_INET6, IPV6_SIP(sdata), tmpsip, sizeof(tmpsip));
            PTCP_HEADER ptcp = (PTCP_HEADER)(sdata + m_offsetlen);
            sprintf(tmpsport, "%d", ntohs(ptcp->th_sport));
        }

        if (g_ckauth) {
            if (GetAuthName(tmpsip, authname, sizeof(authname)) == 0) {
            } else {
                PRINT_INFO_HEAD
                print_info("get auth name fail[srcip %s]", tmpsip);
            }
        }

        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues(authname, tmpsip, m_listenip, tmpsport, m_listenport, "", "", LOG_TYPE_WEBPROXY,
                             ch_cmd, ch_url, result ? D_SUCCESS : D_REFUSE, "")) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[authname %s, sip %s, dip %s, sport %s, dport %s, %s:%s:%s]",
                          authname, tmpsip, m_listenip, tmpsport, m_listenport, LOG_TYPE_WEBPROXY,
                          ch_cmd, ch_url);
                delete p;
            }
        }
    }
}

/**
 * [CWEBPROXYSINGLE::GetHeadLen 返回IP + TCP/UDP 头部长度]
 * @param  sdata [数据包 从ip头部开始的]
 * @return       [长度 失败返回负值]
 */
int CWEBPROXYSINGLE::GetHeadLen(unsigned char *sdata)
{
    if (_ipv4(sdata)) {
        return GetHeadLenIPv4(sdata);
    } else if (_ipv6(sdata)) {
        return GetHeadLenIPv6(sdata);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown proto in get head len func");
        return -1;
    }
}

/**
 * [CWEBPROXYSINGLE::GetHeadLenIPv4 获取应用层内容相对于IP头部开始位置的偏移长度]
 * @param  sdata [IP头开始的数据包]
 * @return       [偏移长度]
 */
int CWEBPROXYSINGLE::GetHeadLenIPv4(unsigned char *sdata)
{
    switch (IPV4_PROTO(sdata)) {
    case TCP:
        return IPV4_IPTCP_HEADER_LEN(sdata);
    case UDP:
        return IPV4_IPUDP_HEADER_LEN(sdata);
    case ICMP:
        return _ipheadlen(sdata);
    default:
        PRINT_ERR_HEAD
        print_err("unknown ipv4 proto.");
        return -1;
    }
}

/**
 * [CWEBPROXYSINGLE::GetHeadLenIPv6 获取应用层内容相对于IP头部开始位置的偏移长度]
 * @param  sdata [IP头开始的数据包]
 * @return       [偏移长度]
 */
int CWEBPROXYSINGLE::GetHeadLenIPv6(unsigned char *sdata)
{
    return m_offsetlen + _tcpheadlen(sdata + m_offsetlen);
}

WebProxyMG::WebProxyMG(void)
{
    BZERO(m_in_tmpip4);
    BZERO(m_in_tmpip6);
    BZERO(m_out_tmpip4);
    BZERO(m_out_tmpip6);
    BZERO(m_dns);
    BZERO(m_dnsipv6);
    m_task_num = 0;
    BZERO(m_task);
}

WebProxyMG::~WebProxyMG(void)
{
}

/**
 * [WebProxyMG::loadConf 导入WEB代理策略]
 * @return            [成功返回0]
 */
int WebProxyMG::loadConf(void)
{
    char taskno[16] = {0};
    char item[100] = {0};
    int tasknum = 0;

    CFILEOP fileop;

    if (fileop.OpenFile(WEBPROXY_CONF, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", WEBPROXY_CONF);
        return -1;
    }

    READ_INT(fileop, "MAIN", "TaskNum", tasknum, true, _out);
    PRINT_DBG_HEAD
    print_dbg("webproxy tasknum:%d", tasknum);

    for (int i = 0; i < tasknum ; i++ ) {
        WebProxyTask *webproxy = addTask();
        if (webproxy == NULL) {
            break;
        }

        sprintf(taskno, "TASK%d", i);
        READ_INT(fileop, taskno, "Area", webproxy->m_areaway, true, _out);
        READ_STRING(fileop, taskno, "ListenIP", webproxy->m_listenip, true, _out);
        READ_STRING(fileop, taskno, "ListenPort", webproxy->m_listenport, true, _out);
        READ_INT(fileop, taskno, "SObjNum", webproxy->m_sobjnum, true, _out);

        for (int j = 0; j < webproxy->m_sobjnum; j++) {
            webproxy->m_sobj[j] = new COBJECT;
            if (webproxy->m_sobj[j] == NULL) {
                PRINT_ERR_HEAD
                print_err("new obj fail[%s]", taskno);
                break;
            }

            sprintf(item, "SObjName%d", j);
            READ_STRING(fileop, taskno, item, webproxy->m_sobj[j]->m_objectname, true, _out);
            sprintf(item, "SObjIP%d", j);
            READ_STRING(fileop, taskno, item, webproxy->m_sobj[j]->m_ipaddress, true, _out);
            sprintf(item, "SObjMask%d", j);
            READ_STRING(fileop, taskno, item, webproxy->m_sobj[j]->m_netmask, true, _out);
            sprintf(item, "SObjMac%d", j);
            READ_STRING(fileop, taskno, item, webproxy->m_sobj[j]->m_mac, true, _out);
            sprintf(item, "SrcIPType%d", j);
            READ_INT(fileop, taskno, item, webproxy->m_sobj[j]->m_iptype, false, _out);

            PRINT_DBG_HEAD
            print_dbg("webproxy task%d: Name[%s] IP[%s] Mask[%s] Mac[%s] Type[%d]", i,
                      webproxy->m_sobj[j]->m_objectname,
                      webproxy->m_sobj[j]->m_ipaddress,
                      webproxy->m_sobj[j]->m_netmask,
                      webproxy->m_sobj[j]->m_mac,
                      webproxy->m_sobj[j]->m_iptype);
        }

        READ_INT(fileop, taskno, "TimeType", webproxy->m_timemod.m_timetype, true, _out);
        READ_STRING(fileop, taskno, "StartTime", webproxy->m_timemod.m_stime, true, _out);
        READ_STRING(fileop, taskno, "EndTime", webproxy->m_timemod.m_etime, true, _out);
        READ_STRING(fileop, taskno, "StartDate", webproxy->m_timemod.m_sdate, true, _out);
        READ_STRING(fileop, taskno, "EndDate", webproxy->m_timemod.m_edate, true, _out);
        READ_STRING(fileop, taskno, "WeekDays", webproxy->m_timemod.m_weekdays, true, _out);
        READ_INT(fileop, taskno, "URLFlag", webproxy->m_urlflag, true, _out);

        if (webproxy->m_urlflag != 0) { //启用过滤的时候，才读URLs
            READ_STRING(fileop, taskno, "URLs", webproxy->m_urls, false, _out);
        }

        PRINT_DBG_HEAD
        print_dbg("Task%d Area:%d ListenIP:%s ListenPort:%s SobjNum:%d URLFlag:%d URLs:%s", i,
                  webproxy->m_areaway, webproxy->m_listenip, webproxy->m_listenport,
                  webproxy->m_sobjnum, webproxy->m_urlflag, webproxy->m_urls);
    }

    fileop.CloseFile();
    return 0;
_out:
    fileop.CloseFile();
    return -1;
}

/**
 * [WebProxyMG::addTask 增加一个任务]
 * @return  [任务指针]
 */
WebProxyTask *WebProxyMG::addTask(void)
{
    if (m_task_num == ARRAY_SIZE(m_task)) {
        PRINT_ERR_HEAD
        print_err("reach max support webproxynum[%d]", ARRAY_SIZE(m_task));
        return NULL;
    }
    m_task[m_task_num] = new WebProxyTask(m_task_num);
    if (m_task[m_task_num] == NULL) {
        PRINT_ERR_HEAD
        print_err("new WebProxyTask fail. current tasknum[%d]", m_task_num);
        return NULL;
    }
    m_task_num++;

    return m_task[m_task_num - 1];
}

/**
 * [WebProxyMG::taskNum 任务数]
 * @return  [任务数]
 */
int WebProxyMG::taskNum(void)
{
    return m_task_num;
}

/**
 * [WebProxyMG::setTmpIP 设置临时IP 即内部跳转IP]
 * @param  innum  [内网业务IP个数]
 * @param  outnum [外网业务IP个数]
 * @return        [成功返回true]
 */
bool WebProxyMG::setTmpIP(int innum, int outnum)
{
    if ((innum <= 0) || (outnum <= 0)) {
        PRINT_ERR_HEAD
        print_err("inipnum[%d] outipnum[%d]", innum, outnum);
        return false;
    }
    MakeV4NatIP(false, g_linklanipseg, innum + 1, m_out_tmpip4, sizeof(m_out_tmpip4));
    MakeV4NatIP(true, g_linklanipseg, outnum + 1, m_in_tmpip4, sizeof(m_in_tmpip4));
    MakeV6NatIP(false, g_linklanipseg, innum + 2, m_out_tmpip6, sizeof(m_out_tmpip6));
    MakeV6NatIP(true, g_linklanipseg, outnum + 2, m_in_tmpip6, sizeof(m_in_tmpip6));
    PRINT_INFO_HEAD
    print_info("innum[%d] outnum[%d] m_in_tmpip4[%s] m_out_tmpip4[%s] m_in_tmpip6[%s] m_out_tmpip6[%s]",
               innum, outnum, m_in_tmpip4, m_out_tmpip4, m_in_tmpip6, m_out_tmpip6);
    return true;
}

/**
 * [WebProxyMG::setDns 设置DNS]
 * @param  dns     [DNS]
 * @param  dnsipv6 [DNS ipv6]
 * @return         [成功返回true]
 */
bool WebProxyMG::setDns(const char *dns, const char *dnsipv6)
{
    if (dns == NULL) {
        PRINT_ERR_HEAD
        print_err("dns null[%s]", dns);
        return false;
    }
    strcpy(m_dns, dns);
    if (dnsipv6 != NULL) {
        strcpy(m_dnsipv6, dnsipv6);
    }
    PRINT_INFO_HEAD
    print_info("webproxy dns[%s] dnsipv6[%s]", m_dns, m_dnsipv6);
    return true;
}

/**
 * [WebProxyMG::setTmpIP 为每个任务设置内部跳转IP]
 * @return  [成功返回true]
 */
bool WebProxyMG::setTmpIP(void)
{
    for (int i = 0; i < m_task_num; ++i) {
        if (is_ip6addr(m_task[i]->m_listenip)) {
            m_task[i]->setLinkIP((m_task[i]->getAreaway() == 0) ? m_out_tmpip6 : m_in_tmpip6);
        } else {
            m_task[i]->setLinkIP((m_task[i]->getAreaway() == 0) ? m_out_tmpip4 : m_in_tmpip4);
        }
    }
    return true;
}

/**
 * [WebProxyMG::run 运行任务]
 */
void WebProxyMG::run(void)
{
    setTmpIP();
    clearWebproxyIptables();
    deleteSingle();
    createSingle();
    setWebproxyIptables();
    modNginxMG();
}

/**
 * [WebProxyMG::clearWebproxyIptables 清理iptables]
 * @return  [成功返回true]
 */
bool WebProxyMG::clearWebproxyIptables(void)
{
    sem_wait(g_iptables_lock);
    system("iptables -F FILTER_WEBPROXY");
    system("ip6tables -F FILTER_WEBPROXY");
    system("iptables -t nat -F NAT_WEBPROXY");
    system("ip6tables -t nat -F NAT_WEBPROXY");
    sem_post(g_iptables_lock);
    PRINT_INFO_HEAD
    print_info("clear webproxy iptables over");
    return true;
}

/**
 * [WebProxyMG::setWebproxyIptables 设置iptables 限制访问的源对象]
 * @return  [成功返回true]
 */
bool WebProxyMG::setWebproxyIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpranges[128] = {0};
    char tmpranged[128] = {0};

    for (int i = 0; i < m_task_num; ++i) {
        if (!IsCloseToSRCObj(m_task[i]->getAreaway())) {
            continue;
        }
        if (m_task[i]->jumpQueue()) {
            MAKE_TABLESTRING(chcmd,
                             "-A FILTER_WEBPROXY -o eth%d -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0",
                             is_ip6addr(m_task[i]->m_listenip), g_linklan,
                             m_task[i]->getLinkIP(), m_task[i]->getLinkPort());
            sem_wait(g_iptables_lock);
            system(chcmd);
            sem_post(g_iptables_lock);
        }
        for (int j = 0; j < m_task[i]->m_sobjnum; ++j) {
            if (ipTypeCheck(m_task[i]->m_listenip, m_task[i]->m_sobj[j]->m_iptype)) {
                BZERO(tmpranges);
                BZERO(tmpranged);
                if (is_ip6addr(m_task[i]->m_listenip)) {
                    MAKE_TABLESTRING(chcmd, "-t nat -A NAT_WEBPROXY %s %s -p tcp --dport %s %s -j DNAT --to [%s]:%s",
                                     true, RangeIpStr('s', m_task[i]->m_sobj[j]->m_ipaddress, tmpranges),
                                     RangeIpStr('d', m_task[i]->m_listenip, tmpranged),
                                     m_task[i]->getListenPort(), m_task[i]->timestring(),
                                     m_task[i]->getLinkIP(), m_task[i]->getLinkPort());
                } else {
                    MAKE_TABLESTRING(chcmd, "-t nat -A NAT_WEBPROXY %s %s -p tcp --dport %s %s -j DNAT --to %s:%s",
                                     false, RangeIpStr('s', m_task[i]->m_sobj[j]->m_ipaddress, tmpranges),
                                     RangeIpStr('d', m_task[i]->m_listenip, tmpranged),
                                     m_task[i]->getListenPort(), m_task[i]->timestring(),
                                     m_task[i]->getLinkIP(), m_task[i]->getLinkPort());
                }
                sem_wait(g_iptables_lock);
                system(chcmd);
                sem_post(g_iptables_lock);
                PRINT_INFO_HEAD
                print_info("webproxy[%s]", chcmd);
            } else {
                PRINT_INFO_HEAD
                print_info("ignore sobj[%s]", m_task[i]->m_sobj[j]->m_ipaddress);
            }
        }
    }
    return true;
}

/**
 * [WebProxyMG::ipTypeCheck 检查IP类型是否相同]
 * @param  ip     [IP]
 * @param  iptype [IP类型]
 * @return        [相同返回true]
 */
bool WebProxyMG::ipTypeCheck(const char *ip, int iptype)
{
    if ((is_ip6addr(ip) && (iptype == IP_TYPE6))
        || ((!is_ip6addr(ip)) && (iptype == IP_TYPE4))) {
        return true;
    } else {
        return false;
    }
}

/**
 * [WebProxyMG::modNginxMG 修改nginx管理类的配置信息]
 * @return  [成功返回true]
 */
bool WebProxyMG::modNginxMG(void)
{
    g_nginx.clear_httpconf();
    for (int i = 0; i < m_task_num; ++i) {
        if (!IsCloseToSRCObj(m_task[i]->getAreaway())) {
            g_nginx.push_back(m_task[i]->getLinkIP(), atoi(m_task[i]->getLinkPort()), m_dns, m_dnsipv6);
        }
    }

    PRINT_INFO_HEAD
    print_info("mod nginx mg over.http rule num[%d]", g_nginx.rule_num_http());
    return true;
}

/**
 * [WebProxyMG::deleteSingle delete删除WEB代理处理对象]
 * @return  [成功返回true]
 */
bool WebProxyMG::deleteSingle(void)
{
    PRINT_INFO_HEAD
    print_info("delete webproxy single begin");

    sem_wait(&g_weblock);
    DELETE_N(g_webapp, C_WEB_PROXY_MAXNUM);
    g_webappnum = 0;
    sem_post(&g_weblock);

    PRINT_INFO_HEAD
    print_info("delete webproxy single over");
    return true;
}

/**
 * [WebProxyMG::createSingle 创建WEB代理数据处理对象]
 * @return  [成功返回true]
 */
bool WebProxyMG::createSingle(void)
{
    PRINT_INFO_HEAD
    print_info("create webproxy single begin");

    sem_wait(&g_weblock);

    for (int i = 0; i < m_task_num; ++i) {
        if (!IsCloseToSRCObj(m_task[i]->getAreaway())) {
            continue;
        }
        if (m_task[i]->jumpQueue()) {
            g_webapp[g_webappnum] = new CWEBPROXYSINGLE();
            strcpy(g_webapp[g_webappnum]->m_listenip, m_task[i]->getListenIP());
            strcpy(g_webapp[g_webappnum]->m_listenport, m_task[i]->getListenPort());
            strcpy(g_webapp[g_webappnum]->m_linkip, m_task[i]->getLinkIP());
            strcpy(g_webapp[g_webappnum]->m_linkport, m_task[i]->getLinkPort());
            g_webapp[g_webappnum]->m_urlflag = m_task[i]->getUrlFlag();
            if (m_task[i]->getUrlFlag() != 0) {
                g_webapp[g_webappnum]->GetUrlList(m_task[i]->getUrls());
            }
            if (is_ip6addr(m_task[i]->m_listenip)) {
                inet_pton(AF_INET6, m_task[i]->getLinkIP(), (void *) & (g_webapp[g_webappnum]->m_ipv6tmpip));
            } else {
                ip4addr_t addr1;
                inet_pton(AF_INET, m_task[i]->getLinkIP(), (void *)&addr1);
                g_webapp[g_webappnum]->m_tmpip = htonl(addr1.s_addr);
            }
            g_webappnum++;
        }
    }

    sem_post(&g_weblock);

    PRINT_INFO_HEAD
    print_info("create webproxy single over. webappnum[%d]", g_webappnum);
    return true;
}

/**
 * [WebProxyMG::getAreaway 获取下标为i的任务的方向]
 * @param  i [任务下标]
 * @return   [成功返回 0内到外 1外到内 失败返回负值]
 */
int WebProxyMG::getAreaway(int i)
{
    if ((i < 0) || (i >= m_task_num)) {
        PRINT_ERR_HEAD
        print_err("input error[%d] tasknum[%d]", i, m_task_num);
        return -1;
    }

    return m_task[i]->getAreaway();
}

/**
 * [WebProxyMG::getListenIP 获取下标为i的任务的监听IP]
 * @param  i [任务下标]
 * @return   [成功返回监听IP 失败返回NULL]
 */
const char *WebProxyMG::getListenIP(int i)
{
    if ((i < 0) || (i >= m_task_num)) {
        PRINT_ERR_HEAD
        print_err("input error[%d] tasknum[%d]", i, m_task_num);
        return NULL;
    }

    return m_task[i]->getListenIP();
}

/**
 * [WebProxyMG::clear清理任务]
 * @return  [成功返回true]
 */
bool WebProxyMG::clear(void)
{
    PRINT_INFO_HEAD
    print_info("webproxy mg clear begin");

    DELETE_N(m_task, m_task_num);
    m_task_num = 0;
    g_cardmg.clear(WEBPROXY_MOD);

    PRINT_INFO_HEAD
    print_info("webproxy mg clear over");
    return true;
}
