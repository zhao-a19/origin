/*******************************************************************************************
*文件: base.cpp
*描述: 平台互联基类
*作者: 王君雷
*日期: 2020-08-18
*修改:
*      使用的第一个通道端口号以及通道最大支持数可以通过配置文件配置 ------> 2020-09-03
*      对于video动态端口，只有返回码为200时才开通道，否则只替换端口------> 2020-09-14
*      流媒体通道传输层协议，可以自动识别也可以通过配置指定        ------> 2020-09-15
*      开通通道以后可以通过配置决定是否需要清空连接追踪表，默认不开启 ------> 2020-09-16
*      操作通道时优先处理POSTROUTING                              ------> 2020-09-22
*      支持替换CallID中的IP                                       ------> 2020-09-28
*      使用select函数处理TCP SIP连接防止关闭描述符混乱            ------> 2020-12-04
*      通道添加enable属性，可支持SIP端口正好在动态通道端口范围内的情况 ------> 2021-07-08
*******************************************************************************************/
#include "base.h"
#include "debugout.h"
#include "FCPeerExecuteCMD.h"
#include "quote_global.h"
#include "FCLogContainer.h"

extern sem_t *g_iptables_lock;

base::base(int taskid, bool siptcp)
{
    m_taskid = taskid;
    m_siptcp = siptcp;
    m_lastid = -1;
    m_pchannel = NULL;
    if (m_siptcp) {
        if (sem_init(&m_tcplock, 0, 1) == -1) {
            PRINT_ERR_HEAD
            print_err("init tcp lock fail");
        }
    }
    if (sem_init(&m_channellock, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init channel lock fail");
    }

    m_first_chport = 30000;//默认3万
    m_max_channel = 3000;  //默认3千
    m_stream_type = STREAM_TYPE_AUTO;
    m_clean_track = 0;
}

base::~base(void)
{
    if (m_pchannel != NULL) {
        delete[] m_pchannel;
    }
    DELETE_N(m_cmd, m_cmdnum);
    if (m_siptcp) {
        sem_destroy(&m_tcplock);
    }
    sem_destroy(&m_channellock);
}

/**
 * [base::getTCPThreadID 获取一个线程]
 * @return  [成功返回线程ID 失败返回负值]
 */
int base::getTCPThreadID(void)
{
    int ret = -1;
    if (m_siptcp) {
        sem_wait(&m_tcplock);
        for (int i = 0; i < (int)ARRAY_SIZE(m_tcpstate); i++) {
            if (m_tcpstate[i] == STATUS_FREE) {
                m_tcpstate[i] = STATUS_INUSE;
                ret = i;
                PRINT_DBG_HEAD
                print_dbg("get threadid [%d]", ret);
                break;
            }
        }
        sem_post(&m_tcplock);
    }
    return ret;
}

/**
 * [base::createThread 创建启动一个线程]
 * @param  func  [线程函数]
 * @param  ptask [线程参数]
 * @return       [成功返回true]
 */
bool base::createThread(threadfunc func, PBTASK ptask)
{
    PRINT_DBG_HEAD
    print_dbg("create thread begin");

    pthread_t pid = 0;
    bool bflag = (pthread_create(&pid, NULL, func, ptask) == 0);
    if (bflag) {
    } else {
        PRINT_ERR_HEAD
        print_err("create thread error");
        DELETE(ptask);
    }

    PRINT_DBG_HEAD
    print_dbg("create thread over");
    return bflag;
}

/**
 * [base::releaseTCPThread 释放TCP线程]
 * @param  threadid [线程下标]
 * @param  ssock    [发送用socket]
 * @param  rsock    [接收用socket]
 * @return          [成功返回true]
 */
bool base::releaseTCPThread(int threadid, int ssock, int rsock)
{
    if ((threadid < 0) || (ssock <= 0) || (rsock <= 0)) {
        PRINT_ERR_HEAD
        print_err("para error.threadid[%d]ssock[%d]rsock[%d]", threadid, ssock, rsock);
        return false;
    }

    if (!m_siptcp) {
        PRINT_INFO_HEAD
        print_info("not use sip tcp");
        return false;
    }

    sem_wait(&m_tcplock);
    if (m_tcpstate[threadid] == STATUS_INUSE) {
        PRINT_DBG_HEAD
        print_dbg("threadid[%d] tcp close ssock[%d] rsock[%d]", threadid, ssock, rsock);
        close(ssock);
        close(rsock);
        m_tcpstate[threadid] = STATUS_FREE;
    } else {
        PRINT_ERR_HEAD
        print_err("threadid[%d] something may error tcpstate[%d]", threadid, m_tcpstate[threadid]);
    }
    sem_post(&m_tcplock);
    return true;
}

/**
 * [base::initTCPMember 初始化TCP传输SIP使用到的成员变量]
 * @return  [成功返回0]
 */
int base::initTCPMember(void)
{
    if (!m_siptcp) {
        PRINT_INFO_HEAD
        print_info("not use sip tcp");
        return -1;
    }
    memset(m_tcpstate, STATUS_FREE, sizeof(m_tcpstate));
    return 0;
}

/**
 * [base::inStart 启动内网]
 */
void base::inStart(void)
{
    showConf();
    setInIptables();
    if (initChannel() != 0) {
        PRINT_ERR_HEAD
        print_err("init channel fail");
        return;
    }
    startUDPThreads();
    if (m_siptcp) {
        initTCPMember();
        startTCPThreads();
    }
}

/**
 * [base::outStart 启动外网]
 */
void base::outStart(void)
{
    showConf();
    setOutIptables();
}

/**
 * [base::setInIptables 设置内网侧IPtables]
 */
void base::setInIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_INFO_HEAD
    print_info("set in iptables begin");

    //FORWARD
    sprintf(chcmd, "%s -I FORWARD -s %s -j ACCEPT", IPTABLES, m_inneroutip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -d %s -p tcp --dport %d:%d -j ACCEPT", IPTABLES,
            m_inneroutip, m_first_chport, LAST_CHANNEL_PORT(m_first_chport, m_max_channel));
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -d %s -p udp --dport %d:%d -j ACCEPT", IPTABLES,
            m_inneroutip, m_first_chport, LAST_CHANNEL_PORT(m_first_chport, m_max_channel));
    systemCmd(chcmd);

    //INPUT
    sprintf(chcmd, "%s -A INPUT -p udp -d %s --dport %s ! -s %s -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -A INPUT -p tcp -d %s --dport %s ! -s %s -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    //POSTROUTING
    sprintf(chcmd, "%s -t nat -I POSTROUTING -d %s -j SNAT --to %s", IPTABLES, m_inneroutip, m_innerinip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j SNAT --to %s", IPTABLES, m_inneroutip, m_gapinip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j ACCEPT", IPTABLES, m_gapinip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);

    PRINT_INFO_HEAD
    print_info("set in iptables over");
}

/**
 * [base::setOutIptables 设置外网侧的IPtables]
 */
void base::setOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_INFO_HEAD
    print_info("set out iptables begin");

    //PREROUTING
    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p udp --sport %s --dport %s -j DNAT --to %s",
            IPTABLES, m_innerinip, m_inneroutip, m_inport, m_outport, m_outcenter);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p udp --sport %s --dport %s -j DNAT --to %s",
            IPTABLES, m_outcenter, m_gapoutip, m_outport, m_inport, m_innerinip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p tcp --dport %s -j DNAT --to %s",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I PREROUTING -s %s -d %s -p tcp --dport %s -j DNAT --to %s",
            IPTABLES, m_outcenter, m_gapoutip, m_inport, m_innerinip);
    systemCmd(chcmd);

    //POSTROUTING
    sprintf(chcmd, "%s -t nat -I POSTROUTING -s %s -j SNAT --to %s", IPTABLES, m_innerinip, m_gapoutip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -t nat -I POSTROUTING -d %s -j SNAT --to %s", IPTABLES, m_innerinip, m_inneroutip);
    systemCmd(chcmd);

    //FORWARD
    sprintf(chcmd, "%s -I FORWARD -s %s -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -s %s -d %s -p tcp --sport %s --dport %s -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -s %s -d %s -p udp --sport %s --dport %s -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -d %s -p udp --dport %d:%d -j ACCEPT", IPTABLES,
            m_innerinip, m_first_chport, LAST_CHANNEL_PORT(m_first_chport, m_max_channel));
    systemCmd(chcmd);
    sprintf(chcmd, "%s -I FORWARD -d %s -p tcp --dport %d:%d -j ACCEPT", IPTABLES,
            m_innerinip, m_first_chport, LAST_CHANNEL_PORT(m_first_chport, m_max_channel));
    systemCmd(chcmd);

    PRINT_INFO_HEAD
    print_info("set out iptables over");
}

/**
 * [base::showConf 展示配置信息]
 */
void base::showConf(void)
{
    PRINT_DBG_HEAD
    print_dbg("Name[%d] = %s", m_taskid, m_name);
    PRINT_DBG_HEAD
    print_dbg("InDev = %d, OutDev = %d", m_secway.getindev(), m_secway.getoutdev());
    PRINT_DBG_HEAD
    print_dbg("InCenter = %s, OutCenter = %s", m_incenter, m_outcenter);
    PRINT_DBG_HEAD
    print_dbg("InPort = %s, OutPort = %s", m_inport, m_outport);
    PRINT_DBG_HEAD
    print_dbg("GapInIP = %s, GapOutIP = %s", m_gapinip, m_gapoutip);
    PRINT_DBG_HEAD
    print_dbg("InBrandID = %d, OutBrandID = %d", m_inbrandid, m_outbrandid);
    PRINT_DBG_HEAD
    print_dbg("Protocol = %s, DefCmdAction = %d", m_proto, m_defaultaction ? 1 : 0);
    PRINT_DBG_HEAD
    print_dbg("InnerInIP = %s, InnerOutIP = %s", m_innerinip, m_inneroutip);
    PRINT_DBG_HEAD
    print_dbg("FirstChPort = %d, MaxChannel = %d", m_first_chport, m_max_channel);
    PRINT_DBG_HEAD
    print_dbg("StreamType = %d, CleanTrack = %d", m_stream_type, m_clean_track);

    for (int j = 0; j < m_cmdnum; j++) {
        PRINT_DBG_HEAD
        print_dbg("cmd[%s] para[%s] action[%s]",
                  m_cmd[j]->m_cmd, m_cmd[j]->m_parameter, m_cmd[j]->m_action ? "allow" : "forbid");
    }
}

/**
 * [base::startUDPThreads 开启UDP任务线程]
 */
void base::startUDPThreads(void)
{
    CBSUdpSockServer srvudp1, srvudp2;
    PBTASK ptask1 = NULL, ptask2 = NULL;

    int sockudp1 = srvudp1.Open(m_gapinip, atoi(m_outport));
    int sockudp2 = srvudp2.Open(m_innerinip, atoi(m_inport));
    if ((sockudp1 < 0) || (sockudp2 < 0)) {
        PRINT_ERR_HEAD
        print_err("sock1=[%d][%s:%s],sock2=[%d][%s:%s]",
                  sockudp1, m_outport, m_gapinip, sockudp2, m_inport, m_innerinip);
        goto _out;
    }

    ptask1 = new BTASK();
    ptask2 = new BTASK();
    if ((ptask1 == NULL) || (ptask2 == NULL)) {
        PRINT_ERR_HEAD
        print_err("new task fail");
        goto _out;
    }

    ptask1->recvsock = ptask2->sendsock = sockudp1;
    ptask1->sendsock = ptask2->recvsock = sockudp2;
    ptask1->psip = ptask2->psip = this;
    ptask1->recvarea = RECV_IN_CENTER;
    ptask2->recvarea = RECV_OUT_CENTER;
    createThread(UDPThread, ptask1);
    createThread(UDPThread, ptask2);

    PRINT_INFO_HEAD
    print_info("start udp threads over");
    return;
_out:
    PRINT_ERR_HEAD
    print_err("start udp threads fail");
    CLOSE(sockudp1);
    CLOSE(sockudp2);
    DELETE(ptask1);
    DELETE(ptask2);
    return;
}

/**
 * [base::startTCPThreads 开启TCP任务线程]
 */
void base::startTCPThreads(void)
{
    PBTASK ptask1 = NULL, ptask2 = NULL;
    ptask1 = new BTASK();
    ptask2 = new BTASK();
    if ((ptask1 == NULL) || (ptask2 == NULL)) {
        PRINT_ERR_HEAD
        print_err("new task error");
        goto _out;
    }

    ptask1->recvsock = ptask1->sendsock = -1;
    ptask2->recvsock = ptask2->sendsock = -1;
    ptask1->psip = ptask2->psip = this;
    ptask1->recvarea = LISTEN_IN_CENTER;
    ptask2->recvarea = LISTEN_OUT_CENTER;
    createThread(TCPThread, ptask1);
    createThread(TCPThread, ptask2);

    PRINT_INFO_HEAD
    print_info("start tcp threads over");
    return;
_out:
    PRINT_ERR_HEAD
    print_err("start tcp threads fail");
    DELETE(ptask1);
    DELETE(ptask2);
    return;
}

/**
 * [base::getSecway 返回安全通道]
 * @return  [安全通道的引用]
 */
SEC_WAY &base::getSecway(void)
{
    return m_secway;
}

/**
 * [base::getGapInIp 获取网闸内网业务IP]
 * @return  [IP]
 */
const char *base::getGapInIp(void)
{
    return m_gapinip;
}

/**
 * [base::getGapOutIp 获取网闸外网业务IP]
 * @return  [IP]
 */
const char *base::getGapOutIp(void)
{
    return m_gapoutip;
}

/**
 * [base::setInnerInIp 为m_innerinip赋值]
 * @param ip     [IP]
 * @return       [成功返回true]
 */
bool base::setInnerInIp(const char *ip)
{
    int len = sizeof(m_innerinip);
    if ((ip != NULL) && (int)strlen(ip) < len) {
        strcpy(m_innerinip, ip);
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("ip[%s] error", ip);
        return false;
    }
}

/**
 * [base::setInnerOutIp 为m_inneroutip赋值]
 * @param ip     [IP]
 * @return       [成功返回true]
 */
bool base::setInnerOutIp(const char *ip)
{
    int len = sizeof(m_inneroutip);
    if ((ip != NULL) && (int)strlen(ip) < len) {
        strcpy(m_inneroutip, ip);
        return true;
    } else {
        PRINT_ERR_HEAD
        print_err("ip[%s] error", ip);
        return false;
    }
}

/**
 * [base::systemCmd system执行命令]
 * @param cmd  [命令]
 * @param side [本端执行，还是让对端执行]
 */
void base::systemCmd(const char *cmd, bool side)
{
    PRINT_INFO_HEAD
    print_info("[%s]%s", side ? "self" : "peer", cmd);

    if (side) {
        system(cmd);
    } else {
        PeerExecuteCMD(cmd);
    }
}

/**
 * [base::initChannel 通道初始化]
 * @return  [成功返回0]
 */
int base::initChannel(void)
{
#define PORT_EQ(a, b) (((a)-(b)==0) || ((a)-(b)==1) || ((a)-(b)==2) || ((a)-(b)==3))

    PRINT_INFO_HEAD
    print_info("init channel begin");

    while ((m_pchannel = new BCHANNEL[m_max_channel]) == NULL) {
        PRINT_ERR_HEAD
        print_err("m_max_channel[%d] new channel fail, retry...", m_max_channel);
        sleep(1);
    }
    memset(m_pchannel, 0, sizeof(BCHANNEL) * m_max_channel);
    for (int i = 0; i < m_max_channel; i++) {
        m_pchannel[i].proxyport = (m_first_chport + 4 * i);
        if (PORT_EQ(atoi(m_inport), m_first_chport + 4 * i)
            || PORT_EQ(atoi(m_outport), m_first_chport + 4 * i)) {
            m_pchannel[i].enable = false;
            PRINT_INFO_HEAD
            print_info("disable channel[%d] port[%d]", i, m_first_chport + 4 * i);
        } else {
            m_pchannel[i].enable = true;
        }
    }

    PRINT_INFO_HEAD
    print_info("init channel over.first channel port[%d] last channel port[%d] max channel[%d]",
               m_first_chport, LAST_CHANNEL_PORT(m_first_chport, m_max_channel), m_max_channel);
    return 0;
}

/**
 * [base::clearVec 清理VECOTR]
 * @param bvec [vector]
 */
void base::clearVec(vector<BLOCK> &bvec)
{
    vector<BLOCK>::iterator iter;
    for (iter = bvec.begin(); iter != bvec.end(); iter++) {
        if (iter->bmalloc) {
            if (iter->nbegin != NULL) {
                free(iter->nbegin);
                iter->nbegin = NULL;
            }
        }
    }
    bvec.clear();
}

/**
 * [base::combineMsg 重组消息]
 * @param dst  [目的缓冲区]
 * @param bvec [vector]
 * @return     [消息长度]
 */
int base::combineMsg(char *dst, vector<BLOCK> &bvec)
{
    int ret = 0;
    vector<BLOCK>::iterator iter;
    for (iter = bvec.begin(); iter != bvec.end(); iter++) {
        if (iter->bmalloc) {
            memcpy(dst + ret, iter->nbegin, iter->nlen);
            ret += iter->nlen;
        } else {
            memcpy(dst + ret, iter->begin, iter->len);
            ret += iter->len;
        }
    }
    return ret;
}

/**
 * [base::adjustLen 调整长度]
 * @param pinfo [PACKET_INFO]
 * @param bvec  [vector]
 */
bool base::adjustLen(PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    if (pinfo.multipart
        && pinfo.subsdp
        && (pinfo.sub_content_len_index > 0)
        && (pinfo.sub_content_len_change != 0)) {
        PRINT_INFO_HEAD
        print_info("sub content len change[%d]", pinfo.sub_content_len_change);
        BLOCK &block = bvec[pinfo.sub_content_len_index];
        int newlen = atoi(block.begin) + pinfo.sub_content_len_change;
        block.nbegin = (char *)malloc(16);
        if (block.nbegin == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc fail [%s]", strerror(errno));
            return false;
        }
        memset(block.nbegin, 0, 16);
        sprintf(block.nbegin, "%d", newlen);
        block.nlen = strlen(block.nbegin);
        block.bmalloc = true;
        pinfo.content_len_change += block.nlen - block.len;
        PRINT_INFO_HEAD
        print_info("old sublen[%d] new sublen[%d] [%s]", block.len, block.nlen, block.nbegin);
    }

    if ((pinfo.content_len_index > 0) && (pinfo.content_len_change != 0)) {
        PRINT_INFO_HEAD
        print_info("content len change[%d]", pinfo.content_len_change);
        BLOCK &block = bvec[pinfo.content_len_index];
        int newlen = atoi(block.begin) + pinfo.content_len_change;
        block.nbegin = (char *)malloc(16);
        if (block.nbegin == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc fail [%s]", strerror(errno));
            return false;
        }
        memset(block.nbegin, 0, 16);
        sprintf(block.nbegin, "%d", newlen);
        block.nlen = strlen(block.nbegin);
        block.bmalloc = true;
        PRINT_INFO_HEAD
        print_info("old len[%d] new len[%d] [%s]", block.len, block.nlen, block.nbegin);
    }
    return true;
}

/**
 * [base::processData 替换处理SIP数据]
 * @param  src      [源数据]
 * @param  len      [源数据长度]
 * @param  dst      [存放替换处理之后的数据 出参]
 * @param  recvarea [接收方向]
 * @return          [返回替换之后的长度 失败返回负值]
 */
int base::processData(const char *src, int len, char *dst, int recvarea)
{
    if ((src == NULL) || (len < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("process data begin. recvarea[%s]", (recvarea == RECV_IN_CENTER) ? "incenter" : "outcenter");

    vector<BLOCK> bvec;
    PACKET_INFO pinfo;
    BZERO(pinfo);
    pinfo.recvarea = recvarea;
    int ret = 0;
    int slen = strlen(src);
    const char *limit = src + slen;
    const char *p = src;
    const char *q = NULL;

    while (p < limit) {
        q = strchr(p, '\n');
        if (q != NULL) {
            if (!doLine(p, q, pinfo, bvec)) {
                goto _out;
            }
            p = q + 1;
        } else {
            if (!doLine(p, limit - 1, pinfo, bvec)) {
                goto _out;
            }
            break;
        }
    }
    if (!adjustLen(pinfo, bvec))
        goto _out;
    ret = combineMsg(dst, bvec);
    if (len > slen) {
        memcpy(dst + ret, src + slen, len - slen);
        ret += len - slen;
    }
    clearVec(bvec);
    return ret;
_out:
    clearVec(bvec);
    return -1;
}

/**
 * [base::getCmd 从命令行中取出命令]
 * @param  chcmd   [取出的命令 出参]
 * @param  cmdsize [命令缓冲区大小 入参]
 * @param  cmdline [可能包含命令的数据包 入参]
 * @return         [取命令成功返回true，否则返回false]
 */
bool base::getCmd(char *chcmd, int cmdsize, const char *cmdline)
{
    //参数检查
    if ((chcmd == NULL) || (cmdline == NULL) || (cmdsize <= 4)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    //xml行 没有命令
    if (cmdline[0] == '<') {
        PRINT_ERR_HEAD
        print_err("find <");
        return false;
    }

    memset(chcmd, 0, cmdsize);
    char *p = (char *)strchr(cmdline, ' ');
    if (p != NULL) {
        if ((p - cmdline) < cmdsize) {
            memcpy(chcmd, cmdline, p - cmdline);
        } else {
            memcpy(chcmd, cmdline, cmdsize - 4);
            strcat(chcmd, "...");
        }
    } else {
        if ((int)strlen(cmdline) < cmdsize) {
            strcpy(chcmd, cmdline);
        } else {
            memcpy(chcmd, cmdline, cmdsize - 4);
            strcat(chcmd, "...");
        }
    }

    //如果命令第一个字符不是字母，不记录日志
    if (!isalpha(chcmd[0])) {
        PRINT_ERR_HEAD
        print_err("is not letter cmd[%s]", cmdline);
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("find cmd[%s] packlen[%d]", chcmd, (int)strlen(cmdline));
    return true;
}

/**
 * [base::filterCmd 过滤信令]
 * @param  chcmd    [信令]
 * @param  recvarea [接收区域]
 * @return          [放过返回true 阻止返回false]
 */
bool base::filterCmd(const char *chcmd, int recvarea)
{
    if (chcmd == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    bool flag = m_defaultaction;
    for (int i = 0; i < m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_cmd[i]->m_cmd) == 0) {
            flag = m_cmd[i]->m_action;
            break;
        }
    }
    recordCallLog(chcmd, flag, recvarea);
    return flag;
}

/**
 * [base::isResponse 是否为响应]
 * @param  line [数据包内容]
 * @param  retcode [返回码]
 * @return      [是返回true，并把返回码存放到retcode；否返回false]
 */
bool base::isResponse(const char *line, int &retcode)
{
    char ch[16] = "SIP/";
    bool bflag = false;
    if (strncmp(line, ch, strlen(ch)) == 0) {
        bflag = true;
        const char *p = strchr(line, ' ');
        if (p != NULL) {
            retcode = atoi(p + 1);
        } else {
            PRINT_INFO_HEAD
            print_info("get retcode fail[%s]", line);
        }
    } else {
        if ((strlen(line) > 4) && (isdigit(line[0])) && (isdigit(line[1]))
            && (isdigit(line[2])) && (line[3] == '\r')) {
            bflag = true;
            retcode = atoi(line);
        }
    }

    PRINT_DBG_HEAD
    print_dbg("%s retcode[%d]", bflag ? "response" : "request", retcode);
    return bflag;
}

/**
 * [base::getTypeDesc 获取策略类型描述]
 * @return  [策略类型]
 */
const char *base::getTypeDesc(void)
{
    return LOG_TYPE_SIP_INTERCONNECT;
}

/**
 * [base::recordCallLog 记录访问日志]
 * @param chcmd      [信令]
 * @param result     [是否放行]
 * @param recvarea   [数据接收区域]
 */
void base::recordCallLog(const char *chcmd, bool result, int recvarea)
{
    if (g_iflog || g_syslog) {
        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues("",
                             (RECV_IN_CENTER == recvarea) ? m_incenter : m_outcenter,
                             (RECV_IN_CENTER == recvarea) ? m_outcenter : m_incenter,
                             (RECV_IN_CENTER == recvarea) ? m_inport : m_outport,
                             (RECV_IN_CENTER == recvarea) ? m_outport : m_inport,
                             "", "",
                             getTypeDesc(), chcmd, "",
                             result ? D_SUCCESS : D_REFUSE,
                             result ? "" : LOG_CONTENT_REFUSE)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[sip %s, dip %s, sport %s, dport %s, %s:%s]",
                          (RECV_IN_CENTER == recvarea) ? m_incenter : m_outcenter,
                          (RECV_IN_CENTER == recvarea) ? m_outcenter : m_incenter,
                          (RECV_IN_CENTER == recvarea) ? m_inport : m_outport,
                          (RECV_IN_CENTER == recvarea) ? m_outport : m_inport,
                          getTypeDesc(), chcmd);
                delete p;
            }
        }
    }
    return;
}


/**
 * [base::doLine 处理一行SIP信息的内容]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    //处理起始行
    if (bvec.size() == 0) {
        pinfo.isresponse = isResponse(begin, pinfo.retcode);
        return doStartLine(begin, end, pinfo, bvec);
    }
    //处理头域包体分割行
    if (memcmp(begin, "\r\n", 2) == 0) {
        pinfo.find_rn = true;
        BLOCK block;
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        PRINT_INFO_HEAD
        print_info("find 0d0a");
        return true;
    }
    //处理头域行
    if (!pinfo.find_rn) {
        return doHeaderLine(begin, end, pinfo, bvec);
    }
    //处理包体行
    return doBodyLine(begin, end, pinfo, bvec);
}

/**
 * [base::doStartLine 处理起始行]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [返回false表示丢弃]
 */
bool base::doStartLine(const char *begin, const char *end, PACKET_INFO &pinfo, vector<BLOCK> &bvec)
{
    if (!pinfo.isresponse) {
        if (getCmd(pinfo.chcmd, sizeof(pinfo.chcmd), begin)) {
            if (!filterCmd(pinfo.chcmd, pinfo.recvarea)) {
                PRINT_ERR_HEAD
                print_err("filter cmd fail[%s]", pinfo.chcmd);
                return false;
            }
        }
        return doMethodLine(begin, end, pinfo, bvec);
    } else {
        BLOCK block;
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        return true;
    }
}

/**
 * [base::doReplaceIP 替换IP]
 * 最常见的：
 *     INVITE sip:33078200001320000004@10.73.192.204:5511 SIP/2.0
 *     BYE sip:32011501001320000155@172.18.13.192:5060 SIP/2.0
 * 特殊情况:
 *     INVITE sip:10002@192.168.2.100;transport=UDP SIP/2.0
 *     INVITE sip:32011501001320000155@172.18.13.192 SIP/2.0
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @param  repip [要替换之后的IP]
 * @return       [成功返回true]
 */
bool base::doReplaceIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                       vector<BLOCK> &bvec, const char *repip)
{
    BLOCK block;
    const char *p = strnchr(begin, end, '@');
    const char *q = NULL;
    if ((p != NULL) && (p < end)) {
        q = p + 1;
        while ((*q == '.') || isdigit(*q)) q++;
        if ((q > p + 1) && (q < end)) {
            bvec.push_back(makeBlock1(block, begin, p - begin + 1));
            bvec.push_back(makeBlock1(block, repip, strlen(repip)));
            bvec.push_back(makeBlock1(block, q, end - q + 1));
            return true;
        }
    }
    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    PRINT_INFO_HEAD
    print_info("replace ip fail[%s]", begin);
    //虽然没替换成功  但还是返回true  把数据包放过
    return true;
}

/**
 * [base::doReplaceIP 替换IP]
 * 例如： Contact: <sip:172.20.20.86:5061>\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @param  oriip [要被替换的IP]
 * @param  repip [要替换之后的IP]
 * @return       [成功返回true]
 */
bool base::doReplaceIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                       vector<BLOCK> &bvec, const char *oriip, const char *repip)
{
    BLOCK block;
    const char *p = strncasestr(begin, end, oriip);
    if (p != NULL) {
        bvec.push_back(makeBlock1(block, begin, p - begin));
        bvec.push_back(makeBlock1(block, repip, strlen(repip)));
        bvec.push_back(makeBlock1(block, p + strlen(oriip), end - (p + strlen(oriip)) + 1));
        return true;
    }
    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    PRINT_INFO_HEAD
    print_info("replace ip fail[%s]", begin);
    //虽然没替换成功  但还是返回true  把数据包放过
    return true;
}

/**
 * [base::doReplaceIPPort 替换IP端口]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @param  oriip [要被替换的IP]
 * @param  repip [要替换之后的IP]
 * @param  repport [要替换之后的端口]
 * @return         [成功返回true]
 */
bool base::doReplaceIPPort(const char *begin, const char *end, PACKET_INFO &pinfo,
                           vector<BLOCK> &bvec, const char *repip, const char *repport)
{
    BLOCK block;
    const char *p = strnchr(begin, end, '@');
    const char *q = NULL;
    const char *r = NULL;
    if ((p != NULL) && (p < end)) {
        q = p + 1;
        while ((*q == '.') || isdigit(*q)) q++;
        if ((q > p + 1) && (q < end) && (*q == ':')) {
            r = q + 1;
            while (isdigit(*r)) r++;
            if ((r > q + 1) && (r < end)) {
                bvec.push_back(makeBlock1(block, begin, p - begin + 1));
                bvec.push_back(makeBlock1(block, repip, strlen(repip)));
                bvec.push_back(makeBlock1(block, q, 1));
                bvec.push_back(makeBlock1(block, repport, strlen(repport)));
                bvec.push_back(makeBlock1(block, r, end - r + 1));
                return true;
            }
        }
    }
    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    PRINT_INFO_HEAD
    print_info("replace ip fail[%s]", begin);
    //虽然没替换成功  但还是返回true  把数据包放过
    return true;
}

/**
 * [base::doReplaceLength 替换Length]
 * 例如： Content-Length : 1114\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @param  bsub  [是否为子块]
 * @return       [成功返回true]
 */
bool base::doReplaceLength(const char *begin, const char *end, PACKET_INFO &pinfo,
                           vector<BLOCK> &bvec, bool bsub)
{
    BLOCK block;
    const char *p = begin;
    const char *q = NULL;
    while (p < end) {
        if (q == NULL) {
            if (isdigit(*p)) {
                q = p;
            }
        } else {
            if (!isdigit(*p)) {
                break;
            }
        }
        p++;
    }

    if (q == NULL) {
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
        PRINT_INFO_HEAD
        print_info("replace content-length fail[%s]", begin);
        //虽然没替换成功  但还是返回true  把数据包放过
    } else {
        bvec.push_back(makeBlock1(block, begin, q - begin));
        bvec.push_back(makeBlock1(block, q, p - q));
        if (bsub) {
            if ((!pinfo.subsdp) || (pinfo.sub_content_len_index == 0)) {
                pinfo.sub_content_len_index = bvec.size() - 1;
                PRINT_INFO_HEAD
                print_info("sub content_len_index %d", pinfo.sub_content_len_index);
            }
        } else {
            pinfo.content_len_index = bvec.size() - 1;
        }
        bvec.push_back(makeBlock1(block, p, end - p + 1));
    }
    return true;
}

/**
 * [base::doReplaceCallIDIP 替换CallID中的IP]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doReplaceCallIDIP(const char *begin, const char *end, PACKET_INFO &pinfo,
                             vector<BLOCK> &bvec)
{
    BLOCK block;
    const char *pat = strnchr(begin, end, '@');
    const char *repip = NULL;
    const char *oriip = NULL;
    if (pat != NULL) {
        if (pinfo.isresponse) {
            oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapinip : m_gapoutip;
            repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_outcenter : m_incenter;
        } else {
            oriip = (pinfo.recvarea == RECV_IN_CENTER) ? m_incenter : m_outcenter;
            repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;
        }
        return doReplaceIP(begin, end, pinfo, bvec, oriip, repip);
    } else {
        bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    }
    return false;
}

/**
 * [base::doReplaceO 替换O行]
 * 例如： o=B2BUA 1 1 IN IP4 10.72.4.95\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doReplaceO(const char *begin, const char *end, PACKET_INFO &pinfo,
                      vector<BLOCK> &bvec)
{
    BLOCK block;
    const char *p = NULL;
    const char *q = NULL;
    const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;

    p = strncasestr(begin, end, "IN IP4 ");
    if (p != NULL) {
        p += strlen("IN IP4 ");
        q = p;
        while ((*q == '.') || isdigit(*q)) q++;
        if ((q > p) && (q < end)) {
            bvec.push_back(makeBlock1(block, begin, p - begin));
            bvec.push_back(makeBlock1(block, repip, strlen(repip)));
            bvec.push_back(makeBlock1(block, q, end - q + 1));
            pinfo.content_len_change += strlen(repip) - (q - p);
            if (pinfo.multipart && pinfo.subsdp && (pinfo.sub_content_len_index > 0)) {
                pinfo.sub_content_len_change += strlen(repip) - (q - p);
            }
            return true;
        }
    }

    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    PRINT_INFO_HEAD
    print_info("replace o ip fail[%s]", begin);
    //虽然没替换成功  但还是返回true  把数据包放过
    return true;
}

/**
 * [base::doReplaceC 替换C行]
 * 例如： c=IN IP4 10.72.4.95\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doReplaceC(const char *begin, const char *end, PACKET_INFO &pinfo,
                      vector<BLOCK> &bvec)
{
    BLOCK block;
    const char *p = NULL;
    const char *q = NULL;
    const char *repip = (pinfo.recvarea == RECV_IN_CENTER) ? m_gapoutip : m_gapinip;

    p = strncasestr(begin, end, "IN IP4 ");
    if (p != NULL) {
        p += strlen("IN IP4 ");
        q = p;
        while ((*q == '.') || isdigit(*q)) q++;
        if ((q > p) && (q < end) && (q - p < sizeof(pinfo.msip))) {
            bvec.push_back(makeBlock1(block, begin, p - begin));
            bvec.push_back(makeBlock1(block, repip, strlen(repip)));
            bvec.push_back(makeBlock1(block, q, end - q + 1));
            memcpy(pinfo.msip, p, q - p);
            pinfo.content_len_change += strlen(repip) - (q - p);
            if (pinfo.multipart && pinfo.subsdp && (pinfo.sub_content_len_index > 0)) {
                pinfo.sub_content_len_change += strlen(repip) - (q - p);
            }
            PRINT_INFO_HEAD
            print_info("get msip ok[%s]", pinfo.msip);
            return true;
        }
    }

    bvec.push_back(makeBlock1(block, begin, end - begin + 1));
    PRINT_INFO_HEAD
    print_info("replace c ip fail[%s]", begin);
    //虽然没替换成功  但还是返回true  把数据包放过
    return true;
}

/**
 * [base::doReplaceAudio 替换处理audio行]
 * 例如：m=audio 28144 RTP/AVP 126 0 8\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doReplaceAudio(const char *begin, const char *end, PACKET_INFO &pinfo,
                          vector<BLOCK> &bvec)
{
    pinfo.atcp = (strncasestr(begin, end, "TCP") != NULL);
    PRINT_DBG_HEAD
    print_dbg("audio stream type is[%s]", pinfo.atcp ? "TCP" : "UDP");
    return doReplacePort(begin, end, pinfo, bvec, true);
}

/**
 * [base::doReplaceVideo 替换处理video行]
 * 例如：m=video 28148 RTP/AVP 126 0 8\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @return       [成功返回true]
 */
bool base::doReplaceVideo(const char *begin, const char *end, PACKET_INFO &pinfo,
                          vector<BLOCK> &bvec)
{
    pinfo.vtcp = (strncasestr(begin, end, "TCP") != NULL);
    PRINT_DBG_HEAD
    print_dbg("video stream type is[%s]", pinfo.vtcp ? "TCP" : "UDP");
    return doReplacePort(begin, end, pinfo, bvec, false);
}

/**
 * [base::doReplacePort 替换动态端口]
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @param  bvec  [vector]
 * @param  baudio[是否为audio]
 * @return       [成功返回true]
 */
bool base::doReplacePort(const char *begin, const char *end, PACKET_INFO &pinfo,
                         vector<BLOCK> &bvec, bool baudio)
{
    PRINT_INFO_HEAD
    print_info("replace port begin");

    BLOCK block;
    const char *p = begin + (baudio ? strlen("m=audio ") : strlen("m=video "));
    const char *q = p;
    char proxyport[PORT_STR_LEN] = {0};

    while (isdigit(*q)) q++;
    if (q > p) {
        bvec.push_back(makeBlock1(block, begin, p - begin));
        memcpy(baudio ? pinfo.aport : pinfo.vport, p, q - p);
        if (!getProxyPort(proxyport, pinfo, baudio)) {
            PRINT_ERR_HEAD
            print_err("get proxy port fail[%s]", begin);
            goto _out;
        }
        bvec.push_back(makeBlock2(block, proxyport, strlen(proxyport)));
        bvec.push_back(makeBlock1(block, q, end - q + 1));
        pinfo.content_len_change += strlen(proxyport) - (q - p);
        if (pinfo.multipart && pinfo.subsdp && (pinfo.sub_content_len_index > 0)) {
            PRINT_INFO_HEAD
            print_info("replace port sublen change %d", strlen(proxyport) - (q - p));
            pinfo.sub_content_len_change += strlen(proxyport) - (q - p);
        }
        PRINT_INFO_HEAD
        print_info("replace port over. proxyport[%s].len change[%d]", proxyport, strlen(proxyport) - (q - p));
        return true;
    }
_out:
    PRINT_ERR_HEAD
    print_err("replace port error[%s]", begin);
    return false;
}

/**
 * [base::lockChannel 通道加锁]
 */
void base::lockChannel(void)
{
    sem_wait(&m_channellock);
}

/**
 * [base::unlockChannel 通道解锁]
 */
void base::unlockChannel(void)
{
    sem_post(&m_channellock);
}

/**
 * [base::getProxyPort 获取代理端口]
 * @param  proxyport [代理端口 出参]
 * @param  pinfo     [PACKET_INFO]
 * @param  baudio    [是否为audio]
 * @return           [成功返回true]
 */
bool base::getProxyPort(char *proxyport, PACKET_INFO &pinfo, bool baudio)
{
    int channelid = getChannelID(pinfo, baudio);
    if (channelid >= 0) {
        if (baudio) {
            sprintf(proxyport, "%d", PROXY_AUDIO_RTP_PORT(m_pchannel[channelid].proxyport));
        } else {
            sprintf(proxyport, "%d", PROXY_VIDEO_RTP_PORT(m_pchannel[channelid].proxyport));
        }
        PRINT_DBG_HEAD
        print_dbg("channelid[%d] proxyport is[%s]", channelid, proxyport);
    } else {
        PRINT_ERR_HEAD
        print_err("get channel id fail");
        return false;
    }
    return true;
}

/**
 * [base::getChannelID 获取通道]
 * @param  pinfo     [PACKET_INFO]
 * @param  baudio    [是否为audio]
 * @return           [返回下标]
 */
int base::getChannelID(PACKET_INFO &pinfo, bool baudio)
{
    if (pinfo.isresponse) {
        return getChannelIDResponse(pinfo, baudio);
    } else {
        return getChannelIDRequest(pinfo, baudio);
    }
}

/**
 * [base::getChannelIDRequest 获取通道下标 当前为请求信息]
 * @param  pinfo     [PACKET_INFO]
 * @param  baudio    [是否为audio]
 * @return           [返回下标 失败返回负值]
 */
int base::getChannelIDRequest(PACKET_INFO &pinfo, bool baudio)
{
    int earliest = 0;
    int idx = 0;

    lockChannel();
    int ret = getChannelIDRequestExist(pinfo, baudio);
    if ((ret >= 0) || (ret == -2)) {
        PRINT_DBG_HEAD
        print_dbg("get channel id request exist ret %d", ret);
        goto _out;
    }

    for (int i = 0; i < m_max_channel; ++i) {
        idx = (m_lastid + 1 + i) % m_max_channel;
        if (!m_pchannel[idx].enable) {
            continue;
        }
        if (m_pchannel[idx].callid[0] == 0) {
            if (time(NULL) - m_pchannel[idx].activetime > CHANNEL_TIME_OUT_SECOND) {
                fillChannel(pinfo, baudio, idx);
                ret = m_lastid = idx;
                PRINT_DBG_HEAD
                print_dbg("get empty channel[%d][%s]", idx, m_pchannel[idx].callid);
                goto _out;
            }
        } else {
            if (m_pchannel[idx].activetime < m_pchannel[earliest].activetime) {
                earliest = idx;
            }
        }
    }
    PRINT_INFO_HEAD
    print_info("reuse channel[%d]", earliest);
    delChannel(earliest);
    fillChannel(pinfo, baudio, earliest);
    ret = earliest;
_out:
    unlockChannel();
    return ret;
}

/**
 * [base::delChannel 根据CallID删除通道]
 * @param callid [CallID]
 */
void base::delChannel(const char *callid)
{
    if ((callid == NULL) || (callid[0] == 0)) {
        PRINT_ERR_HEAD
        print_err("callid null[%s]", callid);
        return;
    }

    for (int i = 0; i < m_max_channel; ++i) {
        if (m_pchannel[i].enable && (strcmp(callid, m_pchannel[i].callid) == 0)) {
            delChannel(i);
            break;
        }
    }
}

/**
 * [base::delChannel 根据ID删除一个通道]
 * @param id [通道下标ID]
 */
void base::delChannel(int id)
{
    operChannelAudio(id, false);
    operChannelVideo(id, false);
    clearChannel(id);
}

/**
 * [base::channelUDP 需要打开UDP流媒体通道]
 * @param  flag [自动识别出的流媒体传输类型 true表示TCP]
 * @return      [需要打开返回true]
 */
bool base::channelUDP(bool flag)
{
    bool ret = true;
    switch (m_stream_type) {
    case STREAM_TYPE_AUTO:
        ret = !flag;
        break;
    case STREAM_TYPE_UDP:
        break;
    case STREAM_TYPE_TCP:
        ret = false;
        break;
    case STREAM_TYPE_UDPTCP:
        break;
    default:
        ret = !flag;
        PRINT_ERR_HEAD
        print_err("unknown stream type[%d]", m_stream_type);
        break;
    }
    return ret;
}

/**
 * [base::channelTCP 需要打开TCP流媒体通道]
 * @param  flag [自动识别出的流媒体传输类型 true表示TCP]
 * @return      [需要打开返回true]
 */
bool base::channelTCP(bool flag)
{
    bool ret = true;
    switch (m_stream_type) {
    case STREAM_TYPE_AUTO:
        ret = flag;
        break;
    case STREAM_TYPE_UDP:
        ret = false;
        break;
    case STREAM_TYPE_TCP:
        break;
    case STREAM_TYPE_UDPTCP:
        break;
    default:
        ret = flag;
        PRINT_ERR_HEAD
        print_err("unknown stream type[%d]", m_stream_type);
        break;
    }
    return ret;
}

/**
 * [base::operChannelAudio 操作audio通道]
 * @param id  [通道下标ID]
 * @param add [true表示添加 false表示删除]
 */
void base::operChannelAudio(int id, bool add)
{
    if ((m_pchannel[id].inmsip[0] != 0) && (m_pchannel[id].outmsip[0] != 0)) {
        if ((m_pchannel[id].in_aport[0] != 0) && (m_pchannel[id].out_aport[0] != 0)) {

            PRINT_DBG_HEAD
            print_dbg("oper channel audio begin.%s [%s][%s][%s][%s][%d]",
                      add ? "add" : "del",
                      m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                      m_pchannel[id].in_aport, m_pchannel[id].out_aport,
                      PROXY_AUDIO_RTP_PORT(m_pchannel[id].proxyport));

            if (channelUDP(m_pchannel[id].atcp)) {
                operChannel(m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                            m_pchannel[id].in_aport, m_pchannel[id].out_aport,
                            PROXY_AUDIO_RTP_PORT(m_pchannel[id].proxyport), add, "udp");
            }

            if (channelTCP(m_pchannel[id].atcp)) {
                operChannel(m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                            m_pchannel[id].in_aport, m_pchannel[id].out_aport,
                            PROXY_AUDIO_RTP_PORT(m_pchannel[id].proxyport), add, "tcp");
            }
        }
    }
}

/**
 * [base::operChannelVideo 操作video通道]
 * @param id  [通道下标ID]
 * @param add [true表示添加 false表示删除]
 */
void base::operChannelVideo(int id, bool add)
{
    if ((m_pchannel[id].inmsip[0] != 0) && (m_pchannel[id].outmsip[0] != 0)) {
        if ((m_pchannel[id].in_vport[0] != 0) && (m_pchannel[id].out_vport[0] != 0)) {

            PRINT_DBG_HEAD
            print_dbg("oper channel video begin.%s [%s][%s][%s][%s][%d]",
                      add ? "add" : "del",
                      m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                      m_pchannel[id].in_vport, m_pchannel[id].out_vport,
                      PROXY_VIDEO_RTP_PORT(m_pchannel[id].proxyport));

            if (channelUDP(m_pchannel[id].vtcp)) {
                operChannel(m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                            m_pchannel[id].in_vport, m_pchannel[id].out_vport,
                            PROXY_VIDEO_RTP_PORT(m_pchannel[id].proxyport), add, "udp");
            }
            if (channelTCP(m_pchannel[id].vtcp)) {
                operChannel(m_pchannel[id].inmsip, m_pchannel[id].outmsip,
                            m_pchannel[id].in_vport, m_pchannel[id].out_vport,
                            PROXY_VIDEO_RTP_PORT(m_pchannel[id].proxyport), add, "tcp");
            }
        }
    }
}

/**
 * [base::clearChannel 清空一个通道中的变量]
 * @param id [通道下标ID]
 */
void base::clearChannel(int id)
{
    BZERO(m_pchannel[id].callid);
    BZERO(m_pchannel[id].inmsip);
    BZERO(m_pchannel[id].outmsip);
    BZERO(m_pchannel[id].in_vport);
    BZERO(m_pchannel[id].out_vport);
    BZERO(m_pchannel[id].in_aport);
    BZERO(m_pchannel[id].out_aport);
    m_pchannel[id].vtcp = false;
    m_pchannel[id].atcp = false;
    m_pchannel[id].activetime = time(NULL);
}

/**
 * [base::fillChannel 把信息填充到通道中]
 * @param pinfo  [PACKET_INFO]
 * @param baudio [是否为audioi]
 * @param id     [通道下标ID]
 */
void base::fillChannel(PACKET_INFO &pinfo, bool baudio, int id)
{
    char *msip = (pinfo.recvarea == RECV_IN_CENTER) ?
                 m_pchannel[id].inmsip : m_pchannel[id].outmsip;
    char *aport = (pinfo.recvarea == RECV_IN_CENTER) ?
                  m_pchannel[id].in_aport : m_pchannel[id].out_aport;
    char *vport = (pinfo.recvarea == RECV_IN_CENTER) ?
                  m_pchannel[id].in_vport : m_pchannel[id].out_vport;
    char *port = baudio ? aport : vport;
    char *pport = baudio ? pinfo.aport : pinfo.vport;

    strcpy(m_pchannel[id].callid, pinfo.callid);
    strcpy(msip, pinfo.msip);
    strcpy(port, pport);
    if (baudio) {
        m_pchannel[id].atcp = pinfo.atcp;
    } else {
        m_pchannel[id].vtcp = pinfo.vtcp;
    }
    m_pchannel[id].activetime = time(NULL);
}

/**
 * [base::operChannel 操作通道iptables]
 * @param inmsip    [内网手台]
 * @param outmsip   [外网手台]
 * @param inport    [内网手台端口]
 * @param outport   [外网手台端口]
 * @param proxyport [代理端口]
 * @param add       [true表示添加 false表示删除]
 * @param proto     [协议]
 */
void base::operChannel(const char *inmsip, const char *outmsip, const char *inport, const char *outport,
                       int proxyport, bool add, const char *proto)
{
    char oper = add ? 'I' : 'D';
    char chcmd[CMD_BUF_LEN] = {0};

    sem_wait(g_iptables_lock);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s -p %s --sport %d --dport %d -j SNAT --to %s:%d",
            IPTABLES, oper, m_inneroutip, inmsip, proto, atoi(outport), atoi(inport), m_gapinip, proxyport);
    systemCmd(chcmd, SELF_SIDE);
    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s -p %s --sport %d --dport %d -j SNAT --to %s:%d",
            IPTABLES, oper, m_inneroutip, inmsip, proto, atoi(outport) + 1, atoi(inport) + 1, m_gapinip, proxyport + 1);
    systemCmd(chcmd, SELF_SIDE);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s",
            IPTABLES, oper, inmsip, m_gapinip, proto, atoi(inport), proxyport, m_inneroutip);
    systemCmd(chcmd, SELF_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s",
            IPTABLES, oper, inmsip, m_gapinip, proto, atoi(inport) + 1, proxyport + 1, m_inneroutip);
    systemCmd(chcmd, SELF_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s:%d",
            IPTABLES, oper, m_inneroutip, m_innerinip, proto, atoi(outport), proxyport, inmsip, atoi(inport));
    systemCmd(chcmd, SELF_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s:%d",
            IPTABLES, oper, m_inneroutip, m_innerinip, proto, atoi(outport) + 1, proxyport + 1, inmsip, atoi(inport) + 1);
    systemCmd(chcmd, SELF_SIDE);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s -p %s --sport %d --dport %d -j SNAT --to %s:%d",
            IPTABLES, oper, m_innerinip, outmsip, proto, atoi(inport), atoi(outport), m_gapoutip, proxyport);
    systemCmd(chcmd, PEER_SIDE);
    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s -p %s --sport %d --dport %d -j SNAT --to %s:%d",
            IPTABLES, oper, m_innerinip, outmsip, proto, atoi(inport) + 1, atoi(outport) + 1, m_gapoutip, proxyport + 1);
    systemCmd(chcmd, PEER_SIDE);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s",
            IPTABLES, oper, outmsip, m_gapoutip, proto, atoi(outport), proxyport, m_innerinip);
    systemCmd(chcmd, PEER_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s",
            IPTABLES, oper, outmsip, m_gapoutip, proto, atoi(outport) + 1, proxyport + 1, m_innerinip);
    systemCmd(chcmd, PEER_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s:%d",
            IPTABLES, oper, m_innerinip, m_inneroutip, proto, atoi(inport), proxyport, outmsip, atoi(outport));
    systemCmd(chcmd, PEER_SIDE);
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p %s --sport %d --dport %d -j DNAT --to %s:%d",
            IPTABLES, oper, m_innerinip, m_inneroutip, proto, atoi(inport) + 1, proxyport + 1, outmsip, atoi(outport) + 1);
    systemCmd(chcmd, PEER_SIDE);

    sem_post(g_iptables_lock);
    if (add && (m_clean_track == 1)) {
        systemCmd(CLEAN_TRACK_FILE, SELF_SIDE);
        systemCmd(CLEAN_TRACK_FILE, PEER_SIDE);
        PRINT_DBG_HEAD
        print_dbg("call clean track[%s]", CLEAN_TRACK_FILE);
    }
}

/**
 * [base::getChannelIDRequestExist 获取(存在情况下的)通道下标 当前为请求信息]
 * @param  pinfo     [PACKET_INFO]
 * @param  baudio    [是否为audio]
 * @return           [成功返回下标 没找到返回-1 严重错误返回-2]
 */
int base::getChannelIDRequestExist(PACKET_INFO &pinfo, bool baudio)
{
    int ret = -1;
    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (strcmp(pinfo.callid, m_pchannel[i].callid) == 0)) {
            char *msip = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].inmsip : m_pchannel[i].outmsip;
            char *aport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].in_aport : m_pchannel[i].out_aport;
            char *vport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].in_vport : m_pchannel[i].out_vport;
            char *port = baudio ? aport : vport;
            char *pport = baudio ? pinfo.aport : pinfo.vport;
            if (strcmp(pinfo.msip, msip) == 0) {
                if ((port[0] == 0) || (strcmp(port, pport) == 0)) {
                    strcpy(port, pport);
                    ret = i;
                } else {
                    PRINT_ERR_HEAD
                    print_err("find conflict port[%s] pport[%s].callid[%s]msip[%s]",
                              port, pport, pinfo.callid, msip);
                    ret = -2;
                }
            } else {
                PRINT_ERR_HEAD
                print_err("find conflict callid[%s] used in diff msip.[%s][%s]", pinfo.callid, pinfo.msip, msip);
                ret = -2;
            }
            goto _out;
        }
    }
_out:
    return ret;
}

/**
 * [base::getChannelIDResponse 获取通道ID 响应信息]
 * @param  pinfo     [PACKET_INFO]
 * @param  baudio    [是否为audio]
 * @return           [成功返回下标]
 */
int base::getChannelIDResponse(PACKET_INFO &pinfo, bool baudio)
{
    if (pinfo.callid[0] == 0) {
        PRINT_ERR_HEAD
        print_err("pinfo callid null[%s]", pinfo.callid);
        return -1;
    }
    int ret = -1;

    lockChannel();
    for (int i = 0; i < m_max_channel; ++i) {
        if (m_pchannel[i].enable && (strcmp(pinfo.callid, m_pchannel[i].callid) == 0)) {
            char *msip = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].inmsip : m_pchannel[i].outmsip;
            char *aport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].in_aport : m_pchannel[i].out_aport;
            char *vport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].in_vport : m_pchannel[i].out_vport;
            char *port = baudio ? aport : vport;

            char *peermsip = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].outmsip : m_pchannel[i].inmsip;
            char *peeraport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].out_aport : m_pchannel[i].in_aport;
            char *peervport = (pinfo.recvarea == RECV_IN_CENTER) ? m_pchannel[i].out_vport : m_pchannel[i].in_vport;
            char *peerport = baudio ? peeraport : peervport;

            char *pport = baudio ? pinfo.aport : pinfo.vport;
            if ((peermsip[0] == 0) || (peerport[0] == 0)) {
                PRINT_ERR_HEAD
                print_err("response come[%s:%s:%s] while request missing[%s][%s]",
                          pinfo.callid, pinfo.msip, pport, peermsip, peerport);
                break;
            }

            if ((msip[0] == 0) || ((strcmp(msip, pinfo.msip) == 0) && (port[0] == 0))) {
                if (baudio) {
                    strcpy(msip, pinfo.msip);
                    strcpy(port, pport);
                    m_pchannel[i].activetime = time(NULL);
                    operChannelAudio(i, true);
                } else if (pinfo.retcode == 200) { //对于video 只有返回码为200时才开通道
                    strcpy(msip, pinfo.msip);
                    strcpy(port, pport);
                    m_pchannel[i].activetime = time(NULL);
                    operChannelVideo(i, true);
                } else {
                    PRINT_INFO_HEAD
                    print_info("retcode is [%d], suspend open video channel. chanid[%d] proxyport[%d]",
                               pinfo.retcode, i, PROXY_VIDEO_RTP_PORT(m_pchannel[i].proxyport));
                }
                ret = i;
                break;
            }

            if (strcmp(msip, pinfo.msip) != 0) {
                PRINT_ERR_HEAD
                print_err("msip[%s] pinfo.msip[%s] diff", msip, pinfo.msip);
                break;
            }

            if (strcmp(port, pport) == 0) {
                ret = i;
                break;
            }
            PRINT_ERR_HEAD
            print_err("find conflict port[%s][%s] callid[%s] chanid[%d]", port, pport, pinfo.callid, i);
            break;
        }
    }
    unlockChannel();
    return ret;
}

/**
 * [base::makeBlock1 组装BLOCK 静态]
 * @param  block [BLOCK引用]
 * @param  begin [开始位置]
 * @param  len   [长度]
 * @return       [BLOCK引用]
 */
BLOCK &base::makeBlock1(BLOCK &block, const char *begin, int len)
{
    if ((begin == NULL) || (len < 0)) {
        PRINT_ERR_HEAD
        print_err("para error[%d][%s]", len, begin);
    } else {
        block.begin = begin;
        block.len = len;
        block.bmalloc = false;
        PRINT_DBG_HEAD
        print_dbg("len %d", block.len);
    }
    return block;
}

/**
 * [base::makeBlock2 组装BLOCK 动态]
 * @param  block [BLOCK引用]
 * @param  begin [开始位置]
 * @param  len   [长度]
 * @return       [BLOCK引用]
 */
BLOCK &base::makeBlock2(BLOCK &block, const char *begin, int len)
{
    if ((begin == NULL) || (len < 0)) {
        PRINT_ERR_HEAD
        print_err("para error[%d][%s]", len, begin);
    } else {
        while ((block.nbegin = (char *)malloc(len)) == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc fail[%d][%s],retry", len, strerror(errno));
            sleep(1);
        }
        memcpy(block.nbegin, begin, len);
        block.nlen = len;
        block.bmalloc = true;
        PRINT_DBG_HEAD
        print_dbg("malloc len %d", block.nlen);
    }
    return block;
}

/**
 * [base::getCallID 从一行内容中获取callid值]
 * 例如：
 *     Call-ID: fbe361a21ed6b2f3609edf776583eac9@10.54.201.203\r\n
 * @param  line      [一行内容]
 * @param  callidbuf [存放callid值的buf]
 * @param  buflen    [buf长度]
 * @return           [成功返回true]
 */
bool base::getCallID(const char *line, char *callidbuf, int buflen)
{
    int i = 0, j = 0;
    if ((line != NULL) && (callidbuf != NULL) && (buflen > 0)) {
        while ((line[i] != '\0') && (line[i] != '\r') && (j < buflen) && (line[i] != '@')) {
            if (line[i] == ' ' || line[i] == ':') {
                i++;
            } else {
                callidbuf[j++] = line[i++];
            }
        }
    }

    return (j > 0);
}

/**
 * [base::parserContentType 解析内容类型到结构体中]
 * 例如：Content-Type: multipart/mixed; boundary="btrunc_boundary"\r\n
 *      Content-Type: application/sdp\r\n
 * @param  begin [开始]
 * @param  end   [结束]
 * @param  pinfo [PACKET_INFO]
 * @return       [成功返回true]
 */
bool base::parserContentType(const char *begin, const char *end, PACKET_INFO &pinfo)
{
    const char *q = NULL;
    const char *p = strncasestr(begin, end, "boundary=");
    if (p != NULL) {
        p += strlen("boundary=");
        if (*p == '"') p++;
        q = p;
        while ((*q != '"') && (*q != '\r') && (*q != '\n') && (q < end)) q++;
        if (q - p < (int)sizeof(pinfo.boundary)) {
            memcpy(pinfo.boundary, p, q - p);
            PRINT_INFO_HEAD
            print_info("boundary is [%s]", pinfo.boundary);
            pinfo.multipart = true;
        } else {
            PRINT_ERR_HEAD
            print_err("boundary too long[%d] max support %d", q - p, sizeof(pinfo.boundary) - 1);
            return false;
        }
    }
    return true;
}

/**
 * [UDPThread 处理UDP传输SIP的线程函数]
 * @param  para [任务指针]
 * @return      [正常情况下不会退出，异常时返回NULL]
 */
void *UDPThread(void *para)
{
    pthread_setself("udpthread");

    PRINT_INFO_HEAD
    print_info("udp thread begin");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    char buff1[MAX_PACKET];
    char buff2[MAX_PACKET];
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;
    PBTASK ptask = (PBTASK)para;
    int recvsock = ptask->recvsock;
    int sendsock = ptask->sendsock;
    int recvarea = ptask->recvarea;
    base *psip = ptask->psip;
    DELETE(ptask);

    sockaddr_in to_addr;
    BZERO(to_addr);
    to_addr.sin_family = AF_INET;
    if (recvarea == RECV_IN_CENTER) {
        to_addr.sin_addr.s_addr = inet_addr(psip->m_inneroutip);
        to_addr.sin_port = htons(atoi(psip->m_outport));
    } else if (recvarea == RECV_OUT_CENTER) {
        to_addr.sin_addr.s_addr = inet_addr(psip->m_incenter);
        to_addr.sin_port = htons(atoi(psip->m_inport));
    } else {
        PRINT_ERR_HEAD
        print_err("recvarea error[%d]", recvarea);
        close(sendsock);
        close(recvsock);
        return NULL;
    }

    while (1) {
        BZERO(buff1);
        BZERO(buff2);
        recvlen = recvfrom(recvsock, buff1, sizeof(buff1), 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s] recvlen[%d] recvarea[%d]",
                      strerror(errno), recvlen, recvarea);
            usleep(1000);
        } else {
            replen = psip->processData(buff1, recvlen, buff2, recvarea);
            if (replen > 0) {
                sendlen = sendto(sendsock, buff2, replen, 0,
                                 (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
                if (sendlen <= 0) {
                    PRINT_ERR_HEAD
                    print_err("sendto error[%s][%d] recvarea[%d]",
                              strerror(errno), sendlen, recvarea);
                } else {
                    PRINT_DBG_HEAD
                    print_dbg("send[%d] %s", sendlen,
                              (recvarea == RECV_IN_CENTER) ? "to outcenter" : "to incenter");
                }
            } else {
                PRINT_ERR_HEAD
                print_err("process data error[%d] recvarea[%d]", replen, recvarea);
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("should never get here recvarea[%d]", recvarea);
    close(sendsock);
    close(recvsock);
    return NULL;
}

/**
 * [TCPThread 处理TCP传输SIP的线程函数]
 * @param  para [任务指针]
 * @return      [正常情况下不会退出，异常时返回NULL]
 */
void *TCPThread(void *para)
{
    pthread_setself("tcpthread");

    PRINT_INFO_HEAD
    print_info("tcp thread begin");
    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int mysock1 = 0, mysock2 = 0;
    int threadid = -1;
    CBSTcpSockServer ser;
    PBTASK ptask = (PBTASK)para;
    int recvarea = ptask->recvarea;
    base *psip = ptask->psip;
    DELETE(ptask);

    char *lsip = (recvarea == LISTEN_IN_CENTER) ? psip->m_gapinip : psip->m_innerinip;
    char *lsport = (recvarea == LISTEN_IN_CENTER) ? psip->m_outport : psip->m_inport;
    char *cnip = (recvarea == LISTEN_IN_CENTER) ? psip->m_inneroutip : psip->m_incenter;
    char *cnport = (recvarea == LISTEN_IN_CENTER) ? psip->m_outport : psip->m_inport;

    while (ser.Open(lsip, atoi(lsport)) < 0) {
        PRINT_ERR_HEAD
        print_err("listen[%s][%s] fail retry", lsip, lsport);
        sleep(1);
    }
    PRINT_INFO_HEAD
    print_info("listen[%s][%s] ok", lsip, lsport);

    while (1) {
        mysock1 = ser.StartServer();
        if (mysock1 < 0) {
            PRINT_ERR_HEAD
            print_err("accept error[%s]", strerror(errno));
            continue;
        }
        threadid = psip->getTCPThreadID();
        if (threadid == -1) {
            PRINT_ERR_HEAD
            print_err("link num has reached the maximum[%d] close it", MAX_THREAD);
            close(mysock1);
            continue;
        }
        PRINT_DBG_HEAD
        print_dbg("tcp thread id[%d] accept sock[%d]", threadid, mysock1);

        mysock2 = psip->m_tcpcli[threadid].Open(cnip, atoi(cnport));
        if (mysock2 <= 0) {
            PRINT_ERR_HEAD
            print_err("connect err.[%s][%s]", cnip, cnport);
            close(mysock1);
            psip->m_tcpstate[threadid] = STATUS_FREE;
            continue;
        }
        if (mysock1 == mysock2) {
            PRINT_ERR_HEAD
            print_err("mysock1 == mysock2[%d] threadid[%d]", mysock1, threadid);
        }

        PBTASK ptask1 = NULL;
        ptask1 = new BTASK();
        if (ptask1 == NULL) {
            PRINT_ERR_HEAD
            print_err("new task error");
            close(mysock1);
            close(mysock2);
            DELETE(ptask1);
            psip->m_tcpstate[threadid] = STATUS_FREE;
            continue;
        }
        ptask1->recvsock = mysock1;
        ptask1->sendsock = mysock2;
        ptask1->threadid = threadid;
        ptask1->psip = psip;
        ptask1->recvarea = recvarea;

        if (!psip->createThread(TCPThread_RS, ptask1)) {
            close(mysock1);
            close(mysock2);
            DELETE(ptask1);
            psip->m_tcpstate[threadid] = STATUS_FREE;
            continue;
        }
        usleep(1000);
    }

    PRINT_ERR_HEAD
    print_err("should never get here recvarea[%d]", recvarea);
    return NULL;
}

/**
 * [base::doRecv 接收处理TCP SIP数据]
 * @param  sock1 [描述符1]
 * @param  sock2 [描述符2]
 * @param  area  [接收自哪个交换中心]
 * @return       [成功返回true]
 */
bool base::doRecv(int sock1, int sock2, int area)
{
    char buff1[MAX_PACKET];
    char buff2[MAX_PACKET];
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;

    recvlen = recv(sock1, buff1, sizeof(buff1) - SIP_PKT_LEN_CHANGE, 0);
    if (recvlen <= 0) {
        PRINT_INFO_HEAD
        print_info("recv fail[%s][%d],may close!", strerror(errno), recvlen);
        return false;
    }

    replen = processData(buff1, recvlen, buff2, area);
    if (replen > 0) {
        sendlen = send(sock2, buff2, replen, 0);
        if (sendlen <= 0) {
            PRINT_INFO_HEAD
            print_info("send fail[%s][%d]", strerror(errno), sendlen);
            return false;
        }
        PRINT_DBG_HEAD
        print_dbg("send[%d]", sendlen);
    } else {
        PRINT_ERR_HEAD
        print_err("replace error[%d]", replen);
        return false;
    }
    return true;
}

/**
 * [TCPThread_RS TCP接收和发送线程函数]
 * @param  para [任务指针]
 * @return      [未使用]
 */
void *TCPThread_RS(void *para)
{
    pthread_setself("tcpthread_rs");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    PBTASK task = (PBTASK)para;
    int recvsock = task->recvsock;
    int sendsock = task->sendsock;
    int threadid = task->threadid;
    int recvarea = task->recvarea;
    base *psip = task->psip;
    DELETE(task);
    int maxfd = 0;
    int ret = 0;
    fd_set fds;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(recvsock, &fds);
        FD_SET(sendsock, &fds);
        maxfd = MAX(recvsock, sendsock);

        ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (ret == 0) {
            //timeout
            continue;
        } else if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("select fail(%s) ret[%d]", strerror(errno), ret);
            break;
        }

        if (FD_ISSET(recvsock, &fds)) {
            if (!psip->doRecv(recvsock, sendsock, (recvarea == LISTEN_IN_CENTER) ? RECV_IN_CENTER : RECV_OUT_CENTER)) {
                PRINT_INFO_HEAD
                print_info("sock[%d] do recv ret false", recvsock);
                break;
            }
        }

        if (FD_ISSET(sendsock, &fds)) {
            if (!psip->doRecv(sendsock, recvsock, (recvarea == LISTEN_IN_CENTER) ? RECV_OUT_CENTER : RECV_IN_CENTER)) {
                PRINT_INFO_HEAD
                print_info("sock[%d] do recv ret false", sendsock);
                break;
            }
        }
    }
    psip->releaseTCPThread(threadid, sendsock, recvsock);
    PRINT_DBG_HEAD
    print_dbg("threadid[%d] exit", threadid);

    return NULL;
}

/**
 * [strnchr 在限定的范围内查找字符]
 * @param  begin [开始位置]
 * @param  end   [结束位置 闭区间]
 * @param  c     [字符]
 * @return       [成功返回指针 失败返回NULL]
 */
const char *strnchr(const char *begin, const char *end, char c)
{
    const char *p = begin;
    if ((begin != NULL) && (end != NULL)) {
        for (p = begin; p <= end; p++) {
            if (*p == c) {
                return p;
            }
        }
    }
    return NULL;
}

/**
 * [strncasestr 在限定范围内查找子串]
 * @param  begin [开始位置]
 * @param  end   [结束位置 闭区间]
 * @param  str   [待查字符串]
 * @return       [成功返回指针 失败返回NULL]
 */
const char *strncasestr(const char *begin, const char *end, const char *str)
{
    const char *p = begin;
    if ((begin != NULL) && (end != NULL) && (str != NULL)) {
        int slen = strlen(str);
        if (slen == 0) {
            PRINT_INFO_HEAD
            print_info("str len is 0");
            return NULL;
        }
        for (p = begin; p <= end + 1 - slen; p++) {
            if (strncasecmp(p, str, slen) == 0) {
                return p;
            }
        }
    }
    return NULL;
}
