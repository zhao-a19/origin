/*******************************************************************************************
*文件: FCClientSipNorm.cpp
*描述: 视频代理
*作者: 王君雷
*日期: 2018-04-12
*修改:
*         编码，通过多态，支持视频代理、视频代理联动                    ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*         修改m_maxchannel赋值位置错误,对于靠近下级平台的一侧不会调用
*         initChannel，就没有赋值的机会了                               ------>   2018-07-24
*         MY_BZERO、MY_DELETE等宏改名,去掉前面的MY_                     ------>   2018-08-05
*         执行iptables时加锁                                            ------>   2018-11-16
*         解决视频中断网重连后无法获取视频问题                          ------>   2019-07-04 -dzj
*         解决SIP发bye时iptables不清除的问题，添加回退开关              ------>   2019-07-24 -dzj
*         优化通道分配逻辑，记录最后一次分配的通道号，下次分配时从此处往后使用，从而尽量避免
*         短时间内复用刚刚回收的通道                                    ------> 2020-08-12 -wjl
*         媒体流动态通道iptables添加后清理可能存在的链接追踪            ------> 2021-04-01 LL
*******************************************************************************************/
#include "FCClientSipNorm.h"
#include "debugout.h"
#include <semaphore.h>

extern sem_t *g_iptables_lock;

#define CLI_SIP_STREAM_USE_TCP

CClientSipNorm::CClientSipNorm(int i): CClientSipBase(i)
{
    m_maxchannel = ARRAY_SIZE(m_channel);
    m_lastid = -1;
}

CClientSipNorm::~CClientSipNorm()
{

}

/**
 * [CClientSipNorm::initChannel 通道初始化]
 */
void CClientSipNorm::initChannel()
{
    BZERO(m_channel);
    for (int i = 0; i < m_maxchannel; i++) {
        sprintf(m_channel[i].myport, "%d", CLI_SIP_NORM_STARTMPORT + i * 2);
        m_channel[i].able = true;
    }
}

/**
 * [CClientSipNorm::getOneChannelID 获取一个可用的通道下标ID号]
 * @param  mrecvip   [媒体流接收者IP]
 * @param  mrecvport [媒体流接收者端口]
 * @param  find      [是否已经出现过 出参]
 * @param  callid    [会话ID]
 * @param  nodeid    [节点ID 未使用]
 * @return           [成功时返回查找到的通道ID号  失败返回负值]
 */
#define FILLCHANNEL(channel, callid, mrecvip, mrecvport) { \
    strcpy((channel).callid, callid);\
    strcpy((channel).media_recvip, mrecvip);\
    strcpy((channel).media_recvport, mrecvport);\
    (channel).tm = time(NULL);\
}

//回收通道时也记录下回收时间 防止短时间内被再次分配使用
#define CLEARCHANNEL(channel) { \
    BZERO((channel).callid); \
    BZERO((channel).media_recvip); \
    BZERO((channel).media_recvport); \
    (channel).tm = time(NULL); \
}

#ifdef RESEAL_SIP_INTERFACE
int CClientSipNorm::getOneChannelID(const char *mrecvip, const char *mrecvport,
                                    int &find, const char *callid, int &nodeid)
{
    if (strcmp(callid, "") == 0) {
        PRINT_ERR_HEAD
        print_err("callid is empty");
        return -1;
    }

    int use_chanid = -1;
    PRINT_DBG_HEAD
    print_dbg("get channelID begin.[%s][%s][%s] lastid[%d]", callid, mrecvip, mrecvport, m_lastid);

    //是否存在
    for (int i = 0; i < m_maxchannel; ++i) {
        if (strcmp(callid, m_channel[i].callid) == 0) {
            if ((strcmp(mrecvip, m_channel[i].media_recvip) == 0)
                && (strcmp(mrecvport, m_channel[i].media_recvport) == 0)) {
                find = 1;
                PRINT_INFO_HEAD
                print_info("already open.channel[%d][%s][%s][%s]", i, callid, mrecvip, mrecvport);
                return i;
            } else {
                PRINT_INFO_HEAD
                print_info("the same callid used in diff sessions.channel[%d][%s][%s:%s]"
                           "clear previous cfg[%s:%s]",
                           i, callid, mrecvip, mrecvport, m_channel[i].media_recvip,
                           m_channel[i].media_recvport);
                delOneChannel(i);
                CLEARCHANNEL(m_channel[i]);
                use_chanid = i;
                break;
            }
        }
    }

    //查找空闲的 同时记录下最早插入的那条
    int earliest = 0;
    int idx = 0;
    for (int i = 0; i < m_maxchannel; ++i) {
        idx = (m_lastid + 1 + i) % m_maxchannel;
        if (strcmp("", m_channel[idx].callid) == 0) {
            if ((use_chanid != idx)
                && (time(NULL) - m_channel[idx].tm > CHANNEL_TIME_OUT_SECOND)) {
                FILLCHANNEL(m_channel[idx], callid, mrecvip, mrecvport);
                m_lastid = idx;
                PRINT_DBG_HEAD
                print_dbg("get empty channel[%d] [%s][%s][%s]", idx, callid, mrecvip, mrecvport);
                return idx;
            }
        } else {
            if (m_channel[idx].tm < m_channel[earliest].tm) {
                earliest = idx;
            }
        }
    }

    PRINT_INFO_HEAD
    print_info("reuse channel[%d]. old info[%s][%s][%s] new info[%s][%s][%s]",
               earliest, m_channel[earliest].callid, m_channel[earliest].media_recvip,
               m_channel[earliest].media_recvport, callid, mrecvip, mrecvport);

    //复用
    delOneChannel(earliest);
    FILLCHANNEL(m_channel[earliest], callid, mrecvip, mrecvport);
    return earliest;
}
#else
int CClientSipNorm::getOneChannelID(const char *mrecvip, const char *mrecvport,
                                    int &find, const char *callid, int &nodeid)
{
    if (strcmp(callid, "") == 0) {
        PRINT_ERR_HEAD
        print_err("callid is empty");
        return -1;
    }

    //是否存在
    for (int i = 0; i < m_maxchannel; ++i) {
        if (strcmp(callid, m_channel[i].callid) == 0) {
            if ((strcmp(mrecvip, m_channel[i].media_recvip) == 0)
                && (strcmp(mrecvport, m_channel[i].media_recvport) == 0)) {
                find = 1;
            } else {
                PRINT_ERR_HEAD
                print_err("The same callid[%s] is used in different sessions,[%s:%s][%s:%s]",
                          callid, mrecvip, mrecvport, m_channel[i].media_recvip,
                          m_channel[i].media_recvport);
                delOneChannel(i);
                FILLCHANNEL(m_channel[i], callid, mrecvip, mrecvport);
            }
            return i;
        }
    }

    //查找空闲的 同时记录下最早插入的那条
    int earliest = 0;
    for (int i = 0; i < m_maxchannel; ++i) {
        if (strcmp("", m_channel[i].callid) == 0) {
            FILLCHANNEL(m_channel[i], callid, mrecvip, mrecvport);
            return i;
        } else {
            if (m_channel[i].tm < m_channel[earliest].tm) {
                earliest = i;
            }
        }
    }

    //复用
    delOneChannel(earliest);
    FILLCHANNEL(m_channel[earliest], callid, mrecvip, mrecvport);
    return earliest;
}
#endif
/**
 * [CClientSipNorm::delOneChannel 删除一个流媒体通道]
 * @param chanid [通道ID]
 */
void CClientSipNorm::delOneChannel(int chanid)
{
    channelOper(chanid, false);
}

/**
 * [CClientSipNorm::addOneChannel 添加一个流媒体通道]
 * @param nodeid [节点ID]
 * @param chanid [通道ID]
 */
void CClientSipNorm::addOneChannel(int nodeid, int chanid)
{
    channelOper(chanid, true);
}

/**
 * [CClientSipNorm::channelOper 打开或删除通道]
 * @param chanid [通道ID]
 * @param ifadd  [是否为打开]
 */
void CClientSipNorm::channelOper(int chanid, bool ifadd)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char c = ifadd ? 'I' : 'D';

    if (chanid < 0) {
        PRINT_ERR_HEAD
        print_err("chanid[%d] err", chanid);
        return ;
    }

    sem_wait(g_iptables_lock);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p udp --dport %d -j DNAT --to '%s':%d",
            IPTABLES, c, m_tmpip2, m_tmpip1, atoi(m_channel[chanid].myport),
            m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport));
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p udp --dport %d -j DNAT --to '%s':%d",
            IPTABLES, c, m_tmpip2, m_tmpip1, atoi(m_channel[chanid].myport) + 1,
            m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport) + 1);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    /* 清理动态端口链接追踪 */
    sprintf(chcmd, "%s -D -d %s -p udp --dport %d", CONNTRACK, m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport));
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    /* 清理动态端口链接追踪 */
    sprintf(chcmd, "%s -D -d %s -p udp --dport %d", CONNTRACK, m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport) + 1);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

#ifdef CLI_SIP_STREAM_USE_TCP
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p tcp --dport %d -j DNAT --to '%s':%d",
            IPTABLES, c, m_tmpip2, m_tmpip1, atoi(m_channel[chanid].myport),
            m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport));
    system(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s -p tcp --dport %d -j DNAT --to '%s':%d",
            IPTABLES, c, m_tmpip2,  m_tmpip1, atoi(m_channel[chanid].myport) + 1,
            m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport) + 1);
    system(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    /* 清理动态端口链接追踪 */
    sprintf(chcmd, "%s -D -d %s -p tcp --dport %d", CONNTRACK, m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport));
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

    /* 清理动态端口链接追踪 */
    sprintf(chcmd, "%s -D -d %s -p tcp --dport %d", CONNTRACK, m_channel[chanid].media_recvip, atoi(m_channel[chanid].media_recvport) + 1);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("chcmd[%s]", chcmd);

#endif

    sem_post(g_iptables_lock);
}

/**
 * [CClientSipNorm::getChannelProxyPort 获取媒体流通道接收端口号]
 * @param nodeid [节点ID]
 * @param chanid [通道ID]
 * @return    [成功返回端口号，失败返回NULL]
 */
const char *CClientSipNorm::getChannelProxyPort(int nodeid, int chanid)
{
    if ((chanid < 0) || (chanid >= m_maxchannel)) {
        PRINT_ERR_HEAD
        print_err("chanid[%d] err", chanid);
        return NULL;
    }
    return m_channel[chanid].myport;
}

/**
 * [CClientSipNorm::getChannelProxyIP 获取接收视频流IP]
 * @param  callid [会话ID]
 * @return        [地址指针]
 */
const char *CClientSipNorm::getChannelProxyIP(const char *callid)
{
    return m_gapoutip;
}

/**
 * [CClientSipNorm::getChannelOutIP 获取发送视频流IP]
 * @param  callid [会话ID]
 * @return        [地址指针]
 */
const char *CClientSipNorm::getChannelOutIP(const char *callid)
{
    return m_gapinip;
}

/**
 * [CClientSipNorm::dstVideoPrepare 网闸靠近平台的一端，视频流通道准备]
 */
void CClientSipNorm::dstVideoPrepare()
{
    char chcmd[CMD_BUF_LEN] = {0};
    int low = CLI_SIP_NORM_STARTMPORT;
    int high = CLI_SIP_NORM_STARTMPORT + m_maxchannel * 2 - 1;

    sprintf(chcmd, "%s -t nat -I PREROUTING -d '%s' -p udp --dport %d:%d -j DNAT --to %s",
            IPTABLES, m_gapoutip, low, high, m_tmpip1);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -I FORWARD -d %s -p udp --dport %d:%d -j ACCEPT",
            IPTABLES, m_tmpip1, low, high);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -d %s -p udp --dport %d:%d -j SNAT --to %s",
            IPTABLES, m_tmpip1, low, high, m_tmpip2);
    SIP_SYSTEM(chcmd);

#ifdef CLI_SIP_STREAM_USE_TCP
    sprintf(chcmd, "%s -t nat -I PREROUTING -d '%s' -p tcp --dport %d:%d -j DNAT --to %s",
            IPTABLES, m_gapoutip, low, high, m_tmpip1);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -I FORWARD -d %s -p tcp --dport %d:%d -j ACCEPT",
            IPTABLES, m_tmpip1, low, high);
    SIP_SYSTEM(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -d %s -p tcp --dport %d:%d -j SNAT --to %s",
            IPTABLES, m_tmpip1, low, high, m_tmpip2);
    SIP_SYSTEM(chcmd);
#endif
}

/**
 * [CClientSipNorm::dstStart 网闸靠近平台的一端启动函数]
 * @return [成功返回0]
 */
int CClientSipNorm::dstStart()
{
    CClientSipBase::dstStart();
    dstVideoPrepare();
    return 0;
}

/**
 * [CClientSipNorm::srcStart 网闸靠近客户端的一端启动函数]
 * @return [成功返回0]
 */
int CClientSipNorm::srcStart()
{
    return CClientSipBase::srcStart();
}

const char *CClientSipNorm::getTypeDesc()
{
    return LOG_TYPE_CLIENT_SIP_NORM;
}

/**
 * [CClientSipNorm::delChannelByCallID 根据callid清除一个视频流通道]
 * @param callid [会话ID]
 */
void CClientSipNorm::delChannelByCallID(const char *callid)
{
    for (int i = 0; i < m_maxchannel; ++i) {
        if (strcmp(callid, m_channel[i].callid) == 0) {
            PRINT_DBG_HEAD
            print_dbg("del channel by id %d[%s]", i, callid);
            delOneChannel(i);
            CLEARCHANNEL(m_channel[i]);
            return;
        }
    }
}
