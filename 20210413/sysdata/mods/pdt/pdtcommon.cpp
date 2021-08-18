/*******************************************************************************************
*文件: pdtcommon.cpp
*描述: PDT互联
*作者: 王君雷
*日期: 2018-07-31
*修改:
*******************************************************************************************/
#include "pdtcommon.h"
#include "debugout.h"

CPDTCommon::CPDTCommon(int taskid): CPDTBase(taskid)
{
    m_max_channel = 0;
    m_pchannel = NULL;
    initLock();
}

CPDTCommon::~CPDTCommon(void)
{
    destroyLock();
    DELETE(m_pchannel);
}

/**
 * [CPDTCommon::initChannel 通道初始化]
 * 标准规定，通道媒体端口应为偶数
 * @return              [成功返回0 失败返回负值]
 */
int CPDTCommon::initChannel(void)
{
    m_max_channel = PDT_COMMON_MAX_CHANNEL;
    m_pchannel = new PDTCHANNEL[m_max_channel];
    if (m_pchannel == NULL) {
        PRINT_ERR_HEAD
        print_err("new channel fail. max channel[%d]", m_max_channel);
        return -1;
    }

    memset(m_pchannel, 0, sizeof(PDTCHANNEL) * m_max_channel);
    for (int i = 0; i < m_max_channel; i++) {
        sprintf(m_pchannel[i].proxyport, "%d", PDT_COMMON_PORT_START + 2 * i);
        m_pchannel[i].enable = true;
    }
    return 0;
}

/**
 * [CPDTCommon::getChannelProxyIP 获取通道代理IP]
 * @param  callid         [会话ID]
 * @param  area           [来自哪个交换中心]
 * @param  channelproxyip [出参]
 * @return                [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyIP(const char *callid, int area, char *channelproxyip)
{
    int ret = -1;
    if (area == AREA_IN_CENTER) {
        ret = 0;
        strcpy(channelproxyip, m_gapoutip);
    } else if (area == AREA_OUT_CENTER) {
        ret = 0;
        strcpy(channelproxyip, m_gapinip);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown area[%d]. callid is[%s]", area, callid);
    }
    return ret;
}

/**
 * [CPDTCommon::getChannelProxyPort 获取通道端口]
 * @param  callid      [会话ID]
 * @param  area        [来自哪个交换中心]
 * @param  originip    [会话发起方IP]
 * @param  mediaport   [媒体端口]
 * @param  isresp      [是否为响应]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyPort(const char *callid, int area, const char *originip,
                                    const char *mediaport, bool isresp, char *channelport)
{
    if ((strlen(originip) <= 0) || (strlen(callid) <= 0) || (strlen(mediaport) <= 0)) {
        PRINT_ERR_HEAD
        print_err("originip[%s], callid[%s], mediaport[%s] should not null",
                  originip, callid, mediaport);
        return -1;
    }

    if (isresp) {
        return getChannelProxyPortRespons(callid, area, originip, mediaport, channelport);
    } else {
        return getChannelProxyPortRequest(callid, area, originip, mediaport, channelport);
    }
}

/**
 * [CPDTCommon::getChannelProxyPortRequest 获取通道端口 数据包为请求包]
 * @param  callid      [会话ID]
 * @param  area        [来自哪个交换中心]
 * @param  originip    [会话发起方IP]
 * @param  mediaport   [媒体端口]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyPortRequest(const char *callid, int area, const char *originip,
        const char *mediaport, char *channelport)
{
    int index = -1;
    int earliest = 0;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s:%s]", callid, originip, mediaport);

    lock();

    //already exist ? less likely
    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (strcmp(callid, m_pchannel[i].callid) == 0)) {
            if ((strcmp((area == AREA_IN_CENTER) ?
                        m_pchannel[i].inmsip : m_pchannel[i].outmsip, originip) == 0)
                && (strcmp((area == AREA_IN_CENTER) ?
                           m_pchannel[i].inmsport : m_pchannel[i].outmsport, mediaport) == 0)) {
                PRINT_INFO_HEAD
                print_info("request again.[%s:%s:%s]", callid, originip, mediaport);
                index = i;
                goto _ok;
            } else {
                PRINT_ERR_HEAD
                print_err("The same callid[%s] is used in different sessions,[%s:%s][%s:%s]",
                          callid, originip, mediaport,
                          (area == AREA_IN_CENTER) ? m_pchannel[i].inmsip : m_pchannel[i].outmsip,
                          (area == AREA_IN_CENTER) ?
                          m_pchannel[i].inmsport : m_pchannel[i].outmsport);
                goto _err;
            }
        }
    }

    //find available and record the earliest one
    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (IS_STR_EMPTY(m_pchannel[i].callid))) {
            index = i;
            break;
        } else {
            if (m_pchannel[i].activetime < m_pchannel[earliest].activetime) {
                earliest = i;
            }
        }
    }

    //reuse the earliest one
    if (index < 0) {
        PRINT_INFO_HEAD
        print_info("reuse the earliest channel[%d].[%s:%s:%s]", earliest, callid, originip, mediaport);
        index = earliest;
        delOneChannel(index);
    }

_ok:
    resetOneChannel(index);
    strcpy(m_pchannel[index].callid, callid);
    strcpy((area == AREA_IN_CENTER) ? m_pchannel[index].inmsip : m_pchannel[index].outmsip, originip);
    strcpy((area == AREA_IN_CENTER) ? m_pchannel[index].inmsport : m_pchannel[index].outmsport, mediaport);
    m_pchannel[index].activetime = time(NULL);
    strcpy(channelport, m_pchannel[index].proxyport);

    unlock();
    PRINT_DBG_HEAD
    print_dbg("get channel port[%s] success.", channelport);
    return 0;

_err:
    unlock();
    return -1;
}

/**
 * [CPDTCommon::getChannelProxyPortRespons 获取通道端口 数据包为响应包]
 * @param  callid      [会话ID]
 * @param  area        [来自哪个交换中心]
 * @param  originip    [会话发起方IP]
 * @param  mediaport   [媒体端口]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyPortRespons(const char *callid, int area, const char *originip,
        const char *mediaport, char *channelport)
{
    if (area == AREA_IN_CENTER) {
        return getChannelProxyPortResponsInCenter(callid, originip, mediaport, channelport);
    } else {
        return getChannelProxyPortResponsOutCenter(callid, originip, mediaport, channelport);
    }
}

/**
 * [CPDTCommon::getChannelProxyPortResponsInCenter 获取通道端口 数据包为响应包 来自内网交换中心]
 * @param  callid      [会话ID]
 * @param  originip    [会话发起方IP]
 * @param  mediaport   [媒体端口]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyPortResponsInCenter(const char *callid, const char *originip,
        const char *mediaport, char *channelport)
{
    int index = -1;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s:%s]", callid, originip, mediaport);

    lock();

    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (strcmp(callid, m_pchannel[i].callid) == 0)) {
            if (IS_STR_EMPTY(m_pchannel[i].outmsip) || IS_STR_EMPTY(m_pchannel[i].outmsport)) {
                PRINT_ERR_HEAD
                print_err("in center response come[%s:%s:%s], while out center request missing",
                          callid, originip, mediaport);
            } else {
                if (IS_STR_EMPTY(m_pchannel[i].inmsip) && IS_STR_EMPTY(m_pchannel[i].inmsport)) {
                    strcpy(m_pchannel[i].inmsip, originip);
                    strcpy(m_pchannel[i].inmsport, mediaport);
                    m_pchannel[i].activetime = time(NULL);
                    addOneChannel(i);
                } else {
                    PRINT_INFO_HEAD
                    print_info("response again.[%s:%s:%s]", callid, originip, mediaport);
                }
                index = i;
            }
            break;
        }
    }

    if (index >= 0) {
        strcpy(channelport, m_pchannel[index].proxyport);
        unlock();
        PRINT_DBG_HEAD
        print_dbg("get channel port over. port[%s]", channelport);
        return 0;
    }

    unlock();
    return -1;
}

/**
 * [CPDTCommon::getChannelProxyPortResponsOutCenter 获取通道端口 数据包为响应包 来自外网交换中心]
 * @param  callid      [会话ID]
 * @param  originip    [会话发起方IP]
 * @param  mediaport   [媒体端口]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTCommon::getChannelProxyPortResponsOutCenter(const char *callid, const char *originip,
        const char *mediaport, char *channelport)
{
    int index = -1;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s:%s]", callid, originip, mediaport);

    lock();

    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (strcmp(callid, m_pchannel[i].callid) == 0)) {
            if (IS_STR_EMPTY(m_pchannel[i].inmsip) || IS_STR_EMPTY(m_pchannel[i].inmsport)) {
                PRINT_ERR_HEAD
                print_err("out center response come[%s:%s:%s], while in center request missing",
                          callid, originip, mediaport);
            } else {
                if (IS_STR_EMPTY(m_pchannel[i].outmsip) && IS_STR_EMPTY(m_pchannel[i].outmsport)) {
                    strcpy(m_pchannel[i].outmsip, originip);
                    strcpy(m_pchannel[i].outmsport, mediaport);
                    m_pchannel[i].activetime = time(NULL);
                    addOneChannel(i);
                } else {
                    PRINT_INFO_HEAD
                    print_info("response again.[%s:%s:%s]", callid, originip, mediaport);
                }
                index = i;
            }
            break;
        }
    }

    if (index >= 0) {
        strcpy(channelport, m_pchannel[index].proxyport);
        unlock();
        PRINT_DBG_HEAD
        print_dbg("get channel port over. port[%s]", channelport);
        return 0;
    }

    unlock();
    return -1;
}

/**
 * [CPDTCommon::resetOneChannel 重置一个通道]
 * @param chanid [通道ID]
 */
void CPDTCommon::resetOneChannel(int chanid)
{
    BZERO(m_pchannel[chanid].inmsip);
    BZERO(m_pchannel[chanid].inmsport);
    BZERO(m_pchannel[chanid].outmsip);
    BZERO(m_pchannel[chanid].outmsport);
    BZERO(m_pchannel[chanid].callid);
    m_pchannel[chanid].activetime = 0;
}

/**
 * [CPDTCommon::delOneChannel 删除一个通道]
 * @param  chanid [通道ID]
 * @return        [成功返回0 失败返回负值]
 */
int CPDTCommon::delOneChannel(int chanid)
{
    return channelOper(chanid, false);
}

/**
 * [CPDTCommon::delOneChannel 添加一个通道]
 * @param  chanid [通道ID]
 * @return        [成功返回0 失败返回负值]
 */
int CPDTCommon::addOneChannel(int chanid)
{
    return channelOper(chanid, true);
}

/**
 * [CPDTCommon::channelOper 通道操作]
 * @param  chanid [通道ID]
 * @param  isadd  [是否为添加]
 * @return        [成功返回0 失败返回负值]
 */
int CPDTCommon::channelOper(int chanid, bool isadd)
{
    char chcmd[CMD_BUF_LEN];
    char oper = isadd ? 'I' : 'D';

    if (IS_STR_EMPTY(m_pchannel[chanid].inmsip)
        || IS_STR_EMPTY(m_pchannel[chanid].inmsport)
        || IS_STR_EMPTY(m_pchannel[chanid].outmsip)
        || IS_STR_EMPTY(m_pchannel[chanid].outmsport)
        || IS_STR_EMPTY(m_pchannel[chanid].callid)) {
        PRINT_ERR_HEAD
        print_err("channel error[%s,%s:%s,%s:%s,%s]", m_pchannel[chanid].callid,
                  m_pchannel[chanid].inmsip, m_pchannel[chanid].inmsport, m_pchannel[chanid].outmsip,
                  m_pchannel[chanid].outmsport, m_pchannel[chanid].proxyport);

        return -1;
    }

    //innet -> outnet
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s  -p udp --sport %s --dport %s -j DNAT --to %s",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_gapinip, m_pchannel[chanid].inmsport,
            m_pchannel[chanid].proxyport, m_inneroutip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s  -p udp --sport %s --dport %s -j SNAT --to %s",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, m_pchannel[chanid].inmsport,
            m_pchannel[chanid].proxyport, m_innerinip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s  -p udp --sport %s --dport %s -j DNAT --to %s:%s",
            IPTABLES, oper, m_innerinip, m_inneroutip, m_pchannel[chanid].inmsport,
            m_pchannel[chanid].proxyport, m_pchannel[chanid].outmsip, m_pchannel[chanid].outmsport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s  -p udp --sport %s --dport %s -j SNAT --to %s:%s",
            IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, m_pchannel[chanid].inmsport,
            m_pchannel[chanid].outmsport, m_gapoutip, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, false);

    //outnet -> innet
    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s  -p udp --sport %s --dport %s -j DNAT --to %s",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_gapoutip, m_pchannel[chanid].outmsport,
            m_pchannel[chanid].proxyport, m_innerinip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s  -p udp --sport %s --dport %s -j SNAT --to %s",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, m_pchannel[chanid].outmsport,
            m_pchannel[chanid].proxyport, m_inneroutip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s %s -d %s  -p udp --sport %s --dport %s -j DNAT --to %s:%s",
            IPTABLES, oper, m_inneroutip, m_innerinip, m_pchannel[chanid].outmsport,
            m_pchannel[chanid].proxyport, m_pchannel[chanid].inmsip, m_pchannel[chanid].inmsport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s %s -d %s  -p udp --sport %s --dport %s -j SNAT --to %s:%s",
            IPTABLES, oper, m_inneroutip, m_pchannel[chanid].inmsip, m_pchannel[chanid].outmsport,
            m_pchannel[chanid].inmsport, m_gapinip, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, true);

    PRINT_DBG_HEAD
    print_dbg("channel oper over [%c][%s,%s:%s,%s:%s,%s]", oper, m_pchannel[chanid].callid,
              m_pchannel[chanid].inmsip, m_pchannel[chanid].inmsport, m_pchannel[chanid].outmsip,
              m_pchannel[chanid].outmsport, m_pchannel[chanid].proxyport);
    return 0;
}

/**
 * [CPDTCommon::deleteChannelByCallID 根据会话ID清除一条通道]
 * @param callid [会话ID]
 */
void CPDTCommon::deleteChannelByCallID(const char *callid)
{
    lock();
    for (int i = 0; i < m_max_channel; i++) {
        if (m_pchannel[i].enable && (strcmp(callid, m_pchannel[i].callid) == 0)) {
            delOneChannel(i);
            resetOneChannel(i);
            PRINT_DBG_HEAD
            print_dbg("del channel by callid ok[%d:%s]", i, callid);
            break;
        }
    }
    unlock();
}

/**
 * [CPDTCommon::initLock 初始化锁]
 */
void CPDTCommon::initLock(void)
{
    if (sem_init(&m_lock, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init lock fail");
    }
}

/**
 * [CPDTCommon::destroyLock 摧毁锁]
 */
void CPDTCommon::destroyLock(void)
{
    sem_destroy(&m_lock);
}

/**
 * [CPDTCommon::lock 加锁]
 */
void CPDTCommon::lock(void)
{
    sem_wait(&m_lock);
}

/**
 * [CPDTCommon::unlock 解锁]
 */
void CPDTCommon::unlock(void)
{
    sem_post(&m_lock);
}

