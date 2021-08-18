/*******************************************************************************************
*文件: SipInterConnect.cpp
*描述: 平台互联
*作者: dzj
*日期: 2019-07-05
*修改:
*        媒体流为TCP时的iptables                                        ------> 2019-08-03
*        修改重请求时的对媒体流结构处理以及媒体流为UDP时iptables方向    ------> 2019-08-07
*        修改级联和代理模式内外网侧iptables规则
*        添加设置媒体流为TCP时主动方向接口                              ------> 2019-08-14
*        修改SIP重请求或重响应造成的内存泄漏问题                        ------> 2019-08-20
*        解决一所检测时主动模式IPTABLES错误导致的不通问题               ------> 2019-10-16
*        解决传输媒体流时每次都使用同一端口问题                         ------> 2019-11-21
*        修改适配东方网力代码改为适配其他厂家                           ------> 2019-12-05
*        修改适配东方网力和数智源代码                                   ------> 2019-12-10
*        当一次INVITE点播对应有多个含SDP的响应包时，也能正常替换动态端口 ------> 2020-08-03
*        修改路由模式下TCP传输视频流时，有一侧主机FORWARD没放过的问题    ------> 2020-08-19
*        解决BUG，半连接状态的通道被清空，从而导致响应包中媒体流端口替换为空 ------> 2020-09-08 wjl
*        执行iptables前加锁，防止多任务多线程同时执行导致失败              ------> 2020-09-11 wjl
*        解决通道分配复用时，初始下标设置为-1导致替换invite端口为空的BUG    ------> 2020-09-14
*        开通道时先操作POSTROUTING，后操作PREROUTING，防止连接通了但源接口不正确的问题
*                                                                       ------> 2020-09-22
*        解决通道复用时、连续2次invite复用同一个通道导致的端口替换为空bug------> 2020-12-24
*        解决视频通道开通时iptables插入慢导致视频流不转发bug             ------> 2021-03-25
*******************************************************************************************/
#include "SipInterConnect.h"
#include "debugout.h"

extern sem_t *g_iptables_lock;

//#define SIP_CLEAN_TRACK "/initrd/abin/clean_track_sip"

CSipInterConnect::CSipInterConnect(int taskid): CSipInterConnectBase(taskid)
{
    m_max_channel = SIP_INTER_CONNECT_MAX_CHANNEL;
    m_pchannel = NULL;
    initLock();
}

CSipInterConnect::~CSipInterConnect(void)
{
    destroyLock();
    DELETE(m_pchannel);
}

/**
 * [CSipInterConnect::needDealFactory 判断厂家]
 * @return [是则返回true]
 */
bool CSipInterConnect::needDealFactory()
{
    return ((ID_SOYUAN == m_inbrandid) || (ID_SOYUAN == m_outbrandid) ||
            (ID_NETPOSA == m_inbrandid) || (ID_NETPOSA == m_outbrandid) ||
            (ID_OTHERBRAND == m_inbrandid) || (ID_OTHERBRAND == m_outbrandid));
}

/**
 * [CSipInterConnect::initChannel 通道初始化]
 * 标准规定，通道媒体端口应为偶数
 * @return              [成功返回0 失败返回负值]
 */
int CSipInterConnect::initChannel(void)
{
    m_pchannel = new SipInterConnectCHANNEL[m_max_channel];
    if (m_pchannel == NULL) {
        PRINT_ERR_HEAD
        print_err("new channel fail. max channel[%d]", m_max_channel);
        return -1;
    }

    m_lastid = -1;
    memset(m_pchannel, 0, sizeof(SipInterConnectCHANNEL) * m_max_channel);
    for (int i = 0; i < SIP_INTER_CONNECT_MAX_CHANNEL; i++) {
        sprintf(m_pchannel[i].proxyport, "%d", SIP_INTER_CONNECT_PORT_START + 2 * i);
        m_pchannel[i].callid = m_pchannel[i].outmsip = m_pchannel[i].inmsip = NULL;
    }
    return 0;
}

/**
 * [CSipInterConnect::setMediaTransfer 设置TCP媒体流主动方向]
 * @param channel_id   [该SIP报文对应的媒体流通道ID]
 * @param transfer     [TCP媒体流方向0:主动，1:被动]
 */
void CSipInterConnect::setMediaTransfer(int channel_id, bool transfer)
{
    PRINT_DBG_HEAD
    print_dbg("set tcp media channel transfer.[%d:%d]", channel_id, transfer);

    lock();
    m_pchannel[channel_id].transfer = transfer;
    unlock();
}


/**
 * [CSipInterConnect::getChannelProxyPort 获取通道端口]
 * @param sip_info      [包含SIP报文每行关键字标志和IP信息]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CSipInterConnect::getChannelProxyPort(SipInterConnect_INFO *sip_info, char *channelport)
{
    if ((NULL == sip_info) || (NULL == sip_info->callid) || (NULL == sip_info->originip)) {
        PRINT_ERR_HEAD
        print_err("originip[%s], callid[%s] should not null",
                  sip_info->originip, sip_info->callid);
        return -1;
    }

    if (sip_info->isresp) {
        return getChannelProxyPortRespons(sip_info, channelport);
    } else {
        return getChannelProxyPortRequest(sip_info, channelport);
    }
}

/**
 * [CSipInterConnect::getChannelProxyPortRequest 获取通道端口 数据包为请求包]
 * @param sip_info      [包含SIP报文每行关键字标志和IP信息]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CSipInterConnect::getChannelProxyPortRequest(SipInterConnect_INFO *sip_info, char *channelport)
{
    int index = -1;
    int idx = 0;
    int earliest = 0;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s]", sip_info->callid, sip_info->originip);

    lock();

    //already exist ? less likely
    for (int i = 0; i < m_max_channel; i++) {
        if (NULL == m_pchannel[i].callid) {
            continue;
        }
        if ((strcmp(sip_info->callid, m_pchannel[i].callid) == 0)) {
            index = i;
            PRINT_INFO_HEAD
            print_info("find callid[%s] index[%d]", sip_info->callid, index);
            goto _ok;
        }
    }

    //查找空闲的 同时记录下最早插入的那条
    for (int i = 0; i < m_max_channel; ++i) {
        idx = (m_lastid + 1 + i) % m_max_channel;
        if (NULL == m_pchannel[idx].callid) {
            m_lastid = index = idx;
            resetOneChannel(idx);
            PRINT_INFO_HEAD
            print_info("get channel[%d] callid[%s]", index, sip_info->callid);
            goto _ok;
        } else {
            if (m_pchannel[idx].activetime < m_pchannel[earliest].activetime) {
                PRINT_DBG_HEAD
                print_dbg("earliest time %d[%d] ---> %d[%d]", earliest, m_pchannel[earliest].activetime,
                          idx, m_pchannel[idx].activetime);
                earliest = idx;
            }
        }
    }

    PRINT_INFO_HEAD
    print_info("index[%d] earliest[%d] callid[%s]", index, earliest, sip_info->callid);

    //reuse the earliest one
    if (index < 0) {
        PRINT_INFO_HEAD
        print_info("reuse the earliest channel[%d]%d.[%s:%s]", earliest, m_pchannel[earliest].activetime,
                   sip_info->callid, sip_info->originip);
        m_lastid = index = earliest;
        delOneChannel(index);
        resetOneChannel(index);
    }

_ok:
    if (SIP_NULL_PORT == m_pchannel[index].port_flag) {
        m_pchannel[index].callid = strdup(sip_info->callid);
        ((sip_info->area == SIP_IN_CENTER) ? m_pchannel[index].inmsip :
         m_pchannel[index].outmsip) = strdup(sip_info->originip);
        PRINT_INFO_HEAD
        print_info("set channel[%d] callid [%s], area[%d], originip[%s], videoport[%d]", \
                   index, m_pchannel[index].callid, sip_info->area, sip_info->originip, sip_info->videoport);
    }
    strcpy((sip_info->area == SIP_IN_CENTER) ? m_pchannel[index].in_videoport :
           m_pchannel[index].out_videoport, sip_info->videoport);
    strcpy((sip_info->area == SIP_IN_CENTER) ? m_pchannel[index].in_audioport :
           m_pchannel[index].out_audioport, sip_info->audioport);
    strcpy(channelport, m_pchannel[index].proxyport);
    m_pchannel[index].is_udp = sip_info->is_udp;
    m_pchannel[index].port_flag = sip_info->port_flag;
    m_pchannel[index].area = sip_info->area ? true : false;
    m_pchannel[index].activetime = time(NULL);
    sip_info->channel_id = index;

    unlock();
    PRINT_INFO_HEAD
    print_info("get channel port[%s] success. index[%d] callid[%s]", channelport, index, sip_info->callid);
    return 0;
}

/**
 * [CSipInterConnect::getChannelProxyPortRespons 获取通道端口 数据包为响应包]
 * @param sip_info      [包含SIP报文每行关键字标志和IP信息]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CSipInterConnect::getChannelProxyPortRespons(SipInterConnect_INFO *sip_info, char *channelport)
{
    if (sip_info->area == SIP_IN_CENTER) {
        return getChannelProxyPortResponsInCenter(sip_info, channelport);
    } else {
        return getChannelProxyPortResponsOutCenter(sip_info, channelport);
    }
}

/**
 * [CSipInterConnect::getSipInfoToChannel 获取通道端口 数据包为响应包 来自内网交换中心]
 * @param index        [通道结构下标]
 * @param  area        [方向]
 * @param  sip_info    [SIP协议携带的信息]
 */
int CSipInterConnect::getSipInfoToChannel(int index, bool area, SipInterConnect_INFO *sip_info)
{
    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[flag %d  port %s port %s]",
              m_pchannel[index].port_flag, sip_info->audioport, sip_info->videoport);
#if 0
    if (m_pchannel[index].activetime != 0) {
        PRINT_INFO_HEAD
        print_info("the channel already add call_id is [%s]", m_pchannel[index].callid);
        return -1;
    }
#endif
    if (SIP_VIDEO_AND_AUDIO_PORT != sip_info->port_flag) {
        (area ? m_pchannel[index].outmsip : m_pchannel[index].inmsip) = strdup(sip_info->originip);
    }
    if (SIP_VIDEO_AND_AUDIO_PORT == m_pchannel[index].port_flag) {
        strcpy(area ? m_pchannel[index].out_audioport : m_pchannel[index].in_audioport,
               sip_info->audioport);
        strcpy(area ? m_pchannel[index].out_videoport : m_pchannel[index].in_videoport,
               sip_info->videoport);
        if (m_pchannel[index].port_flag == sip_info->port_flag) {
            m_pchannel[index].activetime = time(NULL);
            addOneChannel(index);
        }
    } else if (SIP_VIDEO_PORT == m_pchannel[index].port_flag) {
        strcpy(area ? m_pchannel[index].out_videoport : m_pchannel[index].in_videoport,
               sip_info->videoport);
        m_pchannel[index].activetime = time(NULL);
        addOneChannel(index);
    } else if (SIP_AUDIO_PORT == m_pchannel[index].port_flag) {
        strcpy(area ? m_pchannel[index].out_audioport : m_pchannel[index].in_audioport,
               sip_info->audioport);
        m_pchannel[index].activetime = time(NULL);
        addOneChannel(index);
    }

    return 0;
}



/**
 * [CSipInterConnect::getChannelProxyPortResponsInCenter 获取通道端口 数据包为响应包 来自内网交换中心]
 * @param sip_info     [包含SIP报文每行关键字标志和IP信息]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CSipInterConnect::getChannelProxyPortResponsInCenter(SipInterConnect_INFO *sip_info, char *channelport)
{
    int index = -1;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s]", sip_info->callid, sip_info->originip);

    lock();

    for (int i = 0; i < m_max_channel; i++) {
        if (NULL == m_pchannel[i].callid) {
            continue;
        }
        if (strcmp(sip_info->callid, m_pchannel[i].callid) == 0) {
            if (IS_STR_EMPTY(m_pchannel[i].outmsip)) {
                PRINT_ERR_HEAD
                print_err("in center response come[%s:%s], while out center request missing",
                          sip_info->callid, sip_info->originip);
            } else {
                if (getSipInfoToChannel(i, false, sip_info) < 0) {
                    strcpy(channelport, m_pchannel[i].proxyport);
                    goto _out;
                }
                index = i;
            }
            break;
        }
    }

    if (index >= 0) {
        strcpy(channelport, m_pchannel[index].proxyport);
        unlock();
        PRINT_INFO_HEAD
        print_info("get channel port over. port[%s]", channelport);
        return 0;
    }

_out:
    unlock();
    PRINT_ERR_HEAD
    print_err("get channel port. index[%d]", index);
    return -1;
}

/**
 * [CSipInterConnect::getChannelProxyPortResponsOutCenter 获取通道端口 数据包为响应包 来自外网交换中心]
 * @param sip_info     [包含SIP报文每行关键字标志和IP信息]
 * @param  channelport [网闸通道端口号 出参]
 * @return             [成功返回0 失败返回负值]
 */
int CSipInterConnect::getChannelProxyPortResponsOutCenter(SipInterConnect_INFO *sip_info, char *channelport)
{
    int index = -1;

    PRINT_DBG_HEAD
    print_dbg("get channel port begin.[%s:%s]", sip_info->callid, sip_info->originip);

    lock();

    for (int i = 0; i < m_max_channel; i++) {
        if (NULL == m_pchannel[i].callid) {
            continue;
        }

        if (strcmp(sip_info->callid, m_pchannel[i].callid) == 0) {
            PRINT_DBG_HEAD
            print_dbg("find callid[%s][%d]", sip_info->callid, i);
            if (IS_STR_EMPTY(m_pchannel[i].inmsip)) {
                PRINT_ERR_HEAD
                print_err("out center response come[%s:%s], while in center request missing",
                          sip_info->callid, sip_info->originip);
            } else {
                if (getSipInfoToChannel(i, true, sip_info) < 0) {
                    strcpy(channelport, m_pchannel[i].proxyport);
                    goto _out;
                }
                index = i;
            }
            break;
        }
    }

    PRINT_DBG_HEAD
    print_dbg("find channel index [%d]", index);

    if (index >= 0) {
        strcpy(channelport, m_pchannel[index].proxyport);
        unlock();
        PRINT_INFO_HEAD
        print_info("get channel port over. port[%s]", channelport);
        return 0;
    }

_out:
    unlock();
    PRINT_ERR_HEAD
    print_err("get channel port. index[%d]", index);
    return -1;
}

/**
 * [CSipInterConnect::resetOneChannel 重置一个通道]
 * @param chanid [通道ID]
 */
void CSipInterConnect::resetOneChannel(int chanid)
{
    PRINT_INFO_HEAD
    print_info("reset channel id[%d] callid[%s] inmsip[%s] outmsip[%s] "
               "inaport[%s] invport[%s] outaport[%s] outvport[%s]", chanid, \
               (m_pchannel[chanid].callid ? m_pchannel[chanid].callid : ""), \
               (m_pchannel[chanid].inmsip ? m_pchannel[chanid].inmsip : ""), \
               (m_pchannel[chanid].outmsip ? m_pchannel[chanid].outmsip : ""), \
               m_pchannel[chanid].in_audioport, m_pchannel[chanid].in_videoport, \
               m_pchannel[chanid].out_audioport, m_pchannel[chanid].out_videoport);

    if (m_pchannel[chanid].inmsip) {
        free(m_pchannel[chanid].inmsip);
        m_pchannel[chanid].inmsip = NULL;
    }
    if (m_pchannel[chanid].callid) {
        free(m_pchannel[chanid].callid);
        m_pchannel[chanid].callid = NULL;
    }
    if (m_pchannel[chanid].outmsip) {
        free(m_pchannel[chanid].outmsip);
        m_pchannel[chanid].outmsip = NULL;
    }
    BZERO(m_pchannel[chanid].in_audioport);
    BZERO(m_pchannel[chanid].in_videoport);
    BZERO(m_pchannel[chanid].out_audioport);
    BZERO(m_pchannel[chanid].out_videoport);
    m_pchannel[chanid].activetime = time(NULL);
    m_pchannel[chanid].port_flag = 0;
    m_pchannel[chanid].transfer = 0;

}

/**
 * [CSipInterConnect::delOneChannel 删除一个通道]
 * @param  chanid [通道ID]
 * @return        [成功返回0 失败返回负值]
 */
int CSipInterConnect::delOneChannel(int chanid)
{
    if ((NULL == m_pchannel[chanid].inmsip)
        || (NULL == m_pchannel[chanid].outmsip)
        || (NULL == m_pchannel[chanid].callid)) {
        PRINT_ERR_HEAD
        print_err("callid , inmsip, outmsip should not NULL");
        return -1;
    }

    return channelOper(chanid, false);
}

/**
 * [CSipInterConnect::delOneChannel 添加一个通道]
 * @param  chanid [通道ID]
 * @return        [成功返回0 失败返回负值]
 */
int CSipInterConnect::addOneChannel(int chanid)
{
    if ((NULL == m_pchannel[chanid].inmsip)
        || (NULL == m_pchannel[chanid].outmsip)
        || (NULL == m_pchannel[chanid].callid)) {
        PRINT_ERR_HEAD
        print_err("add channel callid, inmsip, outmsip should not NULL");
        return -1;
    }

    return channelOper(chanid, true);
}

/**
 * [CSipInterConnect::handelInToOutChannel 开通内网/下级->外网/上级通道]
 * @param  chanid     [通道ID]
 * @param  oper       [“I”或“D”]
 * @param  pro        [UDP或TCP]
 * @param  inmsport   [内网侧平台媒体流端口]
 * @param  outmsport  [外网侧平台媒体流端口]
 */
void CSipInterConnect::handelInToOutChannel(int chanid, char oper, const char *pro,
        const char *inmsport, const char *outmsport)
{
    char chcmd[CMD_BUF_LEN];

    sem_wait(g_iptables_lock);

    //innet -> outnet
    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, inmsport,
            m_pchannel[chanid].proxyport, m_innerinip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, atoi(inmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_innerinip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j DNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_gapinip, pro, inmsport,
            m_pchannel[chanid].proxyport, m_inneroutip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_gapinip, pro, atoi(inmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_inneroutip);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, inmsport,
            m_pchannel[chanid].proxyport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j ACCEPT",
            IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, atoi(inmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    if (needDealFactory()) {
        sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s':%d",
                IPTABLES, oper, m_inneroutip, m_pchannel[chanid].inmsip, pro, atoi(outmsport) + 1,
                atoi(inmsport) + 1, m_gapinip, atoi(m_pchannel[chanid].proxyport) + 1);
        systemCmd(chcmd, true);

        sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s':%d",
                IPTABLES, oper, m_inneroutip, m_innerinip, pro, atoi(outmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_pchannel[chanid].inmsip, atoi(inmsport) + 1);
        systemCmd(chcmd, true);

        /* FORWARD 链在inStart()已开通 */
    }

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j SNAT --to '%s':'%s'",
            IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, inmsport, outmsport,
            m_gapoutip, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s':%d",
            IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, atoi(inmsport) + 1,
            atoi(outmsport) + 1, m_gapoutip, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j DNAT --to '%s':'%s'",
            IPTABLES, oper, m_innerinip, m_inneroutip, pro, inmsport, m_pchannel[chanid].proxyport,
            m_pchannel[chanid].outmsip, outmsport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s':%d",
            IPTABLES, oper, m_innerinip, m_inneroutip, pro, atoi(inmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_pchannel[chanid].outmsip, atoi(outmsport) + 1);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, inmsport, outmsport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j ACCEPT",
            IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, atoi(inmsport) + 1,
            atoi(outmsport) + 1);
    systemCmd(chcmd, false);

    if (needDealFactory()) {
        sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s'",
                IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, pro, atoi(outmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_inneroutip);
        systemCmd(chcmd, false);

        sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s'",
                IPTABLES, oper, m_pchannel[chanid].outmsip, m_gapoutip, pro, atoi(outmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_innerinip);
        systemCmd(chcmd, false);

        sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j ACCEPT",
                IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, pro, atoi(outmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1);
        systemCmd(chcmd, false);
    }
    sem_post(g_iptables_lock);

    /* 清理连接追踪, 注意顺序, 开始 */

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport '%s' ", CONNTRACK, m_inneroutip, pro, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport '%s' ", CONNTRACK, m_gapinip, pro, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_inneroutip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_gapinip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_innerinip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_gapoutip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    /* 清理连接追踪, 注意顺序, 结束 */

    //systemCmd(SIP_CLEAN_TRACK, true);
    //systemCmd(SIP_CLEAN_TRACK, false);
}

/**
 * [CSipInterConnect::handelOutToInChannel 开通外网/下级->内网/上级通道]
 * @param  chanid     [通道ID]
 * @param  oper       [“I”或“D”]
 * @param  pro        [UDP或TCP]
 * @param  inmsport   [内网侧平台媒体流端口]
 * @param  outmsport  [外网侧平台媒体流端口]
 */
void CSipInterConnect::handelOutToInChannel(int chanid, char oper, const char *pro,
        const char *inmsport, const char *outmsport)
{
    char chcmd[CMD_BUF_LEN];

    sem_wait(g_iptables_lock);
    //outnet -> innet
    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, pro, outmsport,
            m_pchannel[chanid].proxyport, m_inneroutip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, pro, atoi(outmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_inneroutip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j DNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_gapoutip, pro, outmsport,
            m_pchannel[chanid].proxyport, m_innerinip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s'",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_gapoutip, pro, atoi(outmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_innerinip);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s' -p '%s' --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_innerinip, pro, outmsport,
            m_pchannel[chanid].proxyport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s' -p '%s' --sport %d --dport %d -j ACCEPT",
            IPTABLES, oper, m_pchannel[chanid].outmsip, m_gapoutip, pro, atoi(outmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    if (needDealFactory()) {
        sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s':%d",
                IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, atoi(inmsport) + 1,
                atoi(outmsport) + 1, m_gapoutip, atoi(m_pchannel[chanid].proxyport) + 1);
        systemCmd(chcmd, false);

        sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s':%d",
                IPTABLES, oper, m_innerinip, m_inneroutip, pro, atoi(inmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_pchannel[chanid].outmsip, atoi(outmsport) + 1);
        systemCmd(chcmd, false);

        sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s' -p '%s' --sport %d --dport %d -j ACCEPT",
                IPTABLES, oper, m_innerinip, m_pchannel[chanid].outmsip, pro, atoi(inmsport) + 1,
                atoi(outmsport) + 1);
        systemCmd(chcmd, false);
    }

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j SNAT --to '%s':'%s'",
            IPTABLES, oper, m_inneroutip, m_pchannel[chanid].inmsip, pro, outmsport,
            inmsport, m_gapinip, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s':%d",
            IPTABLES, oper, m_inneroutip, m_pchannel[chanid].inmsip, pro, atoi(outmsport) + 1,
            atoi(inmsport) + 1, m_gapinip, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport '%s' --dport '%s' -j DNAT --to '%s':'%s'",
            IPTABLES, oper, m_inneroutip, m_innerinip, pro, outmsport, m_pchannel[chanid].proxyport,
            m_pchannel[chanid].inmsip, inmsport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s':%d",
            IPTABLES, oper, m_inneroutip, m_innerinip, pro, atoi(outmsport) + 1,
            atoi(m_pchannel[chanid].proxyport) + 1, m_pchannel[chanid].inmsip, atoi(inmsport) + 1);
    systemCmd(chcmd, true);

    /* FORWARD 链在inStart()已开通 */

    if (needDealFactory()) {
        sprintf(chcmd, "%s -t nat -%c POSTROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j SNAT --to '%s'",
                IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, atoi(inmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_innerinip);
        systemCmd(chcmd, true);

        sprintf(chcmd, "%s -t nat -%c PREROUTING -s '%s' -d '%s'  -p '%s' --sport %d --dport %d -j DNAT --to '%s'",
                IPTABLES, oper, m_pchannel[chanid].inmsip, m_gapinip, pro, atoi(inmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1, m_inneroutip);
        systemCmd(chcmd, true);

        sprintf(chcmd, "%s -%c FORWARD -s '%s' -d '%s' -p '%s' --sport %d --dport %d -j ACCEPT",
                IPTABLES, oper, m_pchannel[chanid].inmsip, m_inneroutip, pro, atoi(inmsport) + 1,
                atoi(m_pchannel[chanid].proxyport) + 1);
        systemCmd(chcmd, true);
    }


    /* 清理连接追踪, 注意顺序, 开始 */

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport '%s' ", CONNTRACK, m_innerinip, pro, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport '%s' ", CONNTRACK, m_gapoutip, pro, m_pchannel[chanid].proxyport);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_innerinip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_gapoutip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_inneroutip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, false);

    sprintf(chcmd, "%s -D -d '%s' -p '%s' --dport %d ", CONNTRACK, m_gapinip, pro, atoi(m_pchannel[chanid].proxyport) + 1);
    systemCmd(chcmd, true);

    /* 清理连接追踪, 注意顺序, 结束 */

    sem_post(g_iptables_lock);
    //systemCmd(SIP_CLEAN_TRACK, true);
    //systemCmd(SIP_CLEAN_TRACK, false);
}

/**
 * [CSipInterConnect::handelChannel 处理通道规则]
 * @param  chanid     [通道ID]
 * @param  isadd      [是否为添加]
 * @param  is_udp     [是否为UDP]
 * @param  inmsport   [内网侧平台媒体流端口]
 * @param  outmsport  [外网侧平台媒体流端口]
 * @return        [成功返回0 失败返回负值]
 */
int CSipInterConnect::handelChannel(int chanid, bool isadd, bool is_udp,
                                    const char *inmsport, const char *outmsport)
{
    char oper = isadd ? 'I' : 'D';
    const char *pro = is_udp ? "udp" : "tcp";

    PRINT_DBG_HEAD
    print_dbg("channel oper over [%c][pro = %s, area = %d, transfer = %d]", oper, pro,
              m_pchannel[chanid].area, m_pchannel[chanid].transfer);


    if (is_udp) {
        if (false == m_pchannel[chanid].area) {
            handelOutToInChannel(chanid, oper, pro, inmsport, outmsport);
        } else {
            handelInToOutChannel(chanid, oper, pro, inmsport, outmsport);
        }
    } else {
        if (false == m_pchannel[chanid].area) {
            if (m_pchannel[chanid].transfer) {
                handelOutToInChannel(chanid, oper, pro, inmsport, outmsport);
            } else {
                handelInToOutChannel(chanid, oper, pro, inmsport, outmsport);
            }
        } else {
            if (m_pchannel[chanid].transfer) {
                handelInToOutChannel(chanid, oper, pro, inmsport, outmsport);
            } else {
                handelOutToInChannel(chanid, oper, pro, inmsport, outmsport);
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("channel oper over [%c][%s,%s:%s,%s:%s,%s]", oper, m_pchannel[chanid].callid,
              m_pchannel[chanid].inmsip, inmsport, m_pchannel[chanid].outmsip,
              outmsport, m_pchannel[chanid].proxyport);
    return 0;

}

/**
 * [CSipInterConnect::channelOper 通道操作]
 * @param  chanid [通道ID]
 * @param  isadd  [是否为添加]
 * @return        [成功返回0 失败返回负值]
 */
int CSipInterConnect::channelOper(int chanid, bool isadd)
{
    if (SIP_VIDEO_AND_AUDIO_PORT == m_pchannel[chanid].port_flag) {
        if (IS_STR_EMPTY(m_pchannel[chanid].in_audioport)
            || IS_STR_EMPTY(m_pchannel[chanid].in_videoport)
            || IS_STR_EMPTY(m_pchannel[chanid].out_audioport)
            || IS_STR_EMPTY(m_pchannel[chanid].out_videoport)) {
            PRINT_ERR_HEAD
            print_err("channel error[%s,%s,%s,%s,%s]", m_pchannel[chanid].in_audioport,
                      m_pchannel[chanid].in_videoport, m_pchannel[chanid].out_audioport,
                      m_pchannel[chanid].out_videoport, m_pchannel[chanid].proxyport);
            return -1;
        } else {
            if ((strcmp(m_pchannel[chanid].in_audioport, m_pchannel[chanid].in_videoport) == 0) &&
                (strcmp(m_pchannel[chanid].out_audioport, m_pchannel[chanid].out_videoport) == 0)) {
                handelChannel(chanid, isadd, m_pchannel[chanid].is_udp, m_pchannel[chanid].in_audioport,
                              m_pchannel[chanid].out_audioport);
            } else {
                handelChannel(chanid, isadd, m_pchannel[chanid].is_udp, m_pchannel[chanid].in_audioport,
                              m_pchannel[chanid].out_audioport);
                handelChannel(chanid, isadd, m_pchannel[chanid].is_udp, m_pchannel[chanid].in_videoport,
                              m_pchannel[chanid].out_videoport);
            }
        }
    } else if (SIP_VIDEO_PORT == m_pchannel[chanid].port_flag) {
        if (IS_STR_EMPTY(m_pchannel[chanid].in_videoport) || IS_STR_EMPTY(m_pchannel[chanid].out_videoport)) {
            PRINT_ERR_HEAD
            print_err("channel error[%s,%s,%s]", m_pchannel[chanid].in_videoport,
                      m_pchannel[chanid].out_videoport, m_pchannel[chanid].proxyport);
            return -1;
        } else {
            handelChannel(chanid, isadd, m_pchannel[chanid].is_udp, m_pchannel[chanid].in_videoport,
                          m_pchannel[chanid].out_videoport);
        }
    } else if (SIP_AUDIO_PORT == m_pchannel[chanid].port_flag) {
        if (IS_STR_EMPTY(m_pchannel[chanid].in_audioport) || IS_STR_EMPTY(m_pchannel[chanid].out_audioport)) {
            PRINT_ERR_HEAD
            print_err("channel error[%s,%s,%s]", m_pchannel[chanid].in_audioport,
                      m_pchannel[chanid].out_audioport, m_pchannel[chanid].proxyport);
            return -1;
        } else {
            handelChannel(chanid, isadd, m_pchannel[chanid].is_udp, m_pchannel[chanid].in_audioport,
                          m_pchannel[chanid].out_audioport);
        }
    }

    return 0;
}

/**
 * [CSipInterConnect::deleteChannelByCallID 根据会话ID清除一条通道]
 * @param callid [会话ID]
 */
void CSipInterConnect::deleteChannelByCallID(const char *callid)
{
    PRINT_DBG_HEAD
    print_dbg("delete channel by callid[%s]", callid);

    if (NULL == callid) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    lock();
    for (int i = 0; i < m_max_channel; i++) {
#if 0
        //此操作会导致半连接状态的通道被清空，从而导致响应包中媒体流端口替换为空
        if (0 == m_pchannel[i].activetime) {
            resetOneChannel(i);
        }
#endif
        if (NULL == m_pchannel[i].callid) {
            continue;
        }
        if (strcmp(callid, m_pchannel[i].callid) == 0) {
            delOneChannel(i);
            resetOneChannel(i);
            PRINT_INFO_HEAD
            print_info("del channel by callid ok[%d:%s]", i, callid);
            break;
        }
    }
    unlock();
    PRINT_DBG_HEAD
    print_dbg("delete channel by callid[%s] over", callid);
}

/**
 * [CSipInterConnect::dstVideoPrepare 网闸靠近平台的一端，视频流通道准备]
 */
void CSipInterConnect::dstVideoPrepare()
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -t nat -I PREROUTING -d '%s' -p udp --dport %d:%d -j DNAT --to '%s'",
            IPTABLES, m_gapoutip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2, m_innerinip);
    systemCmd(chcmd);


    sprintf(chcmd, "%s -I FORWARD -d '%s' -p udp --dport %d:%d -j ACCEPT",
            IPTABLES, m_innerinip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2);
    systemCmd(chcmd);


    sprintf(chcmd, "%s -t nat -I POSTROUTING -d '%s' -p udp --dport %d:%d -j SNAT --to '%s'",
            IPTABLES, m_innerinip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -d '%s' -p tcp --dport %d:%d -j DNAT --to '%s'",
            IPTABLES, m_gapoutip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2, m_innerinip);
    systemCmd(chcmd);


    sprintf(chcmd, "%s -I FORWARD -d '%s' -p tcp --dport %d:%d -j ACCEPT",
            IPTABLES, m_innerinip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2);
    systemCmd(chcmd);


    sprintf(chcmd, "%s -t nat -I POSTROUTING -d '%s' -p tcp --dport %d:%d -j SNAT --to '%s'",
            IPTABLES, m_innerinip, SIP_INTER_CONNECT_PORT_START,
            SIP_INTER_CONNECT_PORT_START + (m_max_channel - 1) * 2, m_inneroutip);
    systemCmd(chcmd);
}

/**
 * [CSipInterConnect::initLock 初始化锁]
 */
void CSipInterConnect::initLock(void)
{
    if (sem_init(&m_lock, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init lock fail");
    }
}

/**
 * [CSipInterConnect::destroyLock 摧毁锁]
 */
void CSipInterConnect::destroyLock(void)
{
    sem_destroy(&m_lock);
}

/**
 * [CSipInterConnect::lock 加锁]
 */
void CSipInterConnect::lock(void)
{
    sem_wait(&m_lock);
}

/**
 * [CSipInterConnect::unlock 解锁]
 */
void CSipInterConnect::unlock(void)
{
    sem_post(&m_lock);
}

