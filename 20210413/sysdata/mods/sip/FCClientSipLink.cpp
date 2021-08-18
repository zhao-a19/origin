/*******************************************************************************************
*文件: FCClientSipLink.cpp
*描述: 视频代理联动
*作者: 王君雷
*日期: 2018-04-12
*修改:
*         编码实现视频代理联动                                          ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*         改变portAble函数中遍历vector的方法，v8上使用find总报错        ------>   2018-07-19
*         联调测试修改错误：NodeCmdNat执行位置错误                      ------>   2018-07-23
*         联调测试修改通道分配中的设计错误;getOneNode返回值错误;
*         zlog日志更详细                                                ------>   2018-07-24
*         MY_BZERO、MY_DELETE等宏改名,去掉前面的MY_                     ------>   2018-08-05
*         解决获取视频时复用端口导致不通问题                            ------>   2019-09-06 --dzj
*******************************************************************************************/
#include "FCClientSipLink.h"
#include "debugout.h"
#include "FCSysRulesBS.h"
#include "FCFgapCmd.h"
#include "FCPeerExecuteCMD.h"
#include "common.h"

CClientSipLink::CClientSipLink(int i): CClientSipBase(i)
{
    BZERO(m_node);
    m_nodenum = 0;
    m_totalw = 0;
    m_lastpos = 0;
    m_warray = NULL;
    m_maxchannel = 0;
    m_exceptport.clear();
}

CClientSipLink::~CClientSipLink()
{
    DELETE_N(m_node, m_nodenum);
    DELETE(m_warray);
}

/**
 * [CClientSipLink::initChannel 通道初始化]
 */
void CClientSipLink::initChannel()
{
    if (m_nodenum > 0) {
        for (int i = 0; i < m_nodenum; i++) {
            while ((m_node[i]->pchannel = new MediaChannel[m_maxchannel]) == NULL) {
                PRINT_ERR_HEAD
                print_err("nodeid[%d] m_maxchannel[%d] new channel fail, retry...", i, m_maxchannel);
                sleep(1);
            }
            memset(m_node[i]->pchannel, 0, sizeof(MediaChannel) * m_maxchannel);
            for (int j = 0; j < m_maxchannel; j++) {
                sprintf(m_node[i]->pchannel[j].myport, "%d",
                        SIP_LINK_PORT_OFFSET + SIP_LINK_TOTAL_CHANNEL
                        + m_taskno * m_maxchannel * 2 + j * 2);
                m_node[i]->pchannel[j].able = portAble(atoi(m_node[i]->pchannel[j].myport));
            }
        }
        initWeight();
    }
}

/**
 * [CClientSipLink::portAble 判断端口是否可用]
 * @param  port [端口]
 * @return      [可用就返回true]
 */
bool CClientSipLink::portAble(int port)
{
    bool bflag = true;
    vector<int>::iterator it;
    for (it = m_exceptport.begin(); it != m_exceptport.end(); it++) {
        if ((*it == port) || (*it == port + 1)) {
            bflag = false;
            PRINT_INFO_HEAD
            print_info("port[%d] sip link disable", port);
            break;
        }
    }

    return bflag;
}

/**
 * [CClientSipLink::getOneChannelID 获取一个可用的通道下标ID号]
 * @param  mrecvip   [媒体流接收者IP]
 * @param  mrecvport [媒体流接收者端口]
 * @param  find      [是否已经出现过]
 * @param  callid    [会话ID]
 * @param  nodeid    [节点ID]
 * @return           [通道下标  出错返回负值]
 */
int CClientSipLink::getOneChannelID(const char *mrecvip, const char *mrecvport,
                                    int &find, const char *callid, int &nodeid)
{
    PRINT_DBG_HEAD
    print_dbg("get one channel id begin[%s:%s:%s]", callid, mrecvip, mrecvport);

    int id = -1;

    if (strcmp(callid, "") == 0) {
        PRINT_ERR_HEAD
        print_err("callid is empty");
        goto _out;
    }

    for (int k = 0; k < m_nodenum; k++) {
        for (int i = 0; i < m_maxchannel; ++i) {
            if (strcmp(callid, m_node[k]->pchannel[i].callid) == 0) {
                if ((strcmp("", m_node[k]->pchannel[i].media_recvip) == 0)
                    && (strcmp("", m_node[k]->pchannel[i].media_recvport) == 0)) {

                } else if ((strcmp(mrecvip, m_node[k]->pchannel[i].media_recvip) != 0)
                           || (strcmp(mrecvport, m_node[k]->pchannel[i].media_recvport) != 0)) {

                    PRINT_ERR_HEAD
                    print_err("The same callid[%s] is used in different sessions,[%s:%s][%s:%s]",
                              callid, mrecvip, mrecvport, m_node[k]->pchannel[i].media_recvip,
                              m_node[k]->pchannel[i].media_recvport);

                    delOneChannel(k, i);
                } else if (SIP_TIME_OUT(time(NULL) - m_node[k]->pchannel[i].tm)) {

                    delOneChannel(k, i);
                } else {

                    find = 1;
                }

                strcpy(m_node[k]->pchannel[i].media_recvip, mrecvip);
                strcpy(m_node[k]->pchannel[i].media_recvport, mrecvport);
                m_node[k]->pchannel[i].tm = time(NULL);
                nodeid = k;
                id = i;
                goto _out;
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("cannot find callid[%s]", callid);

_out:
    PRINT_DBG_HEAD
    print_dbg("get one channel id over nodeid[%d] chanid[%d]", nodeid, id);
    return id;
}

/**
 * [CClientSipLink::delOneChannel 删除一个流媒体通道]
 * @param nodeid [节点ID]
 * @param chnid  [通道ID]
 */
void CClientSipLink::delOneChannel(int nodeid, int chanid)
{
    int ret = RESULT_OK;
    CFgapCmd fgap(m_node[nodeid]->natip,
                  m_node[nodeid]->natport);

    if ((strcmp(m_node[nodeid]->pchannel[chanid].media_recvip, "") == 0)
        || (strcmp(m_node[nodeid]->pchannel[chanid].media_recvport, "") == 0)) {
        return;
    }

    ret = fgap.Del(m_name,
                   m_node[nodeid]->comeip,
                   m_node[nodeid]->goip,
                   m_node[nodeid]->pchannel[chanid].myport,
                   m_node[nodeid]->pchannel[chanid].media_recvip,
                   m_node[nodeid]->pchannel[chanid].media_recvport);
    if (ret != RESULT_OK) {
        PRINT_ERR_HEAD
        print_err("del channel ret[%d],rname[%s],comeip[%s],goip[%s],myport[%s],rip[%s],rport[%s]",
                  ret, m_name,
                  m_node[nodeid]->comeip,
                  m_node[nodeid]->goip,
                  m_node[nodeid]->pchannel[chanid].myport,
                  m_node[nodeid]->pchannel[chanid].media_recvip,
                  m_node[nodeid]->pchannel[chanid].media_recvport);
    }
}

/**
 * [CClientSipLink::addOneChannel 添加一个流媒体通道]
 * @param nodeid [节点ID]
 * @param chanid [通道ID]
 */
void CClientSipLink::addOneChannel(int nodeid, int chanid)
{
    int ret = RESULT_OK;
    CFgapCmd fgap(m_node[nodeid]->natip,
                  m_node[nodeid]->natport);

    ret = fgap.Add(m_name,
                   m_node[nodeid]->comeip,
                   m_node[nodeid]->goip,
                   m_node[nodeid]->pchannel[chanid].myport,
                   m_node[nodeid]->pchannel[chanid].media_recvip,
                   m_node[nodeid]->pchannel[chanid].media_recvport);
    if (ret != RESULT_OK) {

        char chcmd[CMD_BUF_LEN] = {0};
        sprintf(chcmd, "%s[%s][%s]%d",
                m_name, m_node[nodeid]->comeip, m_node[nodeid]->goip, ret);
        recordSysLog(LOG_TYPE_LINK_NODE_CHECK, D_FAIL, chcmd);

        PRINT_ERR_HEAD
        print_err("add channel ret[%d],rname[%s],comeip[%s],goip[%s],myport[%s],rip[%s],rport[%s]",
                  ret, m_name,
                  m_node[nodeid]->comeip,
                  m_node[nodeid]->goip,
                  m_node[nodeid]->pchannel[chanid].myport,
                  m_node[nodeid]->pchannel[chanid].media_recvip,
                  m_node[nodeid]->pchannel[chanid].media_recvport);
        m_node[nodeid]->online = false;
    }
}

/**
 * [CClientSipLink::getChannelProxyPort 获取媒体流通道接收端口号]
 * @param nodeid [节点ID]
 * @param chanid [通道ID]
 * @return    [成功返回端口号，失败返回NULL]
 */
const char *CClientSipLink::getChannelProxyPort(int nodeid, int chanid)
{
    if ((nodeid < 0) || (nodeid >= m_nodenum)) {
        PRINT_ERR_HEAD
        print_err("nodeid[%d] err, m_nodenum[%d]", nodeid, m_nodenum);
        return NULL;
    }

    if ((chanid < 0) || (chanid >= m_maxchannel)) {
        PRINT_ERR_HEAD
        print_err("chanid[%d] err, m_maxchannel[%d]", chanid, m_maxchannel);
        return NULL;
    }

    return m_node[nodeid]->pchannel[chanid].myport;
}

/**
 * [CClientSipLink::getChannelProxyIP 获取节点接收视频流的IP]
 * @param  callid [会话ID]
 * @return        [地址指针]
 */
const char *CClientSipLink::getChannelProxyIP(const char *callid)
{
    PRINT_DBG_HEAD
    print_dbg("get channel proxy ip begin[%s]", callid);

    if (strcmp(callid, "") == 0) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    char *pyip = NULL;
    int earlychanid = -1;//记录使用时间最早的通道ID
    int onenode = 0;
    int use_chanid = -1;

    //当前通道中有该会话ID
    for (int nodeid = 0; nodeid < m_nodenum; ++nodeid) {
        for (int chanid = 0; chanid < m_maxchannel; ++chanid) {
            if (strcmp(m_node[nodeid]->pchannel[chanid].callid, callid) == 0) {
                if (nodeTest(nodeid)) {
                    if ('\0' == m_node[nodeid]->pchannel[chanid].media_recvport[0]) {
                        pyip = m_node[nodeid]->comeip;
                        goto _out;
                    }
                    pyip = m_node[nodeid]->comeip;
                    delOneChannel(nodeid, chanid);
                    resetOneChannel(nodeid, chanid);
                    use_chanid = chanid;
                } else {
                    //说明使用过该会话ID的节点不在线了
                    resetOneChannel(nodeid, chanid);
                }
            }
        }
    }

    onenode = getOneNode();

    //查找空闲的 同时记录下最早插入的那条
    for (int i = 0; i < m_maxchannel; i++) {
        if (m_node[onenode]->pchannel[i].able) {
            if (strcmp("", m_node[onenode]->pchannel[i].callid) == 0) {
                if (use_chanid < i) {
                    strcpy(m_node[onenode]->pchannel[i].callid, callid);
                    pyip = m_node[onenode]->comeip;
                    goto _out;
                }
            } else {
                if (earlychanid < 0) {
                    earlychanid = i;
                } else if (m_node[onenode]->pchannel[i].tm <
                           m_node[onenode]->pchannel[earlychanid].tm) {
                    earlychanid = i;
                }
            }
        }
    }

    //复用最早的通道
    if (earlychanid >= 0) {
        delOneChannel(onenode, earlychanid);
        resetOneChannel(onenode, earlychanid);
        strcpy(m_node[onenode]->pchannel[earlychanid].callid, callid);
        pyip = m_node[onenode]->comeip;
    }
_out:
    PRINT_DBG_HEAD
    print_dbg("get channel proxy ip over[%s]", pyip);
    return pyip;
}

/**
 * [CClientSipLink::getChannelOutIP 获取节点发送视频流的IP]
 * @param  callid [会话ID]
 * @return        [地址指针]
 */
const char *CClientSipLink::getChannelOutIP(const char *callid)
{
    PRINT_DBG_HEAD
    print_dbg("get channel out ip begin[%s]", callid);
    char *outip = NULL;
    if (strcmp(callid, "") == 0) {
        PRINT_ERR_HEAD
        print_err("para null");
        goto _out;
    }

    for (int nodeid = 0; nodeid < m_nodenum; nodeid++) {
        for (int chanid = 0; chanid < m_maxchannel; chanid++) {
            if (strcmp(m_node[nodeid]->pchannel[chanid].callid, callid) == 0) {
                outip = m_node[nodeid]->goip;
                goto _out;
            }
        }
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("get channel out ip over[%s]", outip);
    return outip;
}

/**
 * [CClientSipLink::srcStart 网闸靠近客户端的一端启动函数]
 * @return [成功返回0]
 */
int CClientSipLink::srcStart()
{
    return CClientSipBase::srcStart();
}

/**
 * [CClientSipLink::dstStart 网闸靠近平台的一端启动函数]
 * @return [成功返回0]
 */
int CClientSipLink::dstStart()
{
    CClientSipBase::dstStart();
    nodeCmdNat();
    return 0;
}

const char *CClientSipLink::getTypeDesc()
{
    return LOG_TYPE_CLIENT_SIP_LINK;
}

/**
 * [CClientSipLink::delChannelByCallID 通过会话ID清除一条视频流通道]
 * @param callid [会话ID]
 */
void CClientSipLink::delChannelByCallID(const char *callid)
{
    PRINT_DBG_HEAD
    print_dbg("del channel by callid begin[%s]", callid);

    for (int nodeid = 0; nodeid < m_nodenum; nodeid++) {
        for (int chanid = 0; chanid < m_maxchannel; chanid++) {
            if (strcmp(callid, m_node[nodeid]->pchannel[chanid].callid) == 0) {
                delOneChannel(nodeid, chanid);
                resetOneChannel(nodeid, chanid);

                PRINT_DBG_HEAD
                print_dbg("del node[%d]channel[%d]", nodeid, chanid);

                goto _out;
            }
        }
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("del channel by callid over");
}

/**
 * [CClientSipLink::设置转发节点调度命令使用的内部nat]
 * 分析处理SIP的逻辑在网闸靠近客户端的一侧，而调度服务启动在节点靠近平台的一侧
 * 所以，需要网闸内部nat跳转一下
 */
void CClientSipLink::nodeCmdNat()
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_DBG_HEAD
    print_dbg("node cmd nat begin...");

    for (int i = 0; i < m_nodenum; ++i) {
        sprintf(chcmd, "%s -t nat -I PREROUTING -d %s -p tcp --dport %d -j DNAT --to %s:%d",
                IPTABLES, m_node[i]->natip, m_node[i]->natport, m_node[i]->comeip,
                m_node[i]->cmdport);
        system(chcmd);
    }

    PRINT_DBG_HEAD
    print_dbg("node cmd nat end");
}

/**
 * [CClientSipLink::nodeTest 测试节点是否在线]
 * @param  nodeid [节点ID]
 * @return        [在线返回true]
 */
bool CClientSipLink::nodeTest(int nodeid)
{
    //超时 才重新检测在线状态
    if (SIP_TIME_OUT(time(NULL) - m_node[nodeid]->testtm)) {
        CFgapCmd fgap(m_node[nodeid]->natip, m_node[nodeid]->natport);
        bool bflag = (fgap.Online() == RESULT_OK);
        m_node[nodeid]->testtm = time(NULL);

        if (bflag != m_node[nodeid]->online) {
            char chcmd[CMD_BUF_LEN] = {0};
            sprintf(chcmd, "%s[%s][%s]", m_name, m_node[nodeid]->comeip, m_node[nodeid]->goip);
            recordSysLog(LOG_TYPE_LINK_NODE_CHECK, bflag ? D_SUCCESS : D_FAIL, chcmd);
        }
        m_node[nodeid]->online = bflag;

    } else {

    }

    return m_node[nodeid]->online;
}

/**
 * [CClientSipLink::initWeight 权重初始化]
 */
void CClientSipLink::initWeight()
{
    PRINT_DBG_HEAD
    print_dbg("int weight begin");
    int n = 0;
    m_totalw = 0;
    for (int i = 0; i < m_nodenum; ++i) {
        m_totalw += SIP_NODE_WEIGHT_EXPRESS(m_node[i]->weight);
    }

    m_warray = new int[m_totalw];
    if (m_warray == NULL) {
        PRINT_ERR_HEAD
        print_err("m_warray new fail");
        return;
    }

    for (int i = 0; i < m_nodenum; ++i) {
        for (int j = 0; j < SIP_NODE_WEIGHT_EXPRESS(m_node[i]->weight); ++j) {
            m_warray[n++] = i;
        }
    }

    //打乱数组顺序
    CCommon comm;
    comm.UnSortArray(m_warray, m_totalw);

    //查看打乱结果
    for (int i = 0; i < m_totalw; i++) {
        PRINT_DBG_HEAD
        print_dbg("m_warray[%d] = [%d]", i, m_warray[i]);
    }
    PRINT_DBG_HEAD
    print_dbg("int weight over, totalw[%d]", m_totalw);
}

/**
 * [CClientSipLink::getOneNode 按权重 选择一个节点]
 * @return [节点ID]
 */
int CClientSipLink::getOneNode()
{
    PRINT_DBG_HEAD
    print_dbg("get one node begin");
    if ((m_warray == NULL) || (m_totalw <= 0)) {
        PRINT_ERR_HEAD
        print_err("totalw[%d], cannot distribute", m_totalw);
        return 0;
    }

    while (1) {
        m_lastpos %= m_totalw;

        if (nodeTest(m_warray[m_lastpos])) {
            m_lastpos++;
            goto _out;
        } else {
            m_lastpos++;
        }
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("get one node over pos[%d] node[%d]", m_lastpos - 1, m_warray[m_lastpos - 1]);

    return m_warray[m_lastpos - 1];
}

/**
 * [CClientSipLink::resetOneChannel 重置一个通道]
 * @param nodeid [节点ID]
 * @param chanid [通道ID]
 */
void CClientSipLink::resetOneChannel(int nodeid, int chanid)
{
    if ((nodeid >= 0) && (nodeid < m_nodenum)) {
        if ((chanid >= 0) && (chanid < m_maxchannel)) {
            BZERO(m_node[nodeid]->pchannel[chanid].callid);
            BZERO(m_node[nodeid]->pchannel[chanid].media_recvip);
            BZERO(m_node[nodeid]->pchannel[chanid].media_recvport);
            m_node[nodeid]->pchannel[chanid].tm = 0;
        }
    }
}
