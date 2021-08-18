/*******************************************************************************************
*文件: SipInterConnectBase.cpp
*描述: 平台互联 基类
*作者: dzj
*日期: 2019-07-05
*修改:
*        修改输出log的接口的无参数的问题                                  ------> 2019-08-01
*        修改平台级联和视频代理sip的iptables                              ------> 2019-08-03
*        修改平台级联sip的iptables
*        为平台级联区分上下级时添加替换接口
*        修改记录平台级联和视频代理日志                                   ------> 2019-08-07
*        支持视频代理
*        添加级联和代理设置媒体流靠近下级的iptables接口                   ------> 2019-08-14
*        修改SIP的FROM和TO字段替换IP接口，添加break；                     ------> 2019-08-20
*        配合界面修改后，这里的IP和port不再需要替换；                     ------> 2019-08-28
*        修改SIP报文结尾无'\n'造成的报文内容丢失无法共享点位问题          ------> 2019-09-28
*        解决IPTABLES问题和SIP一行无'\r'结尾的问题                        ------> 2019-10-16
*        解决传输媒体流时每次都使用同一端口问题                           ------> 2019-11-21
*        解决SIP替换时出现替换不是SDP消息的问题                           ------> 2019-12-03
*        修改找不到"r\n\r\n"时异常处理方法                                ------> 2019-12-05
*        修改编译警告                                                     ------> 2019-12-09-dzj
*        不再串行记录访问日志                                             ------> 2020-01-07-wjl
*        访问日志支持记录MAC字段,暂设置为空                               ------> 2020-01-16 wjl
*        可以识别NOTIFY信令，暂时没有处理它                               ------> 2020-06-11
*        修改回填content-length时(NULL != p)错写为(NULL != 0)的BUG       ------> 2020-08-16 wjl
*        兼容配置文件中Protocol为SIP和GB28181两种情况                     ------> 2020-08-18 wjl
*        解决TCP传输SIP时，connect失败忘记关闭描述符的BUG;
*        使用select处理TCP连接                                           ------> 2020-11-30
*        平台级联，替换下级发出的NOTIFY行中的IP为上级IP,
*        解决新增摄像头，上级看不到的问题。（海康合作发现）              ------> 2020-12-18 ll
********************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "FCBSTX.h"
#include "define.h"
#include "debugout.h"
#include "fileoperator.h"
#include "readcfg.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "FCPeerExecuteCMD.h"
#include "SipInterConnectBase.h"

CSipInterConnectBase::CSipInterConnectBase(int taskid)
{
    m_taskid = taskid;
    BZERO(m_cmd);
    m_inbrandid = ID_OTHERBRAND;
    m_outbrandid = ID_OTHERBRAND;
    m_defaultaction = false;
    m_via = true;
    m_from = true;
    m_to = true;
    m_mode = 0;
    m_area = 0;
}

CSipInterConnectBase::~CSipInterConnectBase(void)
{
    DELETE_N(m_cmd, C_MAX_CMD);
}

/**
 * [CSipInterConnectBase::loadConf 加载配置信息]
 * @param  filename   [文件名称]
 * @return            [成功返回true]
 */
bool CSipInterConnectBase::loadConf(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("load conf begin");

    int tmpint = 0;
    bool bflag = false;
    char taskid[SIP_CONF_KEY_NAME_LEN] = {0};
    char subitem[SIP_CONF_KEY_NAME_LEN] = {0};
    CCommon common;
    int indev = -1;
    int outdev = -1;
    CFILEOP fileop;

    if (fileop.OpenFile(filename, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", filename);
        goto _out;
    }

    sprintf(taskid, "Task%d", m_taskid);
    READ_STRING(fileop, taskid, "Name", m_name, true, _out);
    common.DelChar(m_name, '\'');
    READ_INT(fileop, taskid, "Mode", m_mode, true, _out);
    READ_INT(fileop, taskid, "Area", m_area, true, _out);
    READ_INT(fileop, taskid, "InDev", indev, true, _out);
    READ_INT(fileop, taskid, "OutDev", outdev, true, _out);
    m_secway.setway("", 0, indev, outdev);
    READ_STRING(fileop, taskid, "GapInIP", m_gapinip, true, _out);
    READ_STRING(fileop, taskid, "GapOutIP", m_gapoutip, true, _out);
    READ_STRING(fileop, taskid, "InCenter", m_incenter, true, _out);
    READ_STRING(fileop, taskid, "OutCenter", m_outcenter, true, _out);
    READ_STRING(fileop, taskid, "InPort", m_inport, true, _out);
    READ_STRING(fileop, taskid, "OutPort", m_outport, true, _out);
    READ_STRING(fileop, taskid, "Protocol", m_proto, true, _out);
    READ_INT(fileop, taskid, "InBrandID", m_inbrandid, true, _out);
    READ_INT(fileop, taskid, "OutBrandID", m_outbrandid, true, _out);
    tmpint = 1;
    READ_INT(fileop, taskid, "Via", tmpint, true, _out);
    m_via = (tmpint == 1);
    tmpint = 1;
    READ_INT(fileop, taskid, "From", tmpint, true, _out);
    m_from = (tmpint == 1);
    tmpint = 1;
    READ_INT(fileop, taskid, "To", tmpint, true, _out);
    m_to = (tmpint == 1);
    tmpint = 0;
    READ_INT(fileop, taskid, "DefCmdAction", tmpint, true, _out);
    m_defaultaction = (tmpint == 1);
    READ_INT(fileop, taskid, "CmdNum", m_cmdnum, true, _out);
    m_cmdnum = MIN(m_cmdnum , C_MAX_CMD);

    //读取各个命令
    for (int j = 0; j < m_cmdnum; j++) {
        m_cmd[j] = new CCMDCONF;
        if (m_cmd[j] == NULL) {
            PRINT_ERR_HEAD
            print_err("new cmd error %d", j);
            goto _out;
        }
        sprintf(subitem, "CmdName%d", j);
        READ_STRING(fileop, taskid, subitem, m_cmd[j]->m_cmd, true, _out);
        sprintf(subitem, "Param%d", j);
        READ_STRING(fileop, taskid, subitem, m_cmd[j]->m_parameter, false, _out);
        sprintf(subitem, "Permit%d", j);
        READ_INT(fileop, taskid, subitem, tmpint, true, _out);
        m_cmd[j]->m_action = (tmpint == 1);
    }

    bflag = true;
    showConf();

_out:
    fileop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("load conf over(%s)", bflag ? "ok" : "bad");

    return bflag;
}

/**
 * [CSipInterConnectBase::showConf 展示配置信息]
 */
void CSipInterConnectBase::showConf(void)
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

    for (int j = 0; j < m_cmdnum; j++) {
        PRINT_DBG_HEAD
        print_dbg("cmd[%s] para[%s] action[%s]",
                  m_cmd[j]->m_cmd, m_cmd[j]->m_parameter, m_cmd[j]->m_action ? "allow" : "forbid");
    }
}

/**
 * [CPDTBase::isProtoPSIP 是否为PSIP协议]
 * @return [是返回true]
 */
bool CSipInterConnectBase::isProtoSIP(void)
{
    return (strcmp(m_proto, "SIP") == 0)
           || (strcmp(m_proto, "GB28181") == 0);
}

const char *CSipInterConnectBase::getGapInIp(void)
{
    return m_gapinip;
}

const char *CSipInterConnectBase::getGapOutIp(void)
{
    return m_gapoutip;
}

int CSipInterConnectBase::getMode()
{
    return m_mode;
}

int CSipInterConnectBase::getArea()
{
    return m_area;
}

/**
 * [CSipBase::swapInfo 交换内网和外网的内容]
 */
void CSipInterConnectBase::swapInfo()
{
    char tmpip[IP_STR_LEN] = {0};
    strcpy(tmpip, m_gapinip);
    strcpy(m_gapinip, m_gapoutip);
    strcpy(m_gapoutip, tmpip);
}

/**
 * [CSipInterConnectBase::setInnerInIp 为m_innerinip赋值]
 * @param ip     [description]
 * @return       [成功返回true]
 */
bool CSipInterConnectBase::setInnerInIp(const char *ip)
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
 * [CSipInterConnectBase::setInnerOutIp 为m_inneroutip赋值]
 * @param ip     [description]
 * @return       [成功返回true]
 */
bool CSipInterConnectBase::setInnerOutIp(const char *ip)
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
 * [CSipInterConnectBase::getCmd 从命令行中取出命令]
 * @param  chcmd   [取出的命令 出参]
 * @param  cmdsize [命令缓冲区大小 入参]
 * @param  cmdline [可能包含命令的数据包 入参]
 * @return         [取命令成功返回true，否则返回false]
 */
bool CSipInterConnectBase::getCmd(char *chcmd, int cmdsize, const char *cmdline)
{
    //参数检查
    if ((chcmd == NULL) || (cmdline == NULL) || (cmdsize <= 4)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    //是回应
    char response[20] = "SIP/2.0";
    if (IS_TYPE_OF(cmdline, response)) {
        return false;
    }

    //xml行 没有命令
    if (cmdline[0] == '<') {
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
        PRINT_DBG_HEAD
        print_dbg("cmd[0] is not letter,cmd[%s]", chcmd);
        return false;
    }

    PRINT_INFO_HEAD
    print_info("find cmd[%s],pack len[%d]", chcmd, (int)strlen(cmdline));
    return true;
}

/**
 * [CSipInterConnectBase::filterSipCmd 过滤信令]
 * @param  chcmd      [信令]
 * @param  area       [0:内到外，1:外到内]
 * @return            [允许通过返回true]
 */
bool CSipInterConnectBase::filterSipCmd(const char *chcmd, int area)
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
    recordCallLog(chcmd, flag, area);
    return flag;
}


/**
 * [CSipInterConnectBase::recordCallLog 记录访问日志]
 * @param chcmd      [信令]
 * @param result     [是否放行]
 * @param  area      [0:内到外，1:外到内]
 */
void CSipInterConnectBase::recordCallLog(const char *chcmd, bool result, int area)
{
    if (g_iflog || g_syslog) {
        char mode[C_SIP_KEY_WORLD_LEN] = {0};
        if (SIP_FUN_INTERCONNECT_MODE == m_mode) {
            strcpy(mode, LOG_TYPE_SIP_INTERCONNECT);
        } else if (SIP_FUN_CASCADE_MODE == m_mode) {
            strcpy(mode, LOG_TYPE_SIP_NORM);
        } else if (SIP_FUN_PROXY_MODE == m_mode) {
            strcpy(mode, LOG_TYPE_CLIENT_SIP_NORM);
        }

        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues("",
                             (SIP_IN_CENTER == area) ? m_incenter : m_outcenter,
                             (SIP_IN_CENTER == area) ? m_outcenter : m_incenter,
                             (SIP_IN_CENTER == area) ? m_inport : m_outport,
                             (SIP_IN_CENTER == area) ? m_outport : m_inport,
                             "", "",
                             mode, chcmd, "",
                             result ? D_SUCCESS : D_REFUSE,
                             result ? "" : LOG_CONTENT_REFUSE)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[sip %s, dip %s, sport %s, dport %s, %s:%s]",
                          (SIP_IN_CENTER == area) ? m_incenter : m_outcenter,
                          (SIP_IN_CENTER == area) ? m_outcenter : m_incenter,
                          (SIP_IN_CENTER == area) ? m_inport : m_outport,
                          (SIP_IN_CENTER == area) ? m_outport : m_inport,
                          mode, chcmd);
                delete p;
            }
        }
    }
    return;
}

/**
 * [CSipInterConnectBase::findStrByKey 从字符串src偏移spos长度，
 * 查找字符ikey，然后把ikey之前查找到的字符存放到dst里]
 * @param  src  [被查找的字符串]
 * @param  dst  [存放查找出的字符串]
 * @param  spos [开始查找的偏移位置]
 * @param  ikey [分隔字符]
 * @return      [成功返回下一次查找时的偏移量，失败返回-1]
 */
int CSipInterConnectBase::findStrByKey(const char *src, char *dst, int spos, char ikey)
{
    int slen = strlen(src);

    for (int i = spos; i < slen; i++) {
        if ((i - spos) >= SIP_MAX_LINE_SIZE - 24) {

            PRINT_ERR_HEAD
            print_err("Line too long. More than max support size[%d]", SIP_MAX_LINE_SIZE - 24);
            break;
        }
        *dst++ = *(src + i);
        if (*(src + i) == ikey) {
            return i + 1;
        }
    }

    return -1;
}

/**
 * [CSipInterConnectBase::inStart
 * 对于互联是网闸内网侧启动
 * 对于级联是靠近上级平台的一侧启动
 * 对于视频代理是靠近客户端一侧启动]
 */
void CSipInterConnectBase::inStart(void)
{
    if (SIP_FUN_INTERCONNECT_MODE == m_mode) {
        setInterConnectInIptables();
    } else if (SIP_FUN_CASCADE_MODE == m_mode) {
        setCascadeInIptables();
    } else if (SIP_FUN_PROXY_MODE == m_mode) {
        setProxyInIptables();
        //登记表初始化
        BZERO(m_regtable);
        for (int i = 0; i < (int)ARRAY_SIZE(m_regtable); i++) {
            m_regtable[i].bindport = C_CLI_SIPDYNAMICPORT + i;
        }
    }

    //创建访问 m_tcpstate 时使用的信号量，当互斥锁用
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "%s%d", SIP_TCP_STATE_MUTEX_PATH, m_taskid);
    sem_unlink(chcmd);
    m_tcp_sem = sem_open(chcmd, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 1);
    if (m_tcp_sem == SEM_FAILED) {
        PRINT_ERR_HEAD
        print_err("sem_open error[%s]", strerror(errno));
    }
    memset(m_tcpstate, STATUS_FREE, sizeof(m_tcpstate));

    if (initChannel() < 0) {
        PRINT_ERR_HEAD
        print_err("init channel fail");
    } else {
        startTaskThreads();
    }
}

/**
 * [CSipInterConnectBase::outStart 网闸外网侧启动]
 * 外网侧只需要设置适当的iptables，处理逻辑在内网进行
 */
void CSipInterConnectBase::outStart(void)
{
    if (SIP_FUN_INTERCONNECT_MODE == m_mode) {
        setInterConnectOutIptables();
    } else if (SIP_FUN_CASCADE_MODE == m_mode) {
        setCascadeOutIptables();
        //dstVideoPrepare();
    } else if (SIP_FUN_PROXY_MODE == m_mode) {
        setProxyOutIptables();
        //dstVideoPrepare();
    }
}

/**
 * [CSipInterConnectBase::setInterConnectInIptables 设置互联内网侧iptables]
 */
void CSipInterConnectBase::setInterConnectInIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -I FORWARD -s '%s' -j ACCEPT", IPTABLES, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -A INPUT -p tcp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -d '%s' -p tcp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_inneroutip, m_outport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j SNAT --to '%s'", IPTABLES, m_inneroutip,
            m_gapinip);
    systemCmd(chcmd);
}

/**
 * [CSipInterConnectBase::setInterConnectOutIptables 设置互联外网侧iptables]
 */
void CSipInterConnectBase::setInterConnectOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_inport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_inport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport, m_inneroutip);
    systemCmd(chcmd);
}


/**
 * [CSipInterConnectBase::setCascadeInIptables 设置级联靠近上级平台一侧的iptables]
 */
void CSipInterConnectBase::setCascadeInIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -I FORWARD -s '%s' -j ACCEPT", IPTABLES, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport %s -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -A INPUT -p tcp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -d '%s' -p tcp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_inneroutip, m_outport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j SNAT --to '%s'", IPTABLES, m_inneroutip,
            m_gapinip);
    systemCmd(chcmd);
}

/**
 * [CSipInterConnectBase::setCascadeOutIptables 设置级联外网侧iptables]
 */
void CSipInterConnectBase::setCascadeOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_inport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_inport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, m_inport, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --sport '%s' --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inport, m_inneroutip);
    systemCmd(chcmd);

}


/**
 * [CSipInterConnectBase::setProxyInIptables 设置视频代理 靠近客户端一侧的iptables]
 */
void CSipInterConnectBase::setProxyInIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -I FORWARD -s '%s' -j ACCEPT", IPTABLES, m_inneroutip);
    systemCmd(chcmd);

    //源对象访问控制
    if (!ALL_OBJ(m_incenter)) {
        sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
                IPTABLES, m_gapinip, m_outport, m_incenter);
        systemCmd(chcmd);

        sprintf(chcmd, "%s -A INPUT -p tcp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
                IPTABLES, m_gapinip, m_outport, m_incenter);
        systemCmd(chcmd);
    }

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -d '%s' -p tcp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_inneroutip, m_outport, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j SNAT --to '%s'", IPTABLES, m_inneroutip,
            m_gapinip);
    systemCmd(chcmd);
}

/**
 * [CSipInterConnectBase::setProxyOutIptables 设置代理外网侧iptables]
 */
void CSipInterConnectBase::setProxyOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --sport %d:%d --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport %d:%d -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_outport, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport %d:%d --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p udp --sport '%s' --dport %d:%d -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport %d:%d --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p udp --sport '%s' --dport %d:%d -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, C_CLI_SIPDYNAMICPORT,
            C_CLI_SIPDYNAMICPORT + MAX_SIP_CLIENT - 1, m_inneroutip);
    systemCmd(chcmd);

    //tcp
    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j DNAT --to '%s'",
            IPTABLES, m_innerinip, m_inneroutip, m_outport, m_outcenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I PREROUTING -s '%s' -d '%s' -p tcp -j DNAT --to '%s'",
            IPTABLES, m_outcenter, m_gapoutip, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --dport '%s' -j ACCEPT",
            IPTABLES, m_innerinip, m_outcenter, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -I FORWARD -s '%s' -d '%s' -p tcp --sport '%s' -j ACCEPT",
            IPTABLES, m_outcenter, m_innerinip, m_outport);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --dport '%s' -j SNAT --to '%s'",
            IPTABLES, m_innerinip, m_outcenter, m_outport, m_gapoutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -d '%s' -p tcp --sport '%s' -j SNAT --to '%s'",
            IPTABLES, m_outcenter, m_innerinip, m_outport, m_inneroutip);
    systemCmd(chcmd);


}

/**
 * [CSipInterConnectBase::systemCmd system执行命令]
 * @param cmd  [命令]
 * @param self [本端执行，还是让对端执行]
 */
void CSipInterConnectBase::systemCmd(const char *cmd, bool self)
{
    PRINT_DBG_HEAD
    print_dbg("[%s]%s", self ? "self" : "peer", cmd);

    if (self) {
        system_safe(cmd);
    } else {
        PeerExecuteCMD(cmd);
    }
}

/**
 * [CSipInterConnectBase::createThread 创建启动一个线程]
 * @param  func  [线程函数]
 * @param  ptask [线程参数]
 * @return       [成功返回true]
 */
bool CSipInterConnectBase::createThread(threadfunc func, PSipInterConnectTASK ptask)
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
 * [CSipInterConnectBase::isResponse 是否为响应]
 * @param  line [数据包内容]
 * @return     [是返回true]
 */
bool CSipInterConnectBase::isResponse(const char *line)
{
    bool bflag = false;
    if (strncmp(line, "SIP/", strlen("SIP/")) == 0) {
        bflag = true;
    } else {
        if ((strlen(line) > 4) && (isdigit(line[0])) && (isdigit(line[1]))
            && (isdigit(line[2])) && (line[3] == '\r')) {
            bflag = true;
        }
    }
    PRINT_DBG_HEAD
    print_dbg("is response %s", bflag ? "yes" : "no");
    return bflag;
}

/**
 * [CSipInterConnectBase::replaceCall 替换呼叫信令中的IP信息]
 * @param line [包含信令的一行信息]
 * 最常见的：
 *     INVITE sip:33078200001320000004@10.73.192.204:5511 SIP/2.0
 *     BYE sip:32011501001320000155@172.18.13.192:5060 SIP/2.0
 * 特殊情况:
 *     INVITE sip:10002@192.168.2.100;transport=UDP SIP/2.0
 *     INVITE sip:32011501001320000155@172.18.13.192 SIP/2.0
 * @param  area      [0:内到外，1:外到内]
 */
void CSipInterConnectBase::replaceCall(char *line, int area)
{
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line, '@');

    if (pat != NULL) {
        //把@以及之前的内容保存到tmpstr
        memcpy(tmpstr, line, pat - line + 1);
        //把替换后的IP追加到tmpstr
        strcat(tmpstr, (area == SIP_IN_CENTER) ? m_outcenter : m_incenter);

        char *pcolon = index(pat, ':');
        if (pcolon != NULL) {
            //把冒号及之后的内容追加到变量
            strcat(tmpstr, pcolon);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {

            //处理特殊情况
            PRINT_DBG_HEAD
            print_dbg("not find :,[%s]", line);
            char *psem = index(pat, ';');
            if (psem != NULL) {
                strcat(tmpstr, psem);
                memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
            } else {
                char *pspace = index(pat, ' ');
                if (pspace != NULL) {
                    strcat(tmpstr, pspace);
                    memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
                }
            }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("not find @[%s]", line);
    }

    return ;
}

/**
 * [CSipInterConnectBase::replaceContact 替换Contact字段]
 * @param line       [一行内容]
 * @param  area      [0:内到外，1:外到内]
 * 报文格式
 *    //Contact: <sip:2001$37060200081320000014@37.48.8.61:5060>\r\n
 */
void CSipInterConnectBase::replaceContact(char *recvstr, int area)
{
    if ((recvstr == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *pat = index(recvstr + strlen(SIP_CONTACT_VALUE), '@');
    if (pat != NULL) {
        char *p = index(pat, ':');
        if (p != NULL) {
            memcpy(tmpstr, recvstr, pat - recvstr + 1);
            strcat(tmpstr, (area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
            strcat(tmpstr, p);
            memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
        } else {

            PRINT_DBG_HEAD
            print_dbg("no find [:],[%s]", recvstr);

            //如果发现了@,没发现:,@后正好是X级平台IP,就替换下
            if (IS_TYPE_OF(pat + 1, (area == SIP_IN_CENTER) ? m_incenter : m_outcenter)) {
                memcpy(tmpstr, recvstr, pat - recvstr + 1);
                strcat(tmpstr, (area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
                strcat(tmpstr, pat + 1 + strlen((area == SIP_IN_CENTER) ? m_incenter : m_outcenter));
                memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
            } else {
                PRINT_ERR_HEAD
                print_err("contact replace nothing[%s]", recvstr);
            }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("contact not find @,[%s]", recvstr);

        //e.g  Contact: <sip:172.20.20.86:5061>
        char *p1 = index(recvstr + strlen(SIP_CONTACT_VALUE) + 1, ':');
        if (p1 != NULL) {
            char *p2 = index(p1 + 1, ':');
            if (p2 != NULL) {
                memcpy(tmpstr, recvstr, p1 - recvstr + 1);
                strcat(tmpstr, (area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
                strcat(tmpstr, p2);
                memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
            }
        }
    }
}

/**
 * [CSipInterConnectBase::getCallID 从一行内容中获取callid值]
 * @param  line      [一行内容，已经把Call-id偏移过去了]
 * @param  callidbuf [存放callid值的buf]
 * @param  buflen    [buf长度]
 * @return           [成功返回true]
 */
bool CSipInterConnectBase::getCallID(const char *line, char *callidbuf, int buflen)
{
    int i = 0, j = 0;
    if ((line != NULL) && (callidbuf != NULL) && (buflen > 0)) {
        while ((line[i] != '\0') && (line[i] != '\r') && (j < buflen)) {
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
 * [CSipInterConnectBase::replaceContentLen 替换Content-Length字段]
 * @param line       [一行内容]
 * @param sip_info   [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *  Content-Length:1114\r\n
 *  Content-Length: 1114\r\n
 *  Content-Length : 1114\r\n
 */
void CSipInterConnectBase::replaceContentLen(char *line, SipInterConnect_INFO *sip_info)
{
    int contlen_offset = 0;

    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    contlen_offset = strlen(SIP_CONTENTLEN_VALUE);
    while ((*(line + contlen_offset) == ' ')
           || (*(line + contlen_offset) == ':')) {
        contlen_offset++;
    }

    sip_info->contlen = atoi(line + contlen_offset);
    if (sip_info->contlen) {
        sprintf(line, "%s: %s", SIP_CONTENTLEN_VALUE, "%d\r\n");
    } else {
        PRINT_DBG_HEAD
        print_dbg("not replcae content_len, [%s]", line);
    }

}

/**
 * [CSipInterConnectBase::replaceCinip6 替换c=IN IP6字段]
 * @param recvstr       [一行内容]
 * @param sip_info   [包含SIP报文每行关键字标志和IP信息]
 */
void CSipInterConnectBase::replaceCinip6(char *recvstr, SipInterConnect_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *p = index(recvstr, '\r');
    char *q = index(recvstr, '\n');
    if (p != NULL) {
        memcpy(sip_info->originip, recvstr + strlen(SIP_CINIP6_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP6_VALUE) - strlen(p)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP6_VALUE));
        strcat(tmpstr, (sip_info->area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, p);
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else if (q != NULL) {
        memcpy(sip_info->originip, recvstr + strlen(SIP_CINIP6_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP6_VALUE) - strlen(q)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP6_VALUE));
        strcat(tmpstr, (sip_info->area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, q);
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine CINIP6[\\r],[%s]", recvstr);
    }

}

/**
 * [CSipInterConnectBase::replaceCinip4 替换c=IN IP4字段]
 * @param recvstr       [一行内容]
 * @param sip_info      [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //c=IN IP4 37.48.8.38\r\n
 */
void CSipInterConnectBase::replaceCinip4(char *recvstr, SipInterConnect_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *p = index(recvstr, '\r');
    char *q = index(recvstr, '\n');
    if (p != NULL) {
        memcpy(sip_info->originip, recvstr + strlen(SIP_CINIP4_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP4_VALUE) - strlen(p)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP4_VALUE));
        strcat(tmpstr, (sip_info->area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, p);
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else if (q != NULL) {
        memcpy(sip_info->originip, recvstr + strlen(SIP_CINIP6_VALUE),
               (strlen(recvstr) - strlen(SIP_CINIP6_VALUE) - strlen(q)));
        memcpy(tmpstr, recvstr, strlen(SIP_CINIP6_VALUE));
        strcat(tmpstr, (sip_info->area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, q);
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine CINIP4 [\\r],[%s]", recvstr);
    }

}

/**
 * [CSipInterConnectBase::replaceOinip4 替换o=字段]
 * @param recvstr       [一行内容]
 * @param sip_info      [包含SIP报文每行关键字标志和IP信息]
 * 报文格式
 *    //o=H3C 0 0 IN IP4 37.48.8.38\r\n
 */
void CSipInterConnectBase::replaceOinip4(char *recvstr, SipInterConnect_INFO *sip_info)
{
    if ((recvstr == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *ptr = strstr(recvstr, "IN IP4 ");
    if (ptr != NULL) {
        //IP之前的内容拷贝到tmpstr
        memcpy(tmpstr, recvstr, ptr - recvstr + strlen("IN IP4 "));
        strcat(tmpstr, (sip_info->area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, "\r\n");
        sip_info->contlen += strlen(tmpstr) - strlen(recvstr);
        memcpy(recvstr, tmpstr, SIP_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("not fine OINIP,[%s]", recvstr);
    }

}

/**
 * [CSipInterConnectBase::getTransferMode 获取媒体ID设置媒体方向]
 * @param  line     [数据包]
 * @param  ifvideo  [是为视频，否为音频]
 * @param sip_info  [包含SIP报文每行关键字标志和IP信息]
 * @return          [成功返回0 失败返回负值]
 */
int CSipInterConnectBase::getTransferMode(char *line, SipInterConnect_INFO *sip_info)
{
    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    if (sip_info->channel_id < 0) {
        PRINT_ERR_HEAD
        print_err("The channel information to this SIP message was not obtained !");
        return -1;
    }

    if (strstr(line, "passive")) {
        sip_info->transfer = true;
    } else {
        sip_info->transfer = false;
    }

    //Set the media flow active direction
    setMediaTransfer(sip_info->channel_id, sip_info->transfer);

    PRINT_INFO_HEAD
    print_info("get transfer mode over. line[%s] transfer[%d]", line, sip_info->transfer);
    return 0;

}


/**
 * [CSipInterConnectBase::getMediaPort 获取媒体端口号]
 * @param  line     [数据包]
 * @param  ifvideo  [是为视频，否为音频]
 * @param sip_info  [包含SIP报文每行关键字标志和IP信息]
 * @return      [成功返回0 失败返回负值]
 * 报文格式
 *    //m=audio 63545 udp 105\r\n
 */
int CSipInterConnectBase::getMediaPort(char *line, bool ifvideo, SipInterConnect_INFO *sip_info)
{
    if ((line == NULL) || (sip_info == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("begin handel media m_area [%d] area [%d] m_mode [%d]!", m_area, sip_info->area, m_mode);

    if (SIP_FUN_CASCADE_MODE == m_mode) {
        if ((sip_info->isresp) && (SIP_IN_CENTER == sip_info->area)) {
            PRINT_INFO_HEAD
            print_info("res area is [%d], not handel", sip_info->area);
            return 0;
        } else if ((!sip_info->isresp) && (SIP_OUT_CENTER == sip_info->area)) {
            PRINT_INFO_HEAD
            print_info("req area is [%d], not handel", sip_info->area);
            return 0;
        }
    }

    char *ptr = NULL;
    int portlen = 0;
    int mlen = 0;
    int ptrlen = 0;
    char channelport[PORT_STR_LEN] = {0};
    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    mlen = strlen(ifvideo ? SIP_VIDEO_VALUE : SIP_AUDIO_VALUE);
    ptr = index(line + mlen, ' ');
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("not find Space[%s]", line);
        return -1;
    }

    if (strstr(line, "TCP")) {
        sip_info->is_udp = false;
    } else {
        sip_info->is_udp = true;
    }
    //端口号拷贝到变量
    ptrlen = strlen(ptr);
    portlen = strlen(line) - ptrlen - mlen;
    if (portlen < (int)sizeof(sip_info->audioport)) {
        if (ifvideo) {
            memcpy(sip_info->videoport, line + mlen, portlen);
            if ((SIP_AUDIO_PORT == sip_info->port_flag) ||
                (SIP_VIDEO_AND_AUDIO_PORT == sip_info->port_flag)) {
                sip_info->port_flag = SIP_VIDEO_AND_AUDIO_PORT;
            } else {
                sip_info->port_flag = SIP_VIDEO_PORT;
            }
        } else {
            memcpy(sip_info->audioport, line + mlen, portlen);
            if ((SIP_VIDEO_PORT == sip_info->port_flag) ||
                (SIP_VIDEO_AND_AUDIO_PORT == sip_info->port_flag)) {
                sip_info->port_flag = SIP_VIDEO_AND_AUDIO_PORT;
            } else {
                sip_info->port_flag = SIP_AUDIO_PORT;
            }
        }
    } else {
        PRINT_ERR_HEAD
        print_err("port len invalid[%d],[%s]", portlen, line);
        return -1;
    }

    /* 函数调用前后打印日志, 确定查找动态端口消耗时间 */
    PRINT_INFO_HEAD
    print_info("get proxy port begin: callid[%s], line[%s]", sip_info->callid, line);

    //获取代理端口号
    getChannelProxyPort(sip_info, channelport);

    PRINT_INFO_HEAD
    print_info("get proxy port end: callid[%s], line[%s]", sip_info->callid, line);

    memcpy(tmpstr, line, mlen);
    memcpy(tmpstr + mlen, channelport, strlen(channelport));
    memcpy(tmpstr + mlen + strlen(channelport), ptr, ptrlen);
    sip_info->contlen += strlen(tmpstr) - strlen(line);
    memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);

    PRINT_DBG_HEAD
    print_dbg("replace media port over. line[%s]", line);
    return 0;

}

/**
 * [CSipInterConnectBase::replaceFrom 替换from字段]
 * @param line       [一行内容]
 * @param  area      [0:内到外，1:外到内]
 */
void CSipInterConnectBase::replaceFrom(char *line, int area)
{
    if ((line == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return ;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line + strlen(SIP_FROM_VALUE), '@');
    char *p = NULL;
    if (pat != NULL) {
        memcpy(tmpstr, line, pat - line + 1);
        strcat(tmpstr, (area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
        if (NULL != (p = index(pat, ':'))) {
            strcat(tmpstr, p);
        } else if (NULL != (p = index(pat, '>'))) {
            strcat(tmpstr, p);
        } else if (NULL != (p = index(pat, ';'))) {
            strcat(tmpstr, p);
        } else {
            strcat(tmpstr, "\r\n");
        }
        memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
    }
}

/**
 * [CSipInterConnectBase::replaceTo 替换to字段]
 * @param line       [一行内容]
 * @param  area      [0:内到外，1:外到内]
 * To: <sip:9803@192.168.3.138>
 */
void CSipInterConnectBase::replaceTo(char *line, int area)
{
    if ((line == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};
    char *pat = index(line + strlen(SIP_TO_VALUE), '@');
    char *p = NULL;
    if (pat != NULL) {
        memcpy(tmpstr, line, pat - line + 1);
        strcat(tmpstr, (area == SIP_IN_CENTER) ? m_outcenter : m_incenter);
        if (NULL != (p = index(pat, ':'))) {
            strcat(tmpstr, p);
        } else if (NULL != (p = index(pat, '>'))) {
            strcat(tmpstr, p);
        } else if (NULL != (p = index(pat, ';'))) {
            strcat(tmpstr, p);
        } else {
            strcat(tmpstr, "\r\n");
        }
        memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
    }
}


/**
 * [CSipInterConnectBase::replaceVia 替换VIA字段]
 * @param line       [一行内容]
 * @param  area      [0:内到外，1:外到内]
 * 报文格式
 *    //Via: SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 *    //Via:SIP/2.0/UDP 20.95.4.103:6689;branch=z9hG4bK108764931853145314531420180523110753
 */
void CSipInterConnectBase::replaceVia(char *line, int area)
{
    if ((line == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    char tmpstr[SIP_MAX_LINE_SIZE] = {0};

    char *psip20 = strstr(line, "SIP/2.0/");
    if (psip20 != NULL) {
        char *pcolon = index(psip20, ':');
        if (pcolon != NULL) {
            memcpy(tmpstr, line, psip20 - line + strlen("SIP/2.0/UDP "));
            strcat(tmpstr, (area == SIP_IN_CENTER) ? m_gapoutip : m_gapinip);
            strcat(tmpstr, pcolon);
            memcpy(line, tmpstr, SIP_MAX_LINE_SIZE);
        } else {
            PRINT_ERR_HEAD
            print_err("Via not fine [:], [%s]", line);
        }

    } else {
        PRINT_ERR_HEAD
        print_err("Via not find [SIP/2.0/UDP ], [%s]", line);
    }
}

/**
 * [CSipInterConnectBase::sipKeywordHandle 将sip每行的关键字标志转换为数字]
 * @param  recvstr        [需要被替换的数据包]
 * @param sip_info        [包含SIP报文每行关键字标志和IP信息]
 */
void CSipInterConnectBase::sipKeywordHandle(const char *recvstr, SipInterConnect_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return;
    }

    if (IS_TYPE_OF(recvstr, SIP_INVITE_VALUE)) {
        sip_info->key_flag = SIP_INVITE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_UPDATE_VALUE)) {
        sip_info->key_flag = SIP_UPDATE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_ACK_VALUE)) {
        sip_info->key_flag = SIP_ACK_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_PRACK_VALUE)) {
        sip_info->key_flag = SIP_PRACK_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_BYE_VALUE)) {
        sip_info->key_flag = SIP_BYE_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_REGISTER_VALUE)) {
        sip_info->key_flag = SIP_REGISTER_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CANCEL_VALUE)) {
        sip_info->key_flag = SIP_CANCEL_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_VIA_VALUE)) {
        sip_info->key_flag = SIP_VIA_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CONTACT_VALUE)) {
        sip_info->key_flag = SIP_CONTACT_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_OINIP4_VALUE)) {
        sip_info->key_flag = SIP_OINIP4_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CINIP4_VALUE)) {
        sip_info->key_flag = SIP_CINIP4_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CINIP6_VALUE)) {
        sip_info->key_flag = SIP_CINIP6_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CONTENTLEN_VALUE)) {
        sip_info->key_flag = SIP_CONTENTLEN_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_VIDEO_VALUE)) {
        sip_info->key_flag = SIP_MVIDEO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_AUDIO_VALUE)) {
        sip_info->key_flag = SIP_MAUDIO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_TRANSFER_VALUE)) {
        sip_info->key_flag = SIP_TRANSFER_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_CALLID_VALUE)) {
        sip_info->key_flag = SIP_CALLID_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_FROM_VALUE)) {
        sip_info->key_flag = SIP_FROM_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_TO_VALUE)) {
        sip_info->key_flag = SIP_TO_KEY;
    } else if (IS_TYPE_OF(recvstr, SIP_NOTIFY_VALUE)) {
        sip_info->key_flag = SIP_NOTIFY_KEY;
    } else {
        sip_info->key_flag = SIP_OTHER_KEY;
    }
    return;
}


/**
 * [CSipInterConnectBase::replaceSipReqInfo 替换SIP请求的IP等信息]
 * @param  recvstr    [需要被替换的数据行]
 * @param  sip_info   [包含SIP报文每行关键字标志和IP信息]
 * @return            [正常返回recvstr长度，出错为负值]
 */
int CSipInterConnectBase::replaceSipInfo(char *recvstr, SipInterConnect_INFO *sip_info)
{
    if ((recvstr == NULL) || (NULL == sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    switch (sip_info->key_flag) {
    case SIP_BYE_KEY:
        if (!sip_info->isresp) {
            sip_info->b_bye = true;
            replaceCall(recvstr, sip_info->area);
        }
        break;
    case SIP_MESSAGE_KEY:
    case SIP_INVITE_KEY:
    case SIP_ACK_KEY:
    case SIP_UPDATE_KEY:
    case SIP_PRACK_KEY:
    case SIP_CANCEL_KEY:
        replaceCall(recvstr, sip_info->area);
        break;
    case SIP_CONTACT_KEY:
        replaceContact(recvstr, sip_info->area);
        break;
    case SIP_CINIP4_KEY:
        replaceCinip4(recvstr, sip_info);
        break;
    case SIP_OINIP4_KEY://不必须替换
        replaceOinip4(recvstr, sip_info);
        break;
    case SIP_MVIDEO_KEY:
        getMediaPort(recvstr, true, sip_info);
        break;
    case SIP_MAUDIO_KEY:
        getMediaPort(recvstr, false, sip_info);
        break;
    case SIP_TRANSFER_KEY:
        getTransferMode(recvstr, sip_info);
        break;
    case SIP_CONTENTLEN_KEY:
        replaceContentLen(recvstr, sip_info);
        break;
    case SIP_NOTIFY_KEY:
        replaceCall(recvstr, sip_info->area);
    case SIP_CALLID_KEY:
        if (getCallID(recvstr + strlen(SIP_CALLID_VALUE), sip_info->callid, sizeof(sip_info->callid))) {
            PRINT_DBG_HEAD
            print_dbg("get call id ok[%s]", sip_info->callid);
            if (sip_info->b_bye) {
                deleteChannelByCallID(sip_info->callid);//多态
            }
        }
        break;
    case SIP_VIA_KEY:
        if (m_via) {
            replaceVia(recvstr, sip_info->area);
        }
        break;
    case SIP_FROM_KEY:
        if (m_from) {
            replaceFrom(recvstr, sip_info->area);
        }
        break;
    case SIP_TO_KEY:
        if (m_to) {
            replaceTo(recvstr, sip_info->area);
        }
        break;
    default:
        break;
    }

    return strlen(recvstr);
}


/**
 * [CSipInterConnectBase::processData 处理数据包信息]
 * @param  src  [待处理数据包]
 * @param  len  [src数据包长度]
 * @param  dst  [目的缓冲区]
 * @param  area [区域，来自哪个交换中心]
 * @return      [成功返回dst中信息长度,失败返回负值]
 */
int CSipInterConnectBase::processData(const char *src, int len, char *dst, int area)
{
    if ((src == NULL) || (len < 0) || (dst == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("process data begin. datalen[%s] area [%d]", src, area);

    int ipos = 0;
    int part = 0;
    int res = 0;
    int dstlen = 0;
    char recvstr[SIP_MAX_LINE_SIZE] = {0};
    char tmpdst[SIP_MAX_PACKET] = {0};
    SipInterConnect_INFO sip_info;
    char chcmd[C_SIP_KEY_WORLD_LEN] = {0};
    char *p = NULL;

    memset(&sip_info, 0x00, sizeof(SipInterConnect_INFO));
    sip_info.area = area;
    sip_info.transfer = 0;
    sip_info.channel_id = -1;

    //过滤命令，取SIP请求命令并记日志
    if (getCmd(chcmd, C_SIP_KEY_WORLD_LEN, src)) {
        if (!filterSipCmd(chcmd, area)) {
            PRINT_ERR_HEAD
            print_err("filterSipCmd fail");
            return -1;
        }
    }

    //将收到的SIP报文分行并处理
    while (1) {
        BZERO(recvstr);
        res = findStrByKey(src, recvstr, ipos, '\n');
        if (res == -1) {
            //未找到\n,也要把内容写入
            memcpy(tmpdst + dstlen, recvstr, strlen(recvstr));
            dstlen += (int)strlen(recvstr);
            break;
        }

        part++;
        ipos = res;
        sip_info.key_flag = 0;
        if (1 == part) {
            sip_info.isresp = isResponse(recvstr);
        }
        //每行关键字段匹配转换标志
        sipKeywordHandle(recvstr, &sip_info);

        //替换请求
        res = replaceSipInfo(recvstr, &sip_info);
        if (res < 0) {
            PRINT_ERR_HEAD
            print_err("error res replaceSipReqInfo [%d]\n", res);
            return -1;
        }

        //替换后的行写入dst
        memcpy(tmpdst + dstlen, recvstr, res);
        dstlen += res;
    }

    //将替换后的SDP长度写入，否则SIP会报错
    if (sip_info.contlen) {
        BZERO(recvstr);
        p = strstr(tmpdst, "\r\n\r\n");
        if (NULL != p) {
            memcpy(recvstr, tmpdst, p - tmpdst);
            sprintf(dst, recvstr, sip_info.contlen);
            strcat(dst, p);
        } else {
            sprintf(dst, tmpdst, sip_info.contlen);
        }
    } else {
        memcpy(dst, tmpdst, dstlen);
    }

    dstlen = strlen(dst);
    res = (int)strlen(src);
    if (res < len) {
        memcpy(dst + dstlen, src + res, len - res);
        dstlen += len - res;
    }

    PRINT_DBG_HEAD
    print_dbg("process data over. ret[%s]", dst);
    return dstlen;
}

/**
 * [CSipInterConnectBase::recvServerThread网闸靠近客户端的一侧，接收平台方向数据的线程函数]
 * @param  para [地址端口信息]
 * @return      [无特殊含义]
 */
void *CSipInterConnectBase::recvServerThread(void *para)
{
    pthread_setself("recvserver");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int recvlen = 0;
    int replen = 0;
    int sendlen = 0;
    unsigned char buff[SIP_MAX_LINE_SIZE];
    unsigned char buff2[SIP_MAX_LINE_SIZE];
    PSipInterConnectTASK m_task = (SipInterConnectTASK *)para;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    int recvarea = m_task->recvarea;
    int regid = m_task->regid;
    CSipInterConnectBase *pSipInterConnect = m_task->pSipInterConnect;

    DELETE(m_task);

    if (pSipInterConnect == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    while (1) {
        BZERO(buff);
        BZERO(buff2);

        recvlen = recvfrom(recvsock, buff, sizeof(buff) - SIP_PKT_LEN_CHANGE, 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s][%d]", strerror(errno), recvlen);
            continue;
        }

        pSipInterConnect->m_regtable[regid].updatetime = time(NULL);
        replen = pSipInterConnect->processData((char *)buff, recvlen, (char *)buff2, recvarea);
        if (replen > 0) {
            sendlen = sendto(sendsock, buff2, replen, 0,
                             (struct sockaddr *) & (pSipInterConnect->m_regtable[regid].cliaddr),
                             sizeof(struct sockaddr));
            if (sendlen <= 0) {
                PRINT_ERR_HEAD
                print_err("sendto error[%s][%d]", strerror(errno), sendlen);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("repalace error");
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here");
    close(sendsock);
    close(recvsock);
    return NULL;
}


/**
 * [CSipInterConnectBase::regClient SIP客户端登记]
 *注释:    对于已经登记过的客户端，用fd2返回已建socket描述符
 *         对于未登记的客户端
 *            如果还有空余的登记空间，就创建socket，起线程接收该socket，登记，描述符返回
 *            如果没有空余的登记空间
 *                检查是否有超过1个小时未使用的空间
 *                    如果有超时的就复用空间 描述符返回
 *                    如果没有超时的，就返回登记失败，丢弃客户端信息
 * @param  addr [客户端地址信息]
 * @param  fd1  [接收客户端请求的时候 使用的描述符]
 * @param  fd2  [新创建的socket描述符 出参]
 * @return      [成功返回下标值（登记编号） 失败返回负值]
 */
int CSipInterConnectBase::regClient(sockaddr_in &addr, int fd1, int &fd2)
{
    int maxreg = ARRAY_SIZE(m_regtable);
    int unuse_id = -1;
    int yes = 1;
    int earliest = 0;
    struct sockaddr_in inneraddr;
    pthread_t pid = 0;
    SipInterConnectTASK *psock1 = NULL;

    //是否已经登记过
    for (int i = 0; i < maxreg; i++) {
        if (m_regtable[i].inuse) {
            //最早注册
            if (m_regtable[i].updatetime <= m_regtable[earliest].updatetime) {
                earliest = i;
            }
            //已注册
            if (memcmp(&(m_regtable[i].cliaddr), &addr, sizeof(m_regtable[i].cliaddr)) == 0) {
                m_regtable[i].updatetime = time(NULL);
                fd2 = m_regtable[i].fd;
                return i;
            }
        } else if (unuse_id < 0) {
            unuse_id = i;
        }
    }

    if (unuse_id >= 0) {
        //创建socket
        int myfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (myfd < 0) {
            PRINT_ERR_HEAD
            print_err("socket error[%s]", strerror(errno));
            return -1;
        }

        //setsockopt
        setsockopt(myfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        //地址结构
        BZERO(inneraddr);
        inneraddr.sin_family = AF_INET;
        inneraddr.sin_port = htons(m_regtable[unuse_id].bindport);
        if (inet_pton(AF_INET, m_innerinip, (void *)&inneraddr.sin_addr) <= 0) {
            PRINT_ERR_HEAD
            print_err("inet_pton error[%s],m_tmpip1[%s]", strerror(errno), m_innerinip);
            close(myfd);
            return -1;
        }

        //bind
        if (bind(myfd, (struct sockaddr *)&inneraddr, sizeof(inneraddr)) < 0) {
            PRINT_ERR_HEAD
            print_err("bind error[%s],m_tmpip1[%s],port[%d]",
                      strerror(errno), m_innerinip, m_regtable[unuse_id].bindport);
            close(myfd);
            return -1;
        }

        //准备线程参数
        psock1 = new SipInterConnectTASK();
        if (psock1 == NULL) {
            PRINT_ERR_HEAD
            print_err("new CLISOCKTASK fail");
            close(myfd);
            return -1;
        }
        psock1->recvsock = myfd;
        psock1->sendsock = fd1;
        psock1->pSipInterConnect = this;
        psock1->regid = unuse_id;
        psock1->recvarea = SIP_OUT_CENTER;

        //启动接收线程
        if (pthread_create(&pid, NULL, recvServerThread, (void *)psock1) != 0) {
            PRINT_ERR_HEAD
            print_err("pthread_create error");
            close(myfd);
            return -1;
        }

        memcpy(&(m_regtable[unuse_id].cliaddr), &addr, sizeof(m_regtable[unuse_id].cliaddr));
        m_regtable[unuse_id].inuse = 1;
        m_regtable[unuse_id].updatetime = time(NULL);
        m_regtable[unuse_id].fd = myfd;
        fd2 = m_regtable[unuse_id].fd;
        usleep(10000);//防止线程参数失效
        return unuse_id;
    } else {
        memcpy(&(m_regtable[earliest].cliaddr), &addr, sizeof(m_regtable[earliest].cliaddr));
        m_regtable[earliest].updatetime = time(NULL);
        fd2 = m_regtable[earliest].fd;
        return earliest;
    }
}


/**
 * [recvCenterSIP 接收交换中心SIP信令 线程函数]
 * @param  para [线程参数]
 * @return      [未使用]
 */
void *recvCenterSIP(void *para)
{
    pthread_setself("recvcentersip");

    PRINT_DBG_HEAD
    print_dbg("recv center PSIP begin");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int regid = 0;
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;
    char buff1[SIP_MAX_PACKET];
    char buff2[SIP_MAX_PACKET];
    char *p_tmp = NULL;
    sockaddr_in from_addr;
    sockaddr_in to_addr;
    PSipInterConnectTASK ptask = (PSipInterConnectTASK)para;
    int recvsock = ptask->recvsock;
    int sendsock = ptask->sendsock;
    int recvarea = ptask->recvarea;
    CSipInterConnectBase *pSipInterConnect = ptask->pSipInterConnect;

    DELETE(ptask);

    BZERO(to_addr);

    to_addr.sin_family = AF_INET;
    if (recvarea == SIP_IN_CENTER) {
        to_addr.sin_addr.s_addr = inet_addr(pSipInterConnect->m_inneroutip);
        to_addr.sin_port = htons(atoi(pSipInterConnect->m_outport));
    } else {
        to_addr.sin_addr.s_addr = inet_addr(pSipInterConnect->m_incenter);
        to_addr.sin_port = htons(atoi(pSipInterConnect->m_inport));
    }

    //存放客户端地址信息
    BZERO(from_addr);
    socklen_t fromaddrlen = sizeof(from_addr);

    while (1) {
        BZERO(buff1);
        BZERO(buff2);

        recvlen = recvfrom(recvsock, buff1, sizeof(buff1), 0, (sockaddr *)&from_addr, &fromaddrlen);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom %s:%d error[%s],recvlen[%d],area[%d]", inet_ntoa(from_addr.sin_addr), \
                      ntohs(from_addr.sin_port), strerror(errno), recvlen, recvarea);
            usleep(1000);
        } else {

            /* INVITE, REGISTER 指令添加log日志，默认打印首行，debug 模式打印全部 */
            if ((0 == strncasecmp((char *)buff1, SIP_INVITE_VALUE, strlen(SIP_INVITE_VALUE))) \
                || (0 == strncasecmp((char *)buff1, SIP_REGISTER_VALUE, strlen(SIP_REGISTER_VALUE)))) {

                p_tmp = strstr((char *)buff1, "\r\n");
                if (NULL != p_tmp) {

                    *p_tmp = '\0';
                    PRINT_INFO_HEAD
                    print_info("recv from %s:%d line1:[%s]", inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port), buff1);
                    *p_tmp = '\r';

                    PRINT_DBG_HEAD
                    print_dbg("recv from %s:%d : [%s]", inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port), buff1);
                }

            }

            if (SIP_FUN_PROXY_MODE == pSipInterConnect->m_mode) {
                //客户端登记
                regid = pSipInterConnect->regClient(from_addr, recvsock, sendsock);
                if (regid < 0) {
                    PRINT_ERR_HEAD
                    print_err("register fail, may too many clients");
                    continue;
                }
            }
            replen = pSipInterConnect->processData(buff1, recvlen, buff2, recvarea);
            if (replen > 0) {
                sendlen = sendto(sendsock, buff2, replen, 0,
                                 (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
                if (sendlen <= 0) {
                    PRINT_ERR_HEAD
                    print_err("sendto error[%s][%d],area[%d]",
                              strerror(errno), sendlen, recvarea);
                } else {
                    PRINT_DBG_HEAD
                    print_dbg("send[%d],area[%d]", sendlen, recvarea);
                }
            } else {
                PRINT_ERR_HEAD
                print_err("process data error[%d],area[%d]", replen, recvarea);
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here,area[%d]", recvarea);
    close(sendsock);
    close(recvsock);
    return NULL;
}

/**
 * [CSipInterConnectBase::getTCPThreadID 获取一个TCP线程对应的下标ID]
 * @return [成功返回下标，失败返回-1]
 */
int CSipInterConnectBase::getTCPThreadID()
{
    sem_wait(m_tcp_sem);
    for (int i = 0; i < (int)ARRAY_SIZE(m_tcpstate); i++) {
        if (m_tcpstate[i] == STATUS_FREE) {
            m_tcpstate[i] = STATUS_INUSE;
            sem_post(m_tcp_sem);
            return i;
        }
    }
    sem_post(m_tcp_sem);
    return -1;
}

/**
 * [CSipInterConnectBase::doRecv 接收处理TCP SIP数据]
 * @param  sock1 [描述符1]
 * @param  sock2 [描述符2]
 * @param  recvarea  [区域]
 * @return       [成功返回true]
 */
bool CSipInterConnectBase::doRecv(int sock1, int sock2, int recvarea)
{
    unsigned char buff1[SIP_MAX_PACKET] = {0};
    unsigned char buff2[SIP_MAX_PACKET] = {0};
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    socklen_t addrlen;
    char *p_tmp = NULL;
    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;

    recvlen = recv(sock1, buff1, sizeof(buff1) - SIP_PKT_LEN_CHANGE, 0);
    if (recvlen <= 0) {
        PRINT_INFO_HEAD
        print_info("recv fail[%s][%d],may close!", strerror(errno), recvlen);
        return false;
    }

    /* INVITE, REGISTER 指令添加log日志，默认打印首行，debug 模式打印全部 */
    if ((0 == strncasecmp((char *)buff1, SIP_INVITE_VALUE, strlen(SIP_INVITE_VALUE))) \
        || (0 == strncasecmp((char *)buff1, SIP_REGISTER_VALUE, strlen(SIP_REGISTER_VALUE)))) {

        p_tmp = strstr((char *)buff1, "\r\n");
        if (NULL != p_tmp) {

            addrlen = sizeof(struct sockaddr_in);
            getsockname(sock1, (struct sockaddr *)&local_addr, &addrlen);
            addrlen = sizeof(struct sockaddr_in);
            getpeername(sock1, (struct sockaddr *)&remote_addr, &addrlen);

            *p_tmp = '\0';
            PRINT_INFO_HEAD
            print_info("%s:%d -> %s:%d recv line1:[%s]", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port), \
                       inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port), buff1);
            *p_tmp = '\r';

            PRINT_DBG_HEAD
            print_dbg("%s:%d -> %s:%d recv: [%s]", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port), \
                      inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port), buff1);
        }
    }

    if ((recvarea == SIP_IN_CENTER) || (recvarea == SIP_OUT_CENTER)) {
        replen = processData((const char *)buff1, recvlen, (char *)buff2, recvarea);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown recvarea[%d]", recvarea);
        return false;
    }

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
 * [CSipInterConnectBase::SipTcpSendAndRecvTask TCP接收和发送线程函数]
 * @param  para [SOCKTASK指针]
 * @return      [无特殊含义]
 */
void *CSipInterConnectBase::SipTcpSendAndRecvTask(void *para)
{
    pthread_setself("siptcpsendrecv");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    SipInterConnectTASK *m_task = (SipInterConnectTASK *)para;
    int recvsock = m_task->recvsock;
    int sendsock = m_task->sendsock;
    int thid = m_task->thid;
    int recvarea = m_task->recvarea;
    CSipInterConnectBase *psip = m_task->pSipInterConnect;
    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

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
            if (!psip->doRecv(recvsock, sendsock, (recvarea == SIP_IN_CENTER) ? SIP_IN_CENTER : SIP_OUT_CENTER)) {
                PRINT_INFO_HEAD
                print_info("sock[%d] do recv ret false", recvsock);
                break;
            }
        }

        if (FD_ISSET(sendsock, &fds)) {
            if (!psip->doRecv(sendsock, recvsock, (recvarea == SIP_IN_CENTER) ? SIP_OUT_CENTER : SIP_IN_CENTER)) {
                PRINT_INFO_HEAD
                print_info("=sock[%d] do recv ret false", sendsock);
                break;
            }
        }
    }

    sem_wait(psip->m_tcp_sem);
    if (psip->m_tcpstate[thid] == STATUS_INUSE) {
        PRINT_DBG_HEAD
        print_dbg("thid[%d] tcp close ssock[%d] rsock[%d]", thid, sendsock, recvsock);
        close(sendsock);
        close(recvsock);
        psip->m_tcpstate[thid] = STATUS_FREE;
    } else {
        PRINT_ERR_HEAD
        print_err("thid[%d] something may error! tcpstate[%d]", thid, psip->m_tcpstate[thid]);
    }
    sem_post(psip->m_tcp_sem);

    PRINT_DBG_HEAD
    print_dbg("thid[%d] exit", thid);
    return NULL;
}


/**
 * [SipTcpListenTask TCP监听任务]
 * @param  para [SOCKTASK指针]
 * @return      [正常情况下不会退出，异常时返回NULL]
 */
void *SipTcpListenTask(void *para)
{
    pthread_setself("siptcplisten");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int mysock1 = 0;
    int mysock2 = 0;
    int tcpthid = 0;
    CBSTcpSockServer ser;
    SipInterConnectTASK *m_task = (SipInterConnectTASK *)para;
    int area = m_task->recvarea;
    CSipInterConnectBase *psip = m_task->pSipInterConnect;

    DELETE(m_task);

    if (psip == NULL) {
        PRINT_ERR_HEAD
        print_err("psip null");
        return NULL;
    }

    //根据flag的不同 绑定监听不同的ip 端口
    if (area == SIP_IN_CENTER) {
        while (ser.Open(psip->m_gapinip, atoi(psip->m_outport)) < 0) {
            PRINT_ERR_HEAD
            print_err("listen[%d][%s] fail, retry", atoi(psip->m_outport), psip->m_gapinip);
            sleep(1);
        }
        PRINT_DBG_HEAD
        print_dbg("listen[%d][%s] ok", atoi(psip->m_outport), psip->m_gapinip);

    } else if (area == SIP_OUT_CENTER) {
        while (ser.Open(psip->m_innerinip, atoi(psip->m_inport)) < 0) {
            PRINT_ERR_HEAD
            print_err("listen[%d][%s] fail, retry", atoi(psip->m_inport), psip->m_innerinip);
            sleep(1);
        }
        PRINT_DBG_HEAD
        print_dbg("listen[%d][%s] ok", atoi(psip->m_inport), psip->m_innerinip);
    } else {
        PRINT_ERR_HEAD
        print_err("flag error[%d]", area);
        return NULL;
    }

    while (1) {
        mysock1 = 0;
        mysock2 = 0;
        mysock1 = ser.StartServer();
        if (mysock1 < 0) {
            PRINT_ERR_HEAD
            print_err("accept error[%s]", strerror(errno));
            continue;
        }

        tcpthid = psip->getTCPThreadID();
        if (tcpthid == -1) {
            PRINT_ERR_HEAD
            print_err("LinkNum has reached the maximum [%d], close it", C_MAX_THREAD);
            close(mysock1);
            continue;
        }

        PRINT_DBG_HEAD
        print_dbg("tcpthid[%d] accept sock %d", tcpthid, mysock1);

        //根据flag的不同 去连接不同的ip端口
        if (area == SIP_IN_CENTER) {
            mysock2 = psip->m_cli[tcpthid].Open(psip->m_inneroutip, atoi(psip->m_outport));
            if (mysock2 <= 0) {
                PRINT_ERR_HEAD
                print_err("connect Err! ip[%s] port = [%s] area = [%d]", psip->m_inneroutip, psip->m_outport, area);
                close(mysock1);
                psip->m_tcpstate[tcpthid] = STATUS_FREE;
                continue;
            }
        } else if (area == SIP_OUT_CENTER) {
            mysock2 = psip->m_cli[tcpthid].Open(psip->m_incenter, atoi(psip->m_inport));
            if (mysock2 <= 0) {
                PRINT_ERR_HEAD
                print_err("connect Err! ip[%s] port = [%s] area = [%d]", psip->m_incenter, psip->m_inport, area);
                close(mysock1);
                psip->m_tcpstate[tcpthid] = STATUS_FREE;
                continue;
            }
        }

        if (mysock1 == mysock2) {
            PRINT_ERR_HEAD
            print_err("mysock1 == mysock2 %d, thid=%d", mysock1, tcpthid);
        }

        //准备线程参数
        SipInterConnectTASK *psock1 = new SipInterConnectTASK();
        if (psock1 == NULL) {
            PRINT_ERR_HEAD
            print_err("new SOCKTASK error");

            close(mysock1);
            close(mysock2);
            psip->m_tcpstate[tcpthid] = STATUS_FREE;
            continue;
        }

        psock1->recvsock = mysock1;
        psock1->sendsock = mysock2;
        psock1->thid = tcpthid;
        psock1->pSipInterConnect = psip;
        psock1->recvarea = area;

        pthread_t pid1 = 0;
        if (pthread_create(&pid1, NULL, psip->SipTcpSendAndRecvTask, (void *)psock1) != 0) {
            PRINT_ERR_HEAD
            print_err("pthread_create error");

            close(mysock1);
            close(mysock2);
            psip->m_tcpstate[tcpthid] = STATUS_FREE;
            DELETE(psock1);
            continue;
        }
        usleep(1000);
    }

    PRINT_ERR_HEAD
    print_err("You should never get here, flag = %d", area);
    return NULL;
}



/**
 * [CSipInterConnectBase::startTaskThreads 开启任务线程]
 */
void CSipInterConnectBase::startTaskThreads(void)
{
    PRINT_DBG_HEAD
    print_dbg("start threads");

    CBSUdpSockServer srvudp1, srvudp2;
    PSipInterConnectTASK ptask1 = NULL, ptask2 = NULL, ptask3 = NULL, ptask4 = NULL;

    int sockudp1 = srvudp1.Open(m_gapinip, atoi(m_outport));
    int sockudp2 = srvudp2.Open(m_innerinip, atoi(m_inport));
    if ((sockudp1 < 0) || (sockudp2 < 0)) {
        PRINT_ERR_HEAD
        print_err("sock1=[%d][%s:%s],sock2=[%d][%s:%s]",
                  sockudp1, m_outport, m_gapinip, sockudp2, m_inport, m_innerinip);
        CLOSE(sockudp1);
        CLOSE(sockudp2);
        goto _out;
    }

    ptask1 = new SipInterConnectTASK();
    ptask2 = new SipInterConnectTASK();
    if ((ptask1 == NULL) || (ptask2 == NULL)) {
        PRINT_ERR_HEAD
        print_err("new pdt task fail");
        DELETE(ptask1);
        DELETE(ptask2);
        goto _out;
    }

    ptask1->recvsock = ptask2->sendsock = sockudp1;
    ptask1->sendsock = ptask2->recvsock = sockudp2;
    ptask1->pSipInterConnect = ptask2->pSipInterConnect = this;
    ptask1->recvarea = SIP_IN_CENTER;
    ptask2->recvarea = SIP_OUT_CENTER;

    if (createThread(recvCenterSIP, ptask1)) {
        PRINT_DBG_HEAD
        print_dbg("create thread1 ok");
    }

    if (SIP_FUN_PROXY_MODE != m_mode) {
        if (createThread(recvCenterSIP, ptask2)) {
            PRINT_DBG_HEAD
            print_dbg("create thread2 ok");
        }
    }

    //---------------------------------------------------
    //接收上级平台TCP SIP数据的线程
    ptask3 = new SipInterConnectTASK();
    if (ptask3 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        goto _out;
    }

    ptask3->recvsock = -1;
    ptask3->sendsock = -1;
    ptask3->pSipInterConnect = this;
    ptask3->recvarea = SIP_IN_CENTER;

    if (createThread(SipTcpListenTask, ptask3)) {
        PRINT_DBG_HEAD
        print_dbg("create thread3 ok");
    }

    //---------------------------------------------------
    //接收下级平台TCP SIP数据的线程
    ptask4 = new SipInterConnectTASK();
    if (ptask4 == NULL) {
        PRINT_ERR_HEAD
        print_err("new SOCKTASK error");
        goto _out;
    }

    ptask4->recvsock = -1;
    ptask4->sendsock = -1;
    ptask4->pSipInterConnect = this;
    ptask4->recvarea = SIP_OUT_CENTER;
    if (createThread(SipTcpListenTask, ptask4)) {
        PRINT_DBG_HEAD
        print_dbg("create thread4 ok");
    }


_out:
    PRINT_DBG_HEAD
    print_dbg("start threads over");
    return;
}

/**
 * [CSipInterConnectBase::getSecway 返回安全通道]
 * @return  [安全通道的引用]
 */
SEC_WAY &CSipInterConnectBase::getSecway(void)
{
    return m_secway;
}
