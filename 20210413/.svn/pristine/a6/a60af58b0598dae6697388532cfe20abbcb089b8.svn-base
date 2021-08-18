/*******************************************************************************************
*文件: pdtbase.cpp
*描述: PDT互联 基类
*作者: 王君雷
*日期: 2018-07-31
*修改:
*      修改外网侧添加iptables时nat表POSTROUTING链，一处IP错误          ------> 2018-08-23
*      根据review的讨论，把recvCenterPSIP从类中移出，使用友元函数      ------> 2018-08-25
*      socket通信类接口传参顺序有变动                                  ------> 2019-03-18
*      代码优化，减少循环操作、将有些字符串操作改为指针操作            ------> 2019-06-24 --dzj
*      代码优化，去掉不必要的数组清零操作                              ------> 2019-06-25 --dzj
*      解决SIP日志导出时乱序问题                                       ------> 2019-06-27 --dzj
*      不再串行记录访问日志                                            ------> 2020-01-07 --wjl
*      访问日志支持记录MAC字段,暂设置为空                              ------> 2020-01-16 wjl
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "FCBSTX.h"
#include "pdtbase.h"
#include "define.h"
#include "debugout.h"
#include "fileoperator.h"
#include "readcfg.h"
#include "quote_global.h"
#include "FCLogContainer.h"
#include "FCPeerExecuteCMD.h"

CPDTBase::CPDTBase(int taskid)
{
    m_taskid = taskid;
    BZERO(m_cmd);
    m_inbrandid = PDT_BRAND_OTHER;
    m_outbrandid = PDT_BRAND_OTHER;
    m_defaultaction = false;
}

CPDTBase::~CPDTBase(void)
{
    DELETE_N(m_cmd, C_MAX_CMD);
}

/**
 * [CPDTBase::loadConf 加载配置信息]
 * @param  filename   [文件名称]
 * @return            [成功返回true]
 */
bool CPDTBase::loadConf(const char *filename)
{
    PRINT_DBG_HEAD
    print_dbg("load conf begin");

    int tmpint = 0;
    bool bflag = false;
    char taskid[16] = {0};
    char subitem[16] = {0};
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
    print_dbg("load conf over(%s)", bflag ? "ok" : "fail");

    return bflag;
}

/**
 * [CPDTBase::showConf 展示配置信息]
 */
void CPDTBase::showConf(void)
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
bool CPDTBase::isProtoPSIP(void)
{
    return (strcmp(m_proto, "PSIP") == 0);
}

const char *CPDTBase::getGapInIp(void)
{
    return m_gapinip;
}

const char *CPDTBase::getGapOutIp(void)
{
    return m_gapoutip;
}

/**
 * [CPDTBase::setInnerInIp 为m_innerinip赋值]
 * @param ip     [description]
 * @return       [成功返回true]
 */
bool CPDTBase::setInnerInIp(const char *ip)
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
 * [CPDTBase::setInnerOutIp 为m_inneroutip赋值]
 * @param ip     [description]
 * @return       [成功返回true]
 */
bool CPDTBase::setInnerOutIp(const char *ip)
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
 * [CPDTBase::inStart 网闸内网侧启动]
 */
void CPDTBase::inStart(void)
{
    setInIptables();
    if (initChannel() < 0) {
        PRINT_ERR_HEAD
        print_err("init channel fail");
    } else {
        startTaskThreads();
    }
}

/**
 * [CPDTBase::outStart 网闸外网侧启动]
 * 外网侧只需要设置适当的iptables，处理逻辑在内网进行
 */
void CPDTBase::outStart(void)
{
    setOutIptables();
}

/**
 * [CPDTBase::setInIptables 设置内网侧iptables]
 */
void CPDTBase::setInIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "%s -I FORWARD -s '%s' -j ACCEPT", IPTABLES, m_inneroutip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -A INPUT -p udp -d '%s' --dport '%s' -m iprange ! --src-range '%s' -j DROP",
            IPTABLES, m_gapinip, m_outport, m_incenter);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_gapinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j ACCEPT", IPTABLES, m_innerinip);
    systemCmd(chcmd);

    sprintf(chcmd, "%s -t nat -I POSTROUTING -s '%s' -j SNAT --to '%s'", IPTABLES, m_inneroutip,
            m_gapinip);
    systemCmd(chcmd);
}

/**
 * [CPDTBase::setOutIptables 设置外网侧iptables]
 */
void CPDTBase::setOutIptables(void)
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
}

/**
 * [CPDTBase::systemCmd system执行命令]
 * @param cmd  [命令]
 * @param self [本端执行，还是让对端执行]
 */
void CPDTBase::systemCmd(const char *cmd, bool self)
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
 * [CPDTBase::startTaskThreads 开启任务线程]
 */
void CPDTBase::startTaskThreads(void)
{
    PRINT_DBG_HEAD
    print_dbg("start threads");

    CBSUdpSockServer srvudp1, srvudp2;
    PPDTTASK ptask1, ptask2;

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

    ptask1 = new PDTTASK();
    ptask2 = new PDTTASK();
    if ((ptask1 == NULL) || (ptask2 == NULL)) {
        PRINT_ERR_HEAD
        print_err("new pdt task fail");
        DELETE(ptask1);
        DELETE(ptask2);
        goto _out;
    }

    ptask1->recvsock = ptask2->sendsock = sockudp1;
    ptask1->sendsock = ptask2->recvsock = sockudp2;
    ptask1->ppdt = ptask2->ppdt = this;
    ptask1->recvarea = AREA_IN_CENTER;
    ptask2->recvarea = AREA_OUT_CENTER;

    if (createThread(recvCenterPSIP, ptask1)) {
        PRINT_DBG_HEAD
        print_dbg("create thread1 ok");
    }

    if (createThread(recvCenterPSIP, ptask2)) {
        PRINT_DBG_HEAD
        print_dbg("create thread2 ok");
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("start threads over");
    return;
}

/**
 * [CPDTBase::createThread 创建启动一个线程]
 * @param  func  [线程函数]
 * @param  ptask [线程参数]
 * @return       [成功返回true]
 */
bool CPDTBase::createThread(threadfunc func, PPDTTASK ptask)
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
 * [recvCenterPSIP 接收交换中心PSIP信令 线程函数]
 * @param  para [线程参数]
 * @return      [未使用]
 */
void *recvCenterPSIP(void *para)
{
    pthread_setself("recvcenterpsip");

    PRINT_DBG_HEAD
    print_dbg("recv center PSIP begin");

    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return NULL;
    }

    int recvlen = 0;
    int sendlen = 0;
    int replen = 0;
    char buff1[PDT_MAX_PACKET];
    char buff2[PDT_MAX_PACKET];
    PPDTTASK ptask = (PPDTTASK)para;
    sockaddr_in to_addr;
    BZERO(to_addr);

    to_addr.sin_family = AF_INET;
    if (ptask->recvarea == AREA_IN_CENTER) {
        to_addr.sin_addr.s_addr = inet_addr(ptask->ppdt->m_inneroutip);
        to_addr.sin_port = htons(atoi(ptask->ppdt->m_outport));
    } else {
        to_addr.sin_addr.s_addr = inet_addr(ptask->ppdt->m_incenter);
        to_addr.sin_port = htons(atoi(ptask->ppdt->m_inport));
    }

    while (1) {
        BZERO(buff1);
        BZERO(buff2);

        recvlen = recvfrom(ptask->recvsock, buff1, sizeof(buff1), 0, NULL, NULL);
        if (recvlen <= 0) {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s],recvlen[%d],area[%d]", strerror(errno), recvlen,
                      ptask->recvarea);
            usleep(1000);
        } else {
            replen = ptask->ppdt->processData(buff1, recvlen, buff2, ptask->recvarea);
            if (replen > 0) {
                sendlen = sendto(ptask->sendsock, buff2, replen, 0,
                                 (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
                if (sendlen <= 0) {
                    PRINT_ERR_HEAD
                    print_err("sendto error[%s][%d],area[%d]",
                              strerror(errno), sendlen, ptask->recvarea);
                } else {
                    PRINT_DBG_HEAD
                    print_dbg("send[%d],area[%d]", sendlen, ptask->recvarea);
                }
            } else {
                PRINT_ERR_HEAD
                print_err("process data error[%d],area[%d]", replen, ptask->recvarea);
            }
        }
    }

    PRINT_ERR_HEAD
    print_err("You should never get here,area[%d]", ptask->recvarea);
    close(ptask->sendsock);
    close(ptask->recvsock);
    return NULL;
}

#ifdef RESEAL_SIP_INTERFACE

/**
 * [CPDTBase::findCharByKey 在字符串中查找指定字符]
 * @param  src    [字符串]
 * @param  limit  [字符串结尾]
 * @param  dst    [存放获取到一行的内容]
 * @param  offset [查找偏移位置]
 * @param  key    [字符]
 * @return        [查找指定字符经过的长度,包含c的长度]
 */
int CPDTBase::findCharByKey(const char *src, char *dst, int offset, char key)
{
    if ((src == NULL) || (NULL == dst)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    const char *limit = src + strlen(src);
    int cnt = 0;

    if (offset > limit - src) {
        cnt = -1;
        PRINT_ERR_HEAD
        print_err("offset error[%d], limit-src[%d]", offset, (int)(limit - src));
    } else {
        for (cnt = 0; (src + offset + cnt) < limit ; cnt++) {
            *dst++ = *(src + offset + cnt);
            if (*(src + offset + cnt) == key) {
                cnt++;
                break;
            }
        }
    }

    return cnt;
}


/**
 * [CPDTBase::getContentLen 获取contenlen长度]
 * @param line [数据包]
 * @param clen [存放获取到的长度]
 * @param contentlen_exist[cententlen字段是否存在]
 * @return     [成功返回0 失败返回负值]
 */
int CPDTBase::getContentLen(char *line, int *clen)
{
    if ((line == NULL) || (NULL == clen)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("begin get content len");

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    char digitbuff[MASK_STR_LEN] = {0};
    int shift = 0;
    const struct sip_handler *phandler = &sip_headers[CONTENT_LENGTH_TYPE];

    if (((ret = phandler->process(start, limit, phandler->name, phandler->len, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->cname, phandler->clen, &shift)) > 0)) {
        if (ret > (int)sizeof(digitbuff) - 1) {
            PRINT_DBG_HEAD
            print_dbg("line[%s]. digit len[%d], max support is [%d]",
                      line, ret, (int)sizeof(digitbuff) - 1);
        } else {
            goto _ok;
        }
    }

    PRINT_ERR_HEAD
    print_err("get content len fail[%s]", line);
    return -1;
_ok:
    memcpy(digitbuff, start + shift, ret);
    *clen = atoi(digitbuff);
    if (*clen) {
        BZERO(digitbuff);
        memcpy(digitbuff, start, shift);
        memset(line, 0x00, PDT_MAX_LINE_SIZE);
        memcpy(line, digitbuff, shift);
        memcpy(line + shift, "%d\r\n", 4);
    } else {
        PRINT_DBG_HEAD
        print_dbg("not replace content_len-- line[%s]", line);
    }
    PRINT_DBG_HEAD
    print_dbg("get content len over-- shift[%d], clen [%d]", shift, *clen);
    return 0;
}


/**
 * [CPDTBase::replaceMethodLine 替换请求行]
 * @param line [请求行]
 * @param area [来自哪个交换中心]
 * @return     [正常返回recvstr长度，出错为负值]
 */
int CPDTBase::replaceMethodLine(char *line, method_type mtype, int area)
{
    if ((line == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("begin replace method line [%s]", line);

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    char tmpstr[PDT_MAX_LINE_SIZE] = {0};
    const struct sip_handler *phandler = &sip_methods[mtype];

    if (((ret = phandler->process(start, limit, phandler->seach1, phandler->slen1, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach2, phandler->slen2, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach3, phandler->slen3, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach4, phandler->slen4, &shift)) > 0)) {
        memcpy(tmpstr, start, shift);
        strcat(tmpstr, (area == AREA_IN_CENTER) ? m_outcenter : m_incenter);
        strcat(tmpstr, start + shift + ret);
        memset(line, 0x00, PDT_MAX_LINE_SIZE);
        memcpy(line, tmpstr, PDT_MAX_LINE_SIZE);
    } else {
        PRINT_DBG_HEAD
        print_dbg("method line do not need to replace[%s]", line);
        return strlen(line);
    }

    PRINT_DBG_HEAD
    print_dbg("after replace method line[%s]", line);
    return strlen(line);
}


/**
 * [CPDTBase::pdtReplaceSipHeader 替换SIP的header和SDP信息]
 * @param line      [一行header字段]
 * @param pdt_sip_info  [包含SIP报文每行关键字标志和IP端口信息]
 * @param area      [区域，0来自内网,1来自外网]
 * @return          [正常返回recvstr长度，出错为负值]
 */
int CPDTBase::pdtReplaceSipHeader(char *recvstr, PDT_SIP_INFO *pdt_sip_info, int area)
{
    if ((recvstr == NULL) || (NULL == pdt_sip_info)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    header_type htype = ERR_HTYPE;
    char channelport[PORT_STR_LEN] = {0};
    char channelproxyip[IP_STR_LEN] = {0};
    char mediaport[PORT_STR_LEN] = {0};

    htype = getHeaderType(recvstr);
    switch (htype) {
    case VIA_TYPE:
        if (!pdt_sip_info->isresp) {
            replaceIP(recvstr, htype, area);
        }
        break;
    case CALLID_TYPE:
        if (getCallID(recvstr, pdt_sip_info->callid, (int)sizeof(pdt_sip_info->callid)) >= 0) {
            if (pdt_sip_info->mtype == BYE_TYPE) {
                deleteChannelByCallID(pdt_sip_info->callid);
            }
        } else {
            goto _out;
        }
        break;
    case CONTACT_TYPE:
        replaceIP(recvstr, htype, area);
        break;
    case CONTENT_LENGTH_TYPE:
        if (getContentLen(recvstr, &pdt_sip_info->contlen) < 0) {
            goto _out;
        }
        break;
    case ORIGIN_TYPE:
        if ((getOriginIP(recvstr, pdt_sip_info->originip) < 0)
            || (getChannelProxyIP(pdt_sip_info->callid, area, channelproxyip) < 0)
            || (replaceOriginIP(recvstr, pdt_sip_info->originip, channelproxyip) < 0)) {
            goto _out;
        }
        pdt_sip_info->contlen += strlen(channelproxyip) - strlen(pdt_sip_info->originip);
        break;
    case MEDIA_TYPE:
        if ((getMediaPort(recvstr, mediaport) < 0)
            || (getChannelProxyPort(pdt_sip_info->callid, area, pdt_sip_info->originip, \
                                    mediaport, pdt_sip_info->isresp, channelport) < 0)
            || (replaceMediaPort(recvstr, mediaport, channelport) < 0)) {
            goto _out;
        }
        pdt_sip_info->contlen += strlen(channelport) - strlen(mediaport);
        break;
    default:
        break;
    }

    return strlen(recvstr);
_out:
    PRINT_DBG_HEAD
    print_dbg("process pdt header faile. line[%s]", recvstr);
    return -1;
}

/**
 * [CPDTBase::processData 处理数据包信息]
 * @param  src  [待处理数据包]
 * @param  len  [src数据包长度]
 * @param  dst  [目的缓冲区]
 * @param  area [区域，来自哪个交换中心]
 * @return      [成功返回dst中信息长度,失败返回负值]
 */
int CPDTBase::processData(const char *src, int len, char *dst, int area)
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
    bool filter;
    char recvstr[PDT_MAX_LINE_SIZE] = {0};
    char tmpdst[PDT_MAX_PACKET] = {0};
    PDT_SIP_INFO pdt_sip_info;

    memset(&pdt_sip_info, 0x00, sizeof(PDT_SIP_INFO));
    pdt_sip_info.mtype = ERR_MTYPE;

    while (1) {
        BZERO(recvstr);
        if (part >= PDT_MAX_LINE_NUM) {
            PRINT_ERR_HEAD
            print_err("part[%d] should be less than %d", part, PDT_MAX_LINE_NUM);
            return -1;
        }

        res = findCharByKey(src, recvstr, ipos, '\n');
        if (res <= 0) {
            break;
        } else if (res >= PDT_MAX_LINE_SIZE - PDT_LINE_LEN_CHANGE) {
            PRINT_ERR_HEAD
            print_err("line size should be less than %d,actual is %d",
                      PDT_MAX_LINE_SIZE - PDT_LINE_LEN_CHANGE, res);
            return -1;
        }

        part++;
        ipos += res;

        //process method
        if (1 == part) {
            pdt_sip_info.isresp = isResponse(recvstr);
            if (!(pdt_sip_info.isresp)) {
                if ((pdt_sip_info.mtype = getMethodType(recvstr)) == ERR_MTYPE) {
                    goto _out;
                }
                filter = fileterCmd(sip_methods[pdt_sip_info.mtype].name);
                recordCallLog(sip_methods[pdt_sip_info.mtype].name, filter, area);
                if (!filter) {
                    goto _out;
                }
                res = replaceMethodLine(recvstr, pdt_sip_info.mtype, area);
                if (res < 0) {
                    PRINT_ERR_HEAD
                    print_err("error res replaceMethodLine [%d]\n", res);
                    return -1;
                }
            }
        } else {
            //process headers
            res = pdtReplaceSipHeader(recvstr, &pdt_sip_info, area);
            if (res < 0) {
                PRINT_ERR_HEAD
                print_err("error res pdtReplaceSipHeader [%d]\n", res);
                return -1;
            }
        }

        memcpy(tmpdst + dstlen, recvstr, res);
        dstlen += res;
    }

    //将替换后的SDP长度写入，否则SIP会报错
    if (pdt_sip_info.contlen) {
        sprintf(dst, tmpdst, pdt_sip_info.contlen);
    } else {
        memcpy(dst, tmpdst, dstlen);
    }

    dstlen = strlen(dst);
    res = (int)strlen(src);
    if (res < len) {
        memcpy(dst + dstlen, src + res, len - res);
        dstlen += len - res;
    }

_out:
    PRINT_DBG_HEAD
    print_dbg("process data over. ret[%s]", dst);
    return dstlen;
}

#else
/**
 * [CPDTBase::separateLines 把数据包分行]
 * @param  src       [数据包]
 * @param  len       [数据包长度]
 * @param  strarray  [存放分行后结果的数组]
 * @param  arraysize [数组大小]
 * @return           [成功返回行数，失败返回负值]
 */
int CPDTBase::separateLines(const char *src, int len, char **strarray, int arraysize)
{
    PRINT_DBG_HEAD
    print_dbg("separate lines begin. datalen[%d],arraysize[%d]", len, arraysize);

    int part = 0;
    int ipos = 0;
    int res = 0;
    const char *limit = src + len;

    while (1) {
        if (part >= arraysize) {
            PRINT_ERR_HEAD
            print_err("part[%d] should be less than %d", part, arraysize);
            goto _err;
        }

        res = findCharByKey(src, limit, ipos, '\n');
        if (res <= 0) {
            break;
        } else if (res >= PDT_MAX_LINE_SIZE - PDT_LINE_LEN_CHANGE) {
            PRINT_ERR_HEAD
            print_err("line size should be less than %d,actual is %d",
                      PDT_MAX_LINE_SIZE - PDT_LINE_LEN_CHANGE, res);
            goto _err;
        }

        strarray[part] = new char[PDT_MAX_LINE_SIZE];
        if (strarray[part] == NULL) {
            PRINT_ERR_HEAD
            print_err("new char fail, part[%d]", part);
            goto _err;
        }
        memset(strarray[part], 0, PDT_MAX_LINE_SIZE);
        memcpy(strarray[part], src + ipos, res);
        part++;
        ipos += res;
    }

    PRINT_DBG_HEAD
    print_dbg("separate lines over. part[%d]", part);
    return part;
_err:
    return -1;
}

/**
 * [CPDTBase::getContentLen 获取contenlen长度]
 * @param line [数据包]
 * @param clen [存放获取到的长度]
 * @param shift[数字相对行首的偏移量]
 * @return     [成功返回0 失败返回负值]
 */
int CPDTBase::getContentLen(const char *line, int *clen, int *shift)
{
    PRINT_DBG_HEAD
    print_dbg("begin get content len");

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    char digitbuff[16] = {0};
    const struct sip_handler *phandler = &sip_headers[CONTENT_LENGTH_TYPE];

    if (((ret = phandler->process(start, limit, phandler->name, phandler->len, shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->cname, phandler->clen, shift)) > 0)) {

        if (ret > (int)sizeof(digitbuff) - 1) {
            PRINT_DBG_HEAD
            print_dbg("line[%s]. digit len[%d], max support is [%d]",
                      line, ret, (int)sizeof(digitbuff) - 1);
        } else {
            goto _ok;
        }
    }

    PRINT_ERR_HEAD
    print_err("get content len fail[%s]", line);
    return -1;
_ok:
    memcpy(digitbuff, start + (*shift), ret);
    *clen = atoi(digitbuff);
    PRINT_DBG_HEAD
    print_dbg("get content len over[%s] [%d]", digitbuff, *clen);
    return 0;
}

/**
 * [CPDTBase::findCharByKey 在字符串中查找指定字符]
 * @param  src    [字符串]
 * @param  limit  [字符串结尾]
 * @param  offset [查找偏移位置]
 * @param  key    [字符]
 * @return        [查找指定字符经过的长度,包含c的长度]
 */
int CPDTBase::findCharByKey(const char *src, const char *limit, int offset, char key)
{
    int cnt = 0;

    if (offset > limit - src) {
        cnt = -1;
        PRINT_ERR_HEAD
        print_err("offset error[%d], limit-src[%d]", offset, (int)(limit - src));
    } else {
        for (cnt = 0; (src + offset + cnt) < limit ; cnt++) {
            if (*(src + offset + cnt) == key) {
                cnt++;
                break;
            }
        }
    }

    return cnt;
}

/**
 * [CPDTBase::replaceMethodLine 替换请求行]
 * @param line [请求行]
 * @param area [来自哪个交换中心]
 */
void CPDTBase::replaceMethodLine(char *line, method_type mtype, int area)
{
    PRINT_DBG_HEAD
    print_dbg("begin replace method line [%s]", line);

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    char tmpstr[PDT_MAX_LINE_SIZE] = {0};
    const struct sip_handler *phandler = &sip_methods[mtype];

    if (((ret = phandler->process(start, limit, phandler->seach1, phandler->slen1, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach2, phandler->slen2, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach3, phandler->slen3, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach4, phandler->slen4, &shift)) > 0)) {
        goto _ok;
    }

    PRINT_DBG_HEAD
    print_dbg("method line do not need to replace[%s]", line);
    return;
_ok:
    memcpy(tmpstr, start, shift);
    strcat(tmpstr, (area == AREA_IN_CENTER) ? m_outcenter : m_incenter);
    strcat(tmpstr, start + shift + ret);
    memset(line, 0x00, PDT_MAX_LINE_SIZE);
    memcpy(line, tmpstr, PDT_MAX_LINE_SIZE);

    PRINT_DBG_HEAD
    print_dbg("after replace method line[%s]", line);
    return;
}

/**
 * [CPDTBase::processData 处理数据包信息]
 * @param  src  [待处理数据包]
 * @param  len  [src数据包长度]
 * @param  dst  [目的缓冲区]
 * @param  area [区域，来自哪个交换中心]
 * @return      [成功返回dst中信息长度,失败返回负值]
 */
int CPDTBase::processData(const char *src, int len, char *dst, int area)
{
    PRINT_DBG_HEAD
    print_dbg("process data begin. datalen[%d]", len);

    int ret = -1;
    int part = 0;
    bool isresp, filter;
    int contentid = -1, contentlen = 0, contenshift = 0;
    method_type mtype = ERR_MTYPE;
    header_type htype = ERR_HTYPE;
    char mediaport[6] = {0}, channelport[6] = {0};
    char originip[IP_STR_LEN] = {0};
    char channelproxyip[IP_STR_LEN] = {0};
    char callid[PDT_CALL_ID_LEN] = {0};
    char *recvstr[PDT_MAX_LINE_NUM];
    BZERO(recvstr);

    part = separateLines(src, strlen(src), recvstr, PDT_MAX_LINE_NUM);
    if (part <= 0) {
        goto _out;
    }
    //process method
    isresp = isResponse(recvstr[0]);
    if (!isresp) {
        if ((mtype = getMethodType(recvstr[0])) == ERR_MTYPE) {
            goto _out;
        }
        filter = fileterCmd(sip_methods[mtype].name);
        recordCallLog(sip_methods[mtype].name, filter, area);
        if (!filter) {
            goto _out;
        }
        replaceMethodLine(recvstr[0], mtype, area);
    }
    //process headers
    for (int i = 1; i < part; i++) {
        htype = getHeaderType(recvstr[i]);
        switch (htype) {
        case VIA_TYPE:
            if (!isresp) {
                replaceIP(recvstr[i], htype, area);
            }
            break;
        case CALLID_TYPE:
            if (getCallID(recvstr[i], callid, (int)sizeof(callid)) < 0) {
                goto _out;
            } else if (mtype == BYE_TYPE) {
                deleteChannelByCallID(callid);
            }
            break;
        case CONTACT_TYPE:
            replaceIP(recvstr[i], htype, area);
            break;
        case CONTENT_LENGTH_TYPE:
            contentid = i;
            if (getContentLen(recvstr[i], &contentlen, &contenshift) < 0) {
                goto _out;
            }
            break;
        case ORIGIN_TYPE:
            if ((getOriginIP(recvstr[i], originip) < 0)
                || (getChannelProxyIP(callid, area, channelproxyip) < 0)
                || (replaceOriginIP(recvstr[i], originip, channelproxyip) < 0)) {
                goto _out;
            }
            contentlen += strlen(channelproxyip) - strlen(originip);
            break;
        case MEDIA_TYPE:
            if ((getMediaPort(recvstr[i], mediaport) < 0)
                || (getChannelProxyPort(callid, area, originip, mediaport, isresp, channelport) < 0)
                || (replaceMediaPort(recvstr[i], mediaport, channelport) < 0)) {
                goto _out;
            }
            contentlen += strlen(channelport) - strlen(mediaport);
            break;
        default:
            break;
        }
    }
    //rebuild contentlen
    if ((contentid > 0) && (contentlen > 0)) {
        sprintf(recvstr[contentid] + contenshift, "%d\r\n", contentlen);
    }
    //make dst string
    for (int i = 0; i < part; i++) {
        strcat(dst, recvstr[i]);
    }
    ret = strlen(dst);
    if ((int)strlen(src) < len) {
        memcpy(dst + strlen(dst), src + strlen(src), len - strlen(src));
        ret += len - strlen(src);
    }

_out :
    DELETE_N(recvstr, PDT_MAX_LINE_NUM);
    PRINT_DBG_HEAD
    print_dbg("process data over. ret[%d]", ret);
    return ret;
}
#endif

/**
 * [CPDTBase::isResponse 是否为响应]
 * @param  line [数据包内容]
 * @return     [是返回true]
 */
bool CPDTBase::isResponse(const char *line)
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
    return bflag;
}

/**
 * [CPDTBase::getMethodType 获取信令类型]
 * @param  line [数据包]
 * @return      [信令类型]
 */
method_type CPDTBase::getMethodType(const char *line)
{
    int mlen = string_len(line, line + strlen(line));
    if (mlen <= 0 || mlen >= METHOD_MAX_LEN) {
        PRINT_ERR_HEAD
        print_err("get method fail[%s], string len ret[%d]", line, mlen);
        return ERR_MTYPE;
    }

    PRINT_DBG_HEAD
    print_dbg("mlen[%d], method arraysize[%d]", mlen, (int)(ARRAY_SIZE(sip_methods)));

    for (int i = 0; i < (int)ARRAY_SIZE(sip_methods); i++) {
        if ((strncmp(line, sip_methods[i].name, mlen) == 0)
            || ((sip_methods[i].cname != NULL) && (strncmp(line, sip_methods[i].cname, mlen) == 0))) {
            return (method_type)i;
        }
    }

    PRINT_ERR_HEAD
    print_err("get method fail[%s]", line);
    return ERR_MTYPE;
}

/**
 * [CPDTBase::fileterCmd 过滤命令]
 * @param  chcmd [待过滤的命令]
 * @return       [允许通过发货true]
 */
bool CPDTBase::fileterCmd(const char *chcmd)
{
    bool bflag = m_defaultaction;
    for (int i = 0; i < m_cmdnum; i++) {
        if (strcasecmp(chcmd, m_cmd[i]->m_cmd) == 0) {
            bflag = m_cmd[i]->m_action;
            break;
        }
    }

    if (!bflag) {
        PRINT_ERR_HEAD
        print_err("method[%s] not allow to pass through", chcmd);
    }

    return bflag;
}

/**
 * [CPDTBase::recordCallLog 记录访问日志]
 * @param chcmd      [信令]
 * @param result     [是否放行]
 * @param area       [0为来自内网交换中心]
 */
void CPDTBase::recordCallLog(const char *chcmd, bool result, int area)
{
    if (g_iflog || g_syslog) {
        CallLogPara *p = new CallLogPara;
        if (p != NULL) {
            if (p->SetValues("", (area == AREA_IN_CENTER) ? m_incenter : m_outcenter,
                             (area == AREA_IN_CENTER) ? m_outcenter : m_incenter,
                             (area == AREA_IN_CENTER) ? m_inport : m_outport,
                             (area == AREA_IN_CENTER) ? m_outport : m_inport,
                             "", "",
                             LOG_TYPE_PDT, chcmd, "", result ? D_SUCCESS : D_REFUSE,
                             result ? "" : LOG_CONTENT_REFUSE)) {
                LogContainer &s1 = LogContainer::GetInstance();
                s1.PutPara(p);
            } else {
                PRINT_ERR_HEAD
                print_err("set values fail[sip %s, dip %s, sport %s, dport %s, %s:%s]",
                          (area == AREA_IN_CENTER) ? m_incenter : m_outcenter,
                          (area == AREA_IN_CENTER) ? m_outcenter : m_incenter,
                          (area == AREA_IN_CENTER) ? m_inport : m_outport,
                          (area == AREA_IN_CENTER) ? m_outport : m_inport,
                          LOG_TYPE_PDT, chcmd);
                delete p;
            }
        }
    }
    return;
}

/**
 * [CPDTBase::getHeaderType 获取头部类型]
 * @param  line [数据包]
 * @return      [头部类型]
 */
header_type CPDTBase::getHeaderType(const char *line)
{
    header_type type = ERR_HTYPE;

    for (int i = 0; i < (int)ARRAY_SIZE(sip_headers); i++) {
        if ((strncmp(line, sip_headers[i].name, sip_headers[i].len) == 0)
            || ((sip_headers[i].cname != NULL)
                && (strncmp(line, sip_headers[i].cname, sip_headers[i].clen) == 0))) {
            type = (header_type)i;
            PRINT_DBG_HEAD
            print_dbg("get header type, result[%d]", type);
            break;
        }
    }

    return type;
}

/**
 * [CPDTBase::replaceIP 替换IP地址]
 * @param line [数据包]
 * @param htype[头部类型]
 * @param area [来自哪个交换中心]
 */
void CPDTBase::replaceIP(char *line, header_type htype, int area)
{
    PRINT_DBG_HEAD
    print_dbg("begin replace ip, line[%s], htype[%d]", line, htype);

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    char tmpstr[PDT_MAX_LINE_SIZE] = {0};
    const struct sip_handler *phandler = &sip_headers[htype];

    if (((ret = phandler->process(start, limit, phandler->seach1, phandler->slen1, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach2, phandler->slen2, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach3, phandler->slen3, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->seach4, phandler->slen4, &shift)) > 0)) {
        goto _ok;
    }

    PRINT_DBG_HEAD
    print_dbg("no need to replace ip[%s], htype[%d]", line, htype);
    return;

_ok:
    if ((htype == VIA_TYPE) || (htype == CONTACT_TYPE) ) {
        memcpy(tmpstr, start, shift);
        strcat(tmpstr, (area == AREA_IN_CENTER) ? m_gapoutip : m_gapinip);
        strcat(tmpstr, start + shift + ret);
        memset(line, 0x00, PDT_MAX_LINE_SIZE);
        memcpy(line, tmpstr, PDT_MAX_LINE_SIZE);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown type[%d]", htype);
    }

    PRINT_DBG_HEAD
    print_dbg("after replace ip[%s], htype[%d]", line, htype);
    return;
}

/**
 * [CPDTBase::getCallID 获取CALLID]
 * @param line    [数据包]
 * @param callid  [存放callid的缓冲区]
 * @param clen    [缓冲区长度]
 * @return        [成功返回0 失败返回负值]
 */
int CPDTBase::getCallID(const char *line, char *callid, int clen)
{
    PRINT_DBG_HEAD
    print_dbg("begin get callid");

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    const struct sip_handler *phandler = &sip_headers[CALLID_TYPE];

    if (((ret = phandler->process(start, limit, phandler->name, phandler->len, &shift)) > 0)
        || ((ret = phandler->process(start, limit, phandler->cname, phandler->clen, &shift)) > 0)) {

        if (ret > clen - 1) {
            PRINT_DBG_HEAD
            print_dbg("line[%s].callid len is [%d], max support is [%d]",
                      line, ret, clen - 1);
        } else {
            if (ret > PDT_STD_CALL_ID_LEN) {
                PRINT_INFO_HEAD
                print_info("line[%s].callid len is [%d], violate standard regulation[%d]",
                           line, ret, PDT_STD_CALL_ID_LEN);
            }
            goto _ok;
        }
    }

    PRINT_ERR_HEAD
    print_err("get callid fail[%s]", line);
    return -1;
_ok:
    memcpy(callid, start + shift, ret);
    PRINT_DBG_HEAD
    print_dbg("get callid over[%s]", callid);
    return 0;
}

/**
 * [CPDTBase::getOriginIP 获取会话发起方IP]
 * @param  line     [数据包]
 * @param  originip [会话发起方IP]
 * @return          [成功返回0 失败返回负值]
 */
int CPDTBase::getOriginIP(const char *line, char *originip)
{
    PRINT_DBG_HEAD
    print_dbg("begin get origin ip");

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    const struct sip_handler *phandler = &sip_headers[ORIGIN_TYPE];

    if ((ret = phandler->process(start, limit, phandler->name, phandler->len, &shift)) > 0) {
        if (ret > IP_STR_LEN - 1) {
            PRINT_DBG_HEAD
            print_dbg("line[%s]. originip len[%d], max support is [%d]",
                      line, ret, IP_STR_LEN - 1);
        } else {
            goto _ok;
        }
    }

    PRINT_ERR_HEAD
    print_err("get originip fail[%s]", line);
    return -1;
_ok:
    memcpy(originip, start + shift, ret);
    PRINT_DBG_HEAD
    print_dbg("get originip over[%s]", originip);
    return 0;
}

/**
 * [CPDTBase::replaceOriginIP 替换origin IP]
 * @param  line           [数据包]
 * @param  originip       [originip]
 * @param  channelproxyip [通道代理IP]
 * @return                [成功返回0 失败返回负值]
 */
int CPDTBase::replaceOriginIP(char *line, const char *originip, const char *channelproxyip)
{
    PRINT_DBG_HEAD
    print_dbg("begin replace origin ip. line[%s],originip[%s],proxyip[%s]",
              line, originip, channelproxyip);

    char tmpstr[PDT_MAX_LINE_SIZE] = {0};
    const char *ptr = strstr(line, originip);
    if (ptr != NULL) {
        memcpy(tmpstr, line, ptr - line);
        memcpy(tmpstr + (ptr - line), channelproxyip, strlen(channelproxyip));
        strcat(tmpstr, ptr + strlen(originip));
        memset(line, 0x00, PDT_MAX_LINE_SIZE);
        memcpy(line, tmpstr, PDT_MAX_LINE_SIZE);

        PRINT_DBG_HEAD
        print_dbg("replace origin ip over. line[%s]", line);
        return 0;
    }
    PRINT_ERR_HEAD
    print_err("replace origin ip fail. line[%s]", line);
    return -1;
}

/**
 * [CPDTBase::getMediaPort 获取媒体端口号]
 * @param  line [数据包]
 * @param  port [出参]
 * @return      [成功返回0 失败返回负值]
 */
int CPDTBase::getMediaPort(const char *line, char *port)
{
    PRINT_DBG_HEAD
    print_dbg("begin get media port.[%s]", line);

    const char *start = line;
    const char *limit = line + strlen(line);
    int ret = 0;
    int shift = 0;
    const struct sip_handler *phandler = &sip_headers[MEDIA_TYPE];

    if ((ret = phandler->process(start, limit, phandler->name, phandler->len, &shift)) > 0) {
        if (ret > 5) {
            PRINT_DBG_HEAD
            print_dbg("line[%s]. media port len[%d], max support is [5]", line, ret);
        } else {
            goto _ok;
        }
    }

    PRINT_ERR_HEAD
    print_err("get media port fail. line[%s]", line);
    return -1;
_ok:
    memcpy(port, start + shift, ret);
    PRINT_DBG_HEAD
    print_dbg("get media port over[%s]", port);
    return 0;
}

/**
 * [CPDTBase::replaceMediaPort 替换通道端口号]
 * @param  line        [数据包]
 * @param  mediaport   [媒体端口号]
 * @param  channelport [替换之后的端口号]
 * @return             [成功返回0 失败返回负值]
 */
int CPDTBase::replaceMediaPort(char *line, const char *mediaport, const char *channelport)
{
    PRINT_DBG_HEAD
    print_dbg("begin replace media port. line[%s],mediaport[%s],channelport[%s]",
              line, mediaport, channelport);

    char tmpstr[PDT_MAX_LINE_SIZE] = {0};
    const char *ptr = strstr(line, mediaport);
    if (ptr != NULL) {
        memcpy(tmpstr, line, ptr - line);
        memcpy(tmpstr + (ptr - line), channelport, strlen(channelport));
        strcat(tmpstr, ptr + strlen(mediaport));
        memset(line, 0x00, PDT_MAX_LINE_SIZE);
        memcpy(line, tmpstr, PDT_MAX_LINE_SIZE);

        PRINT_DBG_HEAD
        print_dbg("replace media port over. line[%s]", line);
        return 0;
    }

    PRINT_ERR_HEAD
    print_err("replace media port fail. line[%s]", line);
    return -1;
}

/**
 * [CPDTBase::getSecway 返回安全通道]
 * @return  [安全通道的引用]
 */
SEC_WAY &CPDTBase::getSecway(void)
{
    return m_secway;
}
