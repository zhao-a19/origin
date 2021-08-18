/*******************************************************************************************
*文件:  appmatch.cpp
*描述:  匹配应用模块
*作者:  王君雷
*日期:  2018-12-20
*修改:
*       地址端口的匹配使用结构而不使用立即数                       ------> 2018-12-28
*       解决IPV6校验和计算有误的问题                               ------> 2019-04-09
*       WEB代理支持ipv6                                            ------> 2019-05-21
*       WEB代理支持分模块生效                                       ------> 2020-11-18
*******************************************************************************************/
#include <arpa/inet.h>
#include "appmatch.h"
#include "debugout.h"
#include "network.h"
#include "FCDCSOPCSingle.h"

CSINGLE *g_tcpapp[C_APPSINGLE_MAXNUM];
CSINGLE *g_udpapp[C_APPSINGLE_MAXNUM];
CSINGLE *g_icmpapp;
CSINGLE *g_icmpv6app;
volatile int g_tcpappnum = 0;
volatile int g_udpappnum = 0;
volatile int g_icmpappnum = 0;
volatile int g_icmpv6appnum = 0;
bool rechecksum(uint8 *buff, int flag);
bool rechecksum_ipv6(uint8 *buff, int offsetlen, uint8 proto);
uint16 checksum(uint16 *buffer, int size);

/**
 * [DoMsgIPv4TCP 调用TCP应用对象 去解析处理应用层信息 ipv4]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv4TCP(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    PIP_HEADER pip = (PIP_HEADER)umsg;
    PTCP_HEADER ptcp = _tcpipdata(umsg);
    int fromsrc = 1;
    bool bflag = false; //返回值

    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (g_tcpapp[i]->Match(ntohs(ptcp->th_dport), pip->ip_dst,
                                   ntohs(ptcp->th_sport), pip->ip_src, fromsrc))) {
            bflag = g_tcpapp[i]->DoMsg(umsg, msglen, cherror, pktchanged, fromsrc);
            if (*pktchanged == PACKET_CHANGED) {
                rechecksum(umsg, 1);
            }
            return bflag;
        }
    }

    //webproxy的数据都放在了0号队列
    if (queuenum == 0) {
        sem_wait(&g_weblock);
        for (int i = 0; i < g_webappnum; i++) {
            if (g_webapp[i]->IfMatch(ntohs(ptcp->th_dport), pip->ip_dst)) {
                bflag = g_webapp[i]->DoMsg(umsg, msglen);
                sem_post(&g_weblock);
                return bflag;
            }
        }
        sem_post(&g_weblock);
    }

    //能否匹配上OPC动态端口
    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (strcmp(g_tcpapp[i]->GetService()->m_asservice, "OPC") == 0)) {
            int index = 0;
            if (((CDCSOPCSINGLE *)g_tcpapp[i])->IfMatchDynamic(umsg, index)) {
                return ((CDCSOPCSINGLE *)g_tcpapp[i])->DoMsgDY(umsg, msglen, cherror, pktchanged, index);
            }
        }
    }

    //全部都匹配不上的数据包，按ORACLE重定向的来处理
    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (strcmp(g_tcpapp[i]->GetService()->m_asservice, "ORACLE") == 0)) {
            return g_tcpapp[i]->DoMsg(umsg, msglen, cherror, pktchanged, 1);
        }
    }

    PRINT_ERR_HEAD
    print_err("tcp no match rule. msglen = %d, g_tcpappnum=%d g_webappnum=%d", msglen, g_tcpappnum,
              g_webappnum);
    return false;
}

/**
 * [DoMsgIPv4UDP 调用UDP应用对象 去解析处理应用层信息 ipv4]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv4UDP(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    PIP_HEADER pip = (PIP_HEADER)umsg;
    PUDP_HEADER pudp = _udpipdata(umsg);
    int fromsrc = 1;
    bool bflag = false;//返回值

    for (int i = 0; i < g_udpappnum; i++) {
        if (g_udpapp[i]->QueueNumEqual(queuenum)
            && (g_udpapp[i]->Match(ntohs(pudp->uh_dport), pip->ip_dst,
                                   ntohs(pudp->uh_sport), pip->ip_src, fromsrc))) {
            bflag = g_udpapp[i]->DoMsg(umsg, msglen, cherror, pktchanged, fromsrc);
            if (*pktchanged == PACKET_CHANGED) {
                rechecksum(umsg, 1);
            }
            return bflag;
        }
    }

    PRINT_ERR_HEAD
    print_err("udp no match rule. msglen = %d, g_udpappnum=%d",  msglen, g_udpappnum);
    return false;
}

/**
 * [DoMsgIPv4ICMP 调用ICMP应用对象 去解析处理应用层信息 icmp]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv4ICMP(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    if (g_icmpappnum > 0) {
        return g_icmpapp->DoMsg(umsg, msglen, cherror, pktchanged, -1);
    }

    PRINT_ERR_HEAD
    print_err("icmp no match rule. msglen = %d, g_icmpappnum = %d",  msglen, g_icmpappnum);
    return false;
}

/**
 * [DoMsgIPv4 调用应用对象 去解析处理应用层信息 IPv4]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv4(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    switch (IPV4_PROTO(umsg)) {
    case TCP:
        return DoMsgIPv4TCP(umsg, msglen, cherror, pktchanged, queuenum);
        break;
    case UDP:
        return DoMsgIPv4UDP(umsg, msglen, cherror, pktchanged, queuenum);
        break;
    case ICMP:
        return DoMsgIPv4ICMP(umsg, msglen, cherror, pktchanged, queuenum);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown ipv4 proto.no match rule. msglen = %d, queuenum = %d", msglen, queuenum);
        return false;
        break;
    }
    return false;
}

/**
 * [DoMsgIPv6TCP 调用TCP应用对象 去解析处理应用层信息 ipv6]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  offsetlen  [TCP头部偏移量]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv6TCP(uint8 *umsg, int msglen, int offsetlen, char *cherror, int *pktchanged, int queuenum)
{
    PIPV6_HEADER pipv6 = (PIPV6_HEADER)umsg;
    PTCP_HEADER ptcp = (PTCP_HEADER)(umsg + offsetlen);

    int fromsrc = 1;
    bool bflag = false;//返回值

    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (g_tcpapp[i]->MatchIPv6(ntohs(ptcp->th_dport), pipv6->ip_dst,
                                       ntohs(ptcp->th_sport), pipv6->ip_src, fromsrc))) {
            bflag = g_tcpapp[i]->DoMsgIPV6(umsg, msglen, offsetlen, cherror, pktchanged, fromsrc);
            if (*pktchanged == PACKET_CHANGED) {
                rechecksum_ipv6(umsg, offsetlen, TCP);
            }
            return bflag;
        }
    }
    //webproxy的数据都放在了0号队列
    if (queuenum == 0) {
        //PRINT_DBG_HEAD
        //print_dbg("begin to match webproxy ipv6...");
        for (int i = 0; i < g_webappnum; i++) {
            if (g_webapp[i]->IfMatchIPv6(ntohs(ptcp->th_dport), pipv6->ip_dst)) {
                //PRINT_DBG_HEAD
                //print_dbg("has matched webproxy ipv6...");
                return g_webapp[i]->DoMsgIPv6(umsg, msglen, offsetlen);
            }
        }
    }
#if 0
    //能否匹配上OPC动态端口
    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (strcmp(g_tcpapp[i]->GetService()->m_asservice, "OPC") == 0)) {
            int index = 0;
            if (((CDCSOPCSINGLE *)g_tcpapp[i])->IfMatchDynamic(umsg, index)) {
                return ((CDCSOPCSINGLE *)g_tcpapp[i])->DoMsgDY(umsg, msglen, cherror, pktchanged, index);
            }
        }
    }

    //全部都匹配不上的数据包，按ORACLE重定向的来处理
    for (int i = 0; i < g_tcpappnum; i++) {
        if (g_tcpapp[i]->QueueNumEqual(queuenum)
            && (strcmp(g_tcpapp[i]->GetService()->m_asservice, "ORACLE") == 0)) {
            return g_tcpapp[i]->DoMsg(umsg, msglen, cherror, pktchanged, 1);
        }
    }
#endif
    PRINT_ERR_HEAD
    print_err("tcp no match rule. msglen = %d, g_tcpappnum=%d g_webappnum=%d", msglen, g_tcpappnum,
              g_webappnum);
    return false;
}

/**
 * [DoMsgIPv6UDP 调用UDP应用对象 去解析处理应用层信息 ipv6]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  offsetlen  [UDP头部偏移量]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv6UDP(uint8 *umsg, int msglen, int offsetlen, char *cherror, int *pktchanged, int queuenum)
{
    PIPV6_HEADER pipv6 = (PIPV6_HEADER)umsg;
    PUDP_HEADER pudp = (PUDP_HEADER)(umsg + offsetlen);

    int fromsrc = 1;
    bool bflag = false; //返回值

    for (int i = 0; i < g_udpappnum; i++) {
        if (g_udpapp[i]->QueueNumEqual(queuenum)
            && (g_udpapp[i]->MatchIPv6(ntohs(pudp->uh_dport), pipv6->ip_dst,
                                       ntohs(pudp->uh_sport), pipv6->ip_src, fromsrc))) {
            bflag = g_udpapp[i]->DoMsgIPV6(umsg, msglen, offsetlen, cherror, pktchanged, fromsrc);
            if (*pktchanged == PACKET_CHANGED) {
                rechecksum_ipv6(umsg , offsetlen, UDP);
            }
            return bflag;
        }
    }

    PRINT_ERR_HEAD
    print_err("udp no match rule. msglen = %d, g_udpappnum=%d",  msglen, g_udpappnum);
    return false;
}

/**
 * [DoMsgIPv6ICMP 调用应用对象 去解析处理应用层信息 icmpv6]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  offsetlen  [ICMPv6头部偏移量]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv6ICMP(uint8 *umsg, int msglen, int offsetlen, char *cherror, int *pktchanged, int queuenum)
{
    if (g_icmpv6appnum > 0) {
        return g_icmpv6app->DoMsgIPV6(umsg, msglen, offsetlen, cherror, pktchanged, -1);
    }

    PRINT_ERR_HEAD
    print_err("icmpv6 no match rule. msglen = %d, g_icmpv6appnum = %d",  msglen, g_icmpv6appnum);
    return false;
}

/**
 * [DoMsgIPv6 调用应用对象 去解析处理应用层信息 IPv6]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsgIPv6(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    uint8 proto = 0;
    int len = get_ipv6_ext_headerlen(umsg, msglen, &proto);
    if (len < 0) {
        PRINT_ERR_HEAD
        print_err("get ipv6 ext headerlen fail[%d:%d] queuenum[%d]", len, proto, queuenum);
        return true;
    }

    switch (proto) {
    case TCP:
        return DoMsgIPv6TCP(umsg, msglen, len, cherror, pktchanged, queuenum);
        break;
    case UDP:
        return DoMsgIPv6UDP(umsg, msglen, len, cherror, pktchanged, queuenum);
        break;
    case ICMPV6:
        return DoMsgIPv6ICMP(umsg, msglen, len, cherror, pktchanged, queuenum);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown ipv6 proto[%d].no match rule. msglen[%d] queuenum[%d]", proto, msglen, queuenum);
        return false;
        break;
    }
}

/**
 * [DoMsg 调用应用对象 去解析处理应用层信息]
 * @param  umsg       [IP头开始的数据]
 * @param  msglen     [数据长度]
 * @param  cherror    [出错信息 出参]
 * @param  pktchanged [包内容是否被改变过]
 * @param  queuenum   [队列号]
 * @return            [允许通过返回true]
 */
bool DoMsg(uint8 *umsg, int msglen, char *cherror, int *pktchanged, int queuenum)
{
    if (_ipv4(umsg)) {
        return DoMsgIPv4(umsg, msglen, cherror, pktchanged, queuenum);
    } else if (_ipv6(umsg)) {
        return DoMsgIPv6(umsg, msglen, cherror, pktchanged, queuenum);
    } else {
        PRINT_ERR_HEAD
        print_err("unknown proto.no match rule. msglen = %d", msglen);
        return false;
    }
}

/**
 * [checksum_seudo 计算带伪首部的校验和]
 * @param  ppseudohd[伪首部指针]
 * @param  hdlen    [伪首部长度]
 * @param  buff     [缓冲区指针]
 * @param  len      [缓冲区长度]
 * @return          [校验和值]
 */
uint16 checksum_pseudo(const uint8 *ppseudohd, int hdlen, const uint8 *buff, int len)
{
    if ((ppseudohd == NULL) || (buff == NULL) || (len <= 0) || (hdlen <= 0)) {
        PRINT_ERR_HEAD
        print_err("checksum pseudo para error. len = %d, hdlen = %d", len, hdlen);
        return 0;
    }
    uint8 *data = (uint8 *)malloc(len + hdlen);
    if (data == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc fail. %d", len + hdlen);
        return 0;
    }
    memcpy(data, ppseudohd, hdlen);
    memcpy(data + hdlen, buff, len);

    uint16 sum = checksum((uint16 *)data, hdlen + len);
    free(data);
    return sum;
}

/**
 * [rechecksum 重新计算校验和]
 * @param  buff [ip头部开始的数据包]
 * @param  flag [计算UDP包时用到 UDP的校验和是可选的]
 * @return      [成功返回true]
 */
bool rechecksum(uint8 *buff, int flag)
{
    PRINT_DBG_HEAD
    print_dbg("begin to recheck sum");

    uint16 sum = 0;
    uint16 IPHeadLen = _ipheadlen(buff);
    uint16 IPLen = _iplen(buff);

    PRINT_DBG_HEAD
    print_dbg("ipheadlen %d, iplen %d", IPHeadLen, IPLen);

    PIP_HEADER pip = (PIP_HEADER)buff;

    PRINT_DBG_HEAD
    print_dbg("before repalace ip_sum %x", pip->ip_sum);

    pip->ip_sum = 0;
    sum = checksum((uint16 *)buff, IPHeadLen);
    pip->ip_sum = sum;

    PRINT_DBG_HEAD
    print_dbg("after repalace ip_sum %x", pip->ip_sum);

    if (IS_IPV4TCP(buff)) {
        PSEUDO_HEADER pseudo_header;
        memcpy(&(pseudo_header.ip_src), &(pip->ip_src), sizeof(pseudo_header.ip_src));
        memcpy(&(pseudo_header.ip_dst), &(pip->ip_dst), sizeof(pseudo_header.ip_dst));
        pseudo_header.zeros = 0;
        pseudo_header.protocol = TCP;
        pseudo_header.len = htons(IPLen - IPHeadLen); //TCP头部及后续数据部分总长度

        PTCP_HEADER ptcp = _tcpipdata(buff);

        PRINT_DBG_HEAD
        print_dbg("before repalace tcp_sum %x. pseudo_header.len %x", ptcp->th_sum, pseudo_header.len);

        ptcp->th_sum = 0;
        sum = checksum_pseudo((const uint8 *)&pseudo_header, sizeof(pseudo_header),
                              buff + IPHeadLen, IPLen - IPHeadLen);
        ptcp->th_sum = sum;

        PRINT_DBG_HEAD
        print_dbg("after repalace tcp_sum %x", ptcp->th_sum);

    } else if (IS_IPV4UDP(buff)) {
        PSEUDO_HEADER pseudo_header;
        memcpy(&(pseudo_header.ip_src), &(pip->ip_src), sizeof(pseudo_header.ip_src));
        memcpy(&(pseudo_header.ip_dst), &(pip->ip_dst), sizeof(pseudo_header.ip_dst));
        pseudo_header.zeros = 0;
        pseudo_header.protocol = UDP;
        pseudo_header.len = htons(IPLen - IPHeadLen); //UDP头部及后续数据部分总长度

        PUDP_HEADER pudp = _udpipdata(buff);
        pudp->uh_sum = 0;
        sum = checksum_pseudo((const uint8 *)&pseudo_header, sizeof(pseudo_header),
                              buff + IPHeadLen, IPLen - IPHeadLen);
        pudp->uh_sum = sum;

    } else if (IS_IPV4ICMP(buff)) {

        PICMP8 picmp8 = _icmp8ipdata(buff);
        picmp8->icmp_cksum = 0;
        sum = checksum((uint16 *)(buff + IPHeadLen), IPLen - IPHeadLen);
        picmp8->icmp_cksum = sum;
    }
    return true;
}

/**
 * [checksum 计算一块缓冲区的校验和]
 * @param  buffer [缓冲区]
 * @param  size   [缓冲区大小]
 * @return        [返回校验和]
 */
uint16 checksum(uint16 *buffer, int size)
{
    //uint16 cksum = 0;
    uint32 cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16);
    }
    if (size) {
        cksum += *(uint8 *)buffer;
    }
    while (cksum >> 16) {
        cksum = (cksum >> 16) + (cksum & 0xffff);
    }
    return (uint16)(~cksum);
}

/**
 * [rechecksum_ipv6 重新计算校验和]
 * @param  buff  [IP头部开始的数据包]
 * @param  offsetlen [传输层头部的偏移量]
 * @param  proto [协议]
 * @return       [成功返回true]
 */
bool rechecksum_ipv6(uint8 *buff, int offsetlen, uint8 proto)
{
    PSEUDO_HEADER_IPV6 pseudo_header;
    PIPV6_HEADER pipv6 = (PIPV6_HEADER)buff;
    int ipv6_len = _ipv6len(buff); //紧接在ipv6头部之后的所有数据的长度
    int ipv6hdrlen = _ipv6headlen(buff);
    uint16 sum = 0;

    switch (proto) {
    case TCP:
    case UDP:
        if (ipv6_len - offsetlen > 0) {
            //填充伪首部字段信息
            memcpy(&(pseudo_header.ip_src), &(pipv6->ip_src), sizeof(pseudo_header.ip_src));
            memcpy(&(pseudo_header.ip_dst), &(pipv6->ip_dst), sizeof(pseudo_header.ip_dst));
            pseudo_header.len = htons(ipv6_len);
            memset(&(pseudo_header.zeros), 0, sizeof(pseudo_header.zeros));
            pseudo_header.next_header = proto;

            //重新计算校验和
            if (proto == TCP) {
                PTCP_HEADER ptcp = (PTCP_HEADER)(buff + offsetlen);
                PRINT_DBG_HEAD
                print_dbg("ipv6_len[%d] offsetlen[%d] ipv6 tcp sum before[%d]", ipv6_len, offsetlen,
                          ptcp->th_sum);
                ptcp->th_sum = 0;
                sum = checksum_pseudo((const uint8 *)&pseudo_header, sizeof(pseudo_header),
                                      buff + offsetlen, ipv6_len + ipv6hdrlen - offsetlen);
                ptcp->th_sum = sum;
                PRINT_DBG_HEAD
                print_dbg("ipv6_len[%d] offsetlen[%d] ipv6 tcp sum after[%d]", ipv6_len, offsetlen,
                          ptcp->th_sum);
            } else {
                PUDP_HEADER pudp = (PUDP_HEADER)(buff + offsetlen);
                pudp->uh_sum = 0;
                sum = checksum_pseudo((const uint8 *)&pseudo_header, sizeof(pseudo_header),
                                      buff + offsetlen, ipv6_len + ipv6hdrlen - offsetlen);
                pudp->uh_sum = sum;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("rechecksum ipv6. ipv6len is %d, offsetlen is %d, proto is %d",
                      ipv6_len, offsetlen, proto);
        }
        break;
    case ICMPV6:
        PRINT_ERR_HEAD
        print_err("icmpv6 ignore[%d]", proto);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("proto error[%d]", proto);
        break;
    }
    return false;
}
