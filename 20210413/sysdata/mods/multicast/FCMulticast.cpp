/*******************************************************************************************
*文件:  FCMulticast.cpp
*描述:  组播处理 扩展文件
*作者:  王君雷
*日期:  2018-01-29
*
*修改:
*       支持ASM、SSM、SFM三种类型的组播                              ------> 2018-01-29
*       使用Multicast代替汉语拼音                                    ------> 2018-02-05
*       发送出去的组播报文设置TTL为64，设置禁止本地自环              ------> 2018-03-04
*       添加函数setBindToDevice，只接收指定网口的组播信息            ------> 2018-10-29
*       安全通道使用SEC_WAY类                                        ------> 2019-01-02
*       组播支持IPV6                                                 ------> 2019-06-24
*       组播每间隔30s记录一次访问日志                                ------> 2019-09-02
*       访问日志支持记录MAC字段,暂设置为空                           ------> 2020-01-16 wjl
*       支持分模块生效                                              ------> 2020-11-12
*******************************************************************************************/
#include <errno.h>
#include <net/if.h>
#include "FCMulticast.h"
#include "const.h"
#include "debugout.h"
#include "stringex.h"
#include "readcfg.h"
#include "fileoperator.h"
#include "FCLogContainer.h"
#include "card_mg.h"
#include "FCYWBS.h"
#include "FCLogManage.h"

extern sem_t *g_iptables_lock;
extern CardMG g_cardmg;
extern bool g_iflog;
extern bool g_syslog;
extern int g_linklan;

CMulticastTask::CMulticastTask(int taskid)
{
    BZERO(m_name);
    BZERO(m_srcmulticastip);
    BZERO(m_dstmulticastip);
    BZERO(m_srcport);
    BZERO(m_recvip);
    BZERO(m_dstport);
    BZERO(m_sendip);
    BZERO(m_tmpip);
    BZERO(m_srcip);
    m_type = MULTICAST_ASM;
    m_srcnum = 0;
    m_taskid = taskid;
    m_stop = false;
    m_packetcnt = 0;
    sprintf(m_tmpport, "%d", m_taskid + MULTICAST_NAT_START_PORT);

    if (sem_init(&m_packetsem, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("multicast init sem fail");
    }

    if (sem_init(&m_threadnum, 0, 0) == -1) {
        PRINT_ERR_HEAD
        print_err("multicast init threadnum fail");
    }
}

CMulticastTask::~CMulticastTask(void)
{
    PRINT_INFO_HEAD
    print_info("multicast task deconstruction begin");
    int value = 0;
    int ret = 0;
    sem_destroy(&m_packetsem);

    while (1) {
        ret = sem_getvalue(&m_threadnum, &value);
        if (ret == 0) {
            if (value > 0) {
                usleep(10000);
            } else {
                break;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("sem get value error.[%s]", strerror(errno));
            sleep(1);
        }
    }
    sem_destroy(&m_threadnum);
    PRINT_INFO_HEAD
    print_info("multicast task deconstruction over");
}

/**
 * [CMulticastTask::joinMembership 加入组播组]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::joinMembership(int fd)
{
    PRINT_DBG_HEAD
    print_dbg("multicast begin to join membership.type[%d]", m_type);

    bool bflag = false;
    if (m_type == MULTICAST_ASM) {
        bflag = joinMembershipASM(fd);
    } else if (m_type == MULTICAST_SSM) {
        bflag = joinMembershipSSM(fd);
    } else if (m_type == MULTICAST_SFM) {
        bflag = joinMembershipSFM(fd);
    } else {
        PRINT_ERR_HEAD
        print_err("type error[%d]", m_type);
    }
    PRINT_DBG_HEAD
    print_dbg("multicast join membership type[%d] %s. fd = %d", m_type, bflag ? "ok" : "fail", fd);
    return bflag;
}

/**
 * [CMulticastTask::joinMembershipASM 加入组播 ASM类型]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::joinMembershipASM(int fd)
{
    if (is_ip6addr(m_srcmulticastip)) {
        return joinMembershipASMIPV6(fd);
    }
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(m_srcmulticastip);
    mreq.imr_interface.s_addr = inet_addr(m_recvip);

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[%s:%s:%s]", strerror(errno), m_srcmulticastip, m_recvip);
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("multicast join membership asm ok.ipv4 fd = %d", fd);
    return true;
}

/**
 * [CMulticastTask::joinMembershipASMIPV6 加入组播 ASM类型]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::joinMembershipASMIPV6(int fd)
{
    struct ipv6_mreq mreq6;
    inet_pton(AF_INET6, m_srcmulticastip, &(mreq6.ipv6mr_multiaddr));
    mreq6.ipv6mr_interface = getSrcIfIndex();

    PRINT_DBG_HEAD
    print_dbg("multicast src if index is %u", mreq6.ipv6mr_interface);

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[%s:%s:%s]", strerror(errno), m_srcmulticastip, m_recvip);
        return false;
    }

    PRINT_DBG_HEAD
    print_dbg("multicast join membership asm ok.ipv6 fd = %d", fd);
    return true;
}

/**
 * [CMulticastTask::joinMembershipSSM 加入组播 SSM类型]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::joinMembershipSSM(int fd)
{
    struct ip_mreq_source mreqsource;

    if (m_srcnum <= 0) {
        PRINT_ERR_HEAD
        print_err("srcnum error[%d]", m_srcnum);
        return false;
    }

    if (is_ip6addr(m_srcmulticastip)) {
        return setSourceOpt6(fd);
    }
    for (int i = 0; i < m_srcnum; i++) {
        if (is_ip6addr(m_srcip[i])) {
            PRINT_INFO_HEAD
            print_info("ignore ipv6 src[%s]", m_srcip[i]);
            continue;
        }
        mreqsource.imr_multiaddr.s_addr = inet_addr(m_srcmulticastip);
        mreqsource.imr_sourceaddr.s_addr = inet_addr(m_srcip[i]);
        mreqsource.imr_interface.s_addr = inet_addr(m_recvip);
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreqsource, sizeof(mreqsource)) < 0) {
            PRINT_ERR_HEAD
            print_err("setsockopt error[%s:%s:%s]", strerror(errno), m_srcmulticastip, m_srcip[i]);
            return false;
        }

        PRINT_DBG_HEAD
        print_dbg("[IP_ADD_SOURCE_MEMBERSHIP] ---> %s", m_srcip[i]);
    }

    PRINT_DBG_HEAD
    print_dbg("multicast join membership ssm ok.ipv4 fd = %d", fd);
    return true;
}

/**
 * [CMulticastTask::setSourceOpt6 处理特定源\过滤源  信息]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::setSourceOpt6(int fd)
{
    struct group_source_req mreqsource;
    unsigned int ifindex = getSrcIfIndex();

    for (int i = 0; i < m_srcnum; i++) {
        if (!is_ip6addr(m_srcip[i])) {
            PRINT_INFO_HEAD
            print_info("ignore ipv4 src[%s]", m_srcip[i]);
            continue;
        }
        mreqsource.gsr_interface = ifindex;

        mreqsource.gsr_group.ss_family = AF_INET6;
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&mreqsource.gsr_group;
        addr_v6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, m_srcmulticastip, &(addr_v6->sin6_addr));

        mreqsource.gsr_source.ss_family = AF_INET6;
        struct sockaddr_in6 *addr_v6_source = (struct sockaddr_in6 *)&mreqsource.gsr_source;
        addr_v6_source->sin6_family = AF_INET6;
        inet_pton(AF_INET6, m_srcip[i], &(addr_v6_source->sin6_addr));

        if (setsockopt(fd, IPPROTO_IPV6, ((m_type == MULTICAST_SFM) ? MCAST_BLOCK_SOURCE : MCAST_JOIN_SOURCE_GROUP),
                       &mreqsource, sizeof(mreqsource)) < 0) {
            PRINT_ERR_HEAD;
            print_err("type(%d), srcip[%s], multicastip[%s], ifindex[%u],errinfo[%s]",
                      m_type, m_srcip[i], m_srcmulticastip, ifindex, strerror(errno));
            return false;
        }

        PRINT_DBG_HEAD
        print_dbg("[%s] ---> %s",
                  (m_type == MULTICAST_SFM) ? "MCAST_BLOCK_SOURCE" : "MCAST_JOIN_SOURCE_GROUP", m_srcip[i]);
    }
    return true;
}

/**
 * [CMulticastTask::joinMembershipSFM 加入组播 SFM类型]
 * @param  fd [socket描述符]
 * @return    [成功返回true]
 */
bool CMulticastTask::joinMembershipSFM(int fd)
{
    struct ip_mreq_source mreqsource;

    if (m_srcnum <= 0) {
        PRINT_ERR_HEAD
        print_err("srcnum error[%d]", m_srcnum);
        return false;
    }

    //先按ASM加入 再BLOCK阻塞黑名单中的IP
    if (!joinMembershipASM(fd)) {
        PRINT_ERR_HEAD
        print_err("join asm error[%d]", fd);
        return false;
    }

    if (is_ip6addr(m_srcmulticastip)) {
        return setSourceOpt6(fd);
    }

    for (int i = 0; i < m_srcnum; i++) {
        if (is_ip6addr(m_srcip[i])) {
            PRINT_INFO_HEAD
            print_info("ignore ipv6 src[%s]", m_srcip[i]);
            continue;
        }
        mreqsource.imr_multiaddr.s_addr = inet_addr(m_srcmulticastip);
        mreqsource.imr_sourceaddr.s_addr = inet_addr(m_srcip[i]);
        mreqsource.imr_interface.s_addr = inet_addr(m_recvip);
        if (setsockopt(fd, IPPROTO_IP, IP_BLOCK_SOURCE, &mreqsource, sizeof(mreqsource)) < 0) {
            PRINT_ERR_HEAD
            print_err("setsockopt error[%s:%s:%s]", strerror(errno), m_srcmulticastip, m_srcip[i]);
            return false;
        }
        PRINT_DBG_HEAD
        print_dbg("[IP_BLOCK_SOURCE] ---> %s", m_srcip[i]);
    }
    PRINT_DBG_HEAD
    print_dbg("multicast join membership sfm ok.ipv4 fd = %d", fd);
    return true;
}

/**
 * [CMulticastTask::stop 异步的停止运行任务]
 */
void CMulticastTask::stop(void)
{
    m_stop = true;
}

/**
 * [CMulticastTask::getStop 检查是否停止了]
 * @return  [需要停止返回true]
 */
bool CMulticastTask::getStop(void)
{
    return m_stop;
}

/**
 * [CMulticastTask::increaseThread 增加线程个数]
 */
void CMulticastTask::increaseThread(void)
{
    sem_post(&m_threadnum);
}

/**
 * [CMulticastTask::reduceThread 减少线程个数]
 */
void CMulticastTask::reduceThread(void)
{
    sem_wait(&m_threadnum);
}

/**
 * [CMulticastTask::setTmpIP 设置临时IP]
 * @param ip [临时IP]
 */
void CMulticastTask::setTmpIP(const char *ip)
{
    if (ip != NULL) {
        strcpy(m_tmpip, ip);
        PRINT_INFO_HEAD
        print_info("multicast taskid[%d] tmpip[%s] tmpport[%s]",
                   m_taskid, m_tmpip, m_tmpport);
    }
}

/**
 * [CMulticastTask::udpSocketBind 创建UDPsocket 绑定地址端口]
 * @param  ip   [IP]
 * @param  port [端口]
 * @return      [失败返回-1  成功返回描述符]
 */
int CMulticastTask::udpSocketBind(const char *ip, int port)
{
    int yes = 1;
    int fd = 0;
    int addrlen = 0;
    struct sockaddr_storage addr;
    BZERO(addr);

    if ((fd = socket(is_ip6addr(ip) ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]ip[%s]port[%d]", strerror(errno), ip, port);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[%s]ip[%s]port[%d]", strerror(errno), ip, port);
        close(fd);
        return -1;
    }

    struct timeval t1 = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t1, sizeof(struct timeval));

    if (!fillAddr(ip, port, addr, addrlen)) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error[%s] ip[%s] port[%d]", strerror(errno), ip, port);
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * [CMulticastTask::fillAddr 填充地址结构]
 * @param  ip   [IP]
 * @param  port [端口]
 * @param  addr [地址结构 出参]
 * @param  addrlen [地址结构长度 出参]
 * @return      [成功返回true]
 */
bool CMulticastTask::fillAddr(const char *ip, int port, struct sockaddr_storage &addr, int &addrlen)
{
    if (is_ip6addr(ip)) {
        addr.ss_family = AF_INET6;
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&addr;
        addr_v6->sin6_family = AF_INET6;
        addr_v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &(addr_v6->sin6_addr)) <= 0) {
            PRINT_ERR_HEAD
            print_err("inet_pton error[%s]ip[%s]port[%d]", strerror(errno), ip, port);
            return false;
        }
        addrlen = sizeof(struct sockaddr_in6);
    } else {
        addr.ss_family = AF_INET;
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&addr;
        addr_v4->sin_family = AF_INET;
        addr_v4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &(addr_v4->sin_addr)) <= 0) {
            PRINT_ERR_HEAD
            print_err("inet_pton error[%s]ip[%s]port[%d]", strerror(errno), ip, port);
            return false;
        }
        addrlen = sizeof(struct sockaddr_in);
    }
    return true;
}

/**
 * [CMulticastTask::setTTL 设置组播TTL]
 * @param  fd  [socket描述符]
 * @param  val [ttl值]
 * @return     [成功返回true]
 */
bool CMulticastTask::setTTL(int fd, unsigned char ttlval)
{
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttlval, sizeof(ttlval)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[%s,fd %d, ttlval:%d]", strerror(errno), fd, ttlval);
        return false;
    }
    return true;
}

/**
 * [CMulticastTask::setHops 设置数据包跳限]
 * @param  fd   [socket描述符]
 * @param  hops [跳限值]
 * @return      [成功返回true]
 */
bool CMulticastTask::setHops(int fd, int hops)
{
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt error[%s,fd %d, hops:%d]", strerror(errno), fd, hops);
        return false;
    }
    return true;
}

/**
 * [CMulticastTask::setLoop 设置组播数据报本地自环]
 * @param  fd     [socket描述符]
 * @param  ifloop [是否本地自环]
 * @param  ipv6   [是否为IPV6]
 * @return        [成功返回true]
 */
bool CMulticastTask::setLoop(int fd, bool ifloop, bool ipv6)
{
    if (ipv6) {
        unsigned int loop = ifloop ? 1 : 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            PRINT_ERR_HEAD
            print_err("setsockopt error[%s:%d]", strerror(errno), fd);
            return false;
        }
    } else {
        unsigned char loop = ifloop ? 1 : 0;
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
            PRINT_ERR_HEAD
            print_err("setsockopt error[%s:%d]", strerror(errno), fd);
            return false;
        }
    }
    return true;
}

/**
 * [CMulticastTask::setBindToDevice 设置接收组播信息时从哪个接口进入]
 * @param  fd     [socket描述符]
 * @param  device [设备名称，如eth0、bond0等]
 * @return        [成功返回true]
 */
bool CMulticastTask::setBindToDevice(int fd, const char *device)
{
    if (device != NULL) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)) != 0) {
            PRINT_ERR_HEAD
            print_err("setsockopt error[%s:%d:%s]", strerror(errno), fd, device);
        } else {
            return true;
        }
    }
    return false;
}

/**
 * [CMulticastTask::mcRecv 网闸接收组播程序]
 * @param  arg [组播任务指针]
 * @return     [无特殊含义]
 */
void *CMulticastTask::mcRecv(void *arg)
{
    pthread_setself("mcrecv");

    CMulticastTask *ptask = (CMulticastTask *)arg;
    int ret = 0;
    int fd_recv = 0;
    int fd_send = 0;
    struct sockaddr_storage addrsend;
    char recvbuf[MULTICAST_MAX_LEN] = {0};
    BZERO(addrsend);
    int addrlen = 0;

    ptask->increaseThread();
    ptask->setInputCard();
    for (int i = 0; i < 5; ++i) {
        if ((fd_recv = udpSocketBind(ptask->m_srcmulticastip, atoi(ptask->m_srcport))) < 0) {
            PRINT_ERR_HEAD
            print_err("bind ip port fail[%s %s],retry", ptask->m_srcmulticastip, ptask->m_srcport);
            sleep(2);
        } else {
            break;
        }
    }
    if (fd_recv < 0) {
        PRINT_ERR_HEAD
        print_err("recv thread return");
        ptask->reduceThread();
        return NULL;
    }

    char cardname[32] = {0};
    int srcdev = ptask->getSrcDev();
    INT_TO_CARDNAME(srcdev, cardname);
    setBindToDevice(fd_recv, cardname);
    if (!(ptask->joinMembership(fd_recv))) {
        close(fd_recv);
        ptask->reduceThread();
        return NULL;
    }
    //------------------------------------以上为接收相关 以下为发送相关---------------
    if ((fd_send = socket(is_ip6addr(ptask->m_tmpip) ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        close(fd_recv);
        ptask->reduceThread();
        return NULL;
    }

    if (!fillAddr(ptask->m_tmpip, atoi(ptask->m_tmpport), addrsend, addrlen)) {
        PRINT_ERR_HEAD
        print_err("fill addr error[%s][%s]", ptask->m_tmpip, ptask->m_srcport);
        close(fd_recv);
        close(fd_send);
        ptask->reduceThread();
        return NULL;
    }

    PRINT_INFO_HEAD
    print_info("recvip[%s] srcmulticastip[%s][%s] tmpip[%s]",
               ptask->m_recvip, ptask->m_srcmulticastip, ptask->m_srcport, ptask->m_tmpip);

    //循环接收转发
    while (1) {
        ret = recvfrom(fd_recv, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        if (ret <= 0) {
            if ((EAGAIN == errno) || (EWOULDBLOCK == errno)) {
                if (ptask->getStop()) {
                    PRINT_INFO_HEAD
                    print_info("thread stop now");
                    goto _out;
                }
            } else {
                PRINT_ERR_HEAD
                print_err("recvfrom error[%s:%d]", strerror(errno), ret);
                sleep(1);
            }
            continue;
        }

        if (sendto(fd_send, recvbuf, ret, 0, (struct sockaddr *)&addrsend, addrlen) < 0) {
            PRINT_ERR_HEAD
            print_err("sendto error[%s]", strerror(errno));
            sleep(1);
            continue;
        }

        sem_wait(&(ptask->m_packetsem));
        ptask->m_packetcnt++;
        sem_post(&(ptask->m_packetsem));

        PRINT_DBG_HEAD
        print_dbg("recv from multicast, and send one packet len[%d]", ret);
    }

_out:
    close(fd_recv);
    close(fd_send);
    ptask->reduceThread();
    return NULL;
}

/**
 * [CMulticastTask::mcSend 网闸向外转发组播程序]
 * @param  arg [组播任务指针]
 * @return     [无特殊含义]
 */
void *CMulticastTask::mcSend(void *arg)
{
    pthread_setself("mcsend");

    CMulticastTask *ptask = (CMulticastTask *)arg;
    int ret = 0;
    int fd_recv = 0;
    int fd_send = 0;
    int addrlen = 0;
    struct sockaddr_storage addrsend;
    BZERO(addrsend);
    char recvbuf[MULTICAST_MAX_LEN] = {0};

    ptask->increaseThread();
    ptask->setOutputCard();
    for (int i = 0; i < 5; ++i) {
        if ((fd_recv = udpSocketBind(ptask->m_tmpip, atoi(ptask->m_tmpport))) < 0) {
            PRINT_ERR_HEAD
            print_err("multicast udp bind fail,retry.[%s][%s]", ptask->m_tmpip, ptask->m_tmpport);
            sleep(2);
        } else {
            break;
        }
    }
    if (fd_recv < 0) {
        PRINT_ERR_HEAD
        print_err("send thread return");
        ptask->reduceThread();
        return NULL;
    }

    for (int i = 0; i < 5; ++i) {
        if ((fd_send = udpSocketBind(ptask->m_sendip, 0)) < 0) {
            PRINT_ERR_HEAD
            print_err("multicast udp bind fail,retry.[%s][0]", ptask->m_sendip);
            sleep(2);
        } else {
            break;
        }
    }
    if (fd_send < 0) {
        close(fd_recv);
        PRINT_ERR_HEAD
        print_err("send2 thread return");
        ptask->reduceThread();
        return NULL;
    }

    if (is_ip6addr(ptask->m_dstmulticastip)) {
        setHops(fd_send, MULTICAST_HOPS_VAL);
        setLoop(fd_send, false, true);
    } else {
        setTTL(fd_send, MULTICAST_TTL_VAL);
        setLoop(fd_send, false, false);
    }

    if (!fillAddr(ptask->m_dstmulticastip, atoi(ptask->m_dstport), addrsend, addrlen)) {
        close(fd_recv);
        close(fd_send);
        ptask->reduceThread();
        return NULL;
    }

    PRINT_INFO_HEAD
    print_info("recv tmpip[%s][%s] sendip[%s] dstmulticast[%s][%s]",
               ptask->m_tmpip, ptask->m_tmpport, ptask->m_sendip, ptask->m_dstmulticastip, ptask->m_dstport);

    //循环接收转发
    while (1) {
        ret = recvfrom(fd_recv, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        if (ret <= 0) {
            if ((EAGAIN == errno) || (EWOULDBLOCK == errno)) {
                if (ptask->getStop()) {
                    PRINT_INFO_HEAD
                    print_info("thread stop now");
                    goto _out;
                }
            } else {
                PRINT_ERR_HEAD
                print_err("recvfrom error[%s:%d]", strerror(errno), ret);
                sleep(1);
            }
            continue;
        }

        if (sendto(fd_send, recvbuf, ret, 0, (struct sockaddr *)&addrsend, addrlen) < 0) {
            PRINT_ERR_HEAD
            print_err("sendto error.len %d,errinfo[%s]", ret, strerror(errno));
            sleep(1);
            continue;
        }
        PRINT_DBG_HEAD
        print_dbg("recv one packet and send to multicast.len[%d]", ret);
    }

_out:
    close(fd_recv);
    close(fd_send);
    ptask->reduceThread();
    return NULL;
}

/**
 * [CMulticastTask::startMulticastTask 启动组播任务]
 * @param  issrc [是否为源端]
 * @return       [成功返回true]
 */
bool CMulticastTask::startMulticastTask(bool issrc)
{
    pthread_t tid;
    int ret = pthread_create(&tid, NULL, issrc ? mcRecv : mcSend, this);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create fail[%d]", ret);
        return false;
    }

    if (issrc && (g_iflog || g_syslog)) {
        pthread_t tid2;
        ret = pthread_create(&tid2, NULL, mcStatistics, this);
        if (ret != 0) {
            PRINT_ERR_HEAD
            print_err("pthread create statistics fail[%d]", ret);
            return false;
        }
    }
    return true;
}

/**
 * [CMulticastTask::configCheck 配置检查]
 * @return [检查无误返回true]
 */
#define IP_TYPE_SAME(ip1,ip2) ((is_ip6addr(ip1) && is_ip6addr(ip2)) || ((!is_ip6addr(ip1)) && (!is_ip6addr(ip2))))
bool CMulticastTask::configCheck(void)
{
    return IfMulticastIP(m_srcmulticastip)
           && IfMulticastIP(m_dstmulticastip)
           && (!ALL_OBJ(m_sendip))
           && (!IPV6_ALL_OBJ(m_sendip))
           && (strcmp(m_sendip, "") != 0)
           && (strcmp(m_recvip, "") != 0)
           && IP_TYPE_SAME(m_srcmulticastip, m_recvip)
           && IP_TYPE_SAME(m_dstmulticastip, m_sendip);
}

/**
 * [CMulticastTask::getSrcDev 获取进入口号]
 * @return  [进入的网口号]
 */
int CMulticastTask::getSrcDev(void)
{
    return (m_secway.getarea() == 0) ? m_secway.getindev() : m_secway.getoutdev();
}

/**
 * [CMulticastTask::getDstDev 获取出网口号]
 * @return  [出的网口号]
 */
int CMulticastTask::getDstDev(void)
{
    return (m_secway.getarea() == 0) ? m_secway.getoutdev() : m_secway.getindev();
}

/**
 * [CMulticastTask::getArea 获取安全通道方向]
 * @return  [安全通道方向]
 */
int CMulticastTask::getArea(void)
{
    return m_secway.getarea();
}

/**
 * [CMulticastTask::getSrcIfIndex 获取进入的网卡索引号]
 * @return  [索引号]
 */
unsigned int CMulticastTask::getSrcIfIndex(void)
{
    char dev[32] = {0};
    int srcdev = getSrcDev();
    INT_TO_CARDNAME(srcdev, dev);
    return if_nametoindex(dev);
}

/**
 * [CMulticastTask::getDstIfIndex 获取出的网卡索引号]
 * @return  [索引号]
 */
unsigned int CMulticastTask::getDstIfIndex(void)
{
    char dev[32] = {0};
    int dstdev = getDstDev();
    INT_TO_CARDNAME(dstdev, dev);
    return if_nametoindex(dev);
}

/**
 * [CMulticastTask::setOutputCard 设置出接口]
 */
void CMulticastTask::setOutputCard(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char cardname[32] = {0};
    INT_TO_CARDNAME(getDstDev(), cardname);
    sprintf(chcmd, "route %s add '%s' %s", is_ip6addr(m_dstmulticastip) ? "-A inet6" : "" ,
            m_dstmulticastip, cardname);
    system_safe(chcmd);
    PRINT_DBG_HEAD
    print_dbg("muticast set output card[%s]", chcmd);
}

/**
 * [CMulticastTask::setInputCard 设置进接口]
 */
void CMulticastTask::setInputCard(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char cardname[32] = {0};

    INT_TO_CARDNAME(getSrcDev(), cardname);
    sprintf(chcmd, "route %s add '%s' %s", is_ip6addr(m_srcmulticastip) ? "-A inet6" : "" ,
            m_srcmulticastip, cardname);
    system(chcmd);
    PRINT_DBG_HEAD
    print_dbg("muticast set input card[%s]", chcmd);
}

/**
 * [CMulticastTask::mcStatistics 转发包数统计]
 * @param  arg   [description]
 * @return       [description]
 */
void *CMulticastTask::mcStatistics(void *arg)
{
    pthread_setself("mcstatistics");

    CMulticastTask *ptask = (CMulticastTask *)arg;
    char chcmd[CMD_BUF_LEN] = {0};
    uint32 cnt = 0;
    int sec_cnt = 0;
    ptask->increaseThread();

    while (1) {
        sleep(1);
        sec_cnt++;
        if (ptask->getStop()) {
            goto _out;
        }
        if (sec_cnt < MULTICAST_LOG_CYCLE) {
            continue;
        }

        sec_cnt = 0;
        if (ptask->m_packetcnt > 0) {
            sem_wait(&(ptask->m_packetsem));
            cnt = ptask->m_packetcnt;
            ptask->m_packetcnt -= cnt;
            sem_post(&(ptask->m_packetsem));

            sprintf(chcmd, "%s[%d]", LOG_CONTENT_MULTICAST_TRANSFER, cnt);
            CallLogPara *p = new CallLogPara;
            if (p != NULL) {
                if (p->SetValues("", ptask->m_srcmulticastip, ptask->m_dstmulticastip, ptask->m_srcport,
                                 ptask->m_dstport, "", "", LOG_TYPE_MULTICAST, "", "",  D_SUCCESS, chcmd)) {
                    LogContainer &s1 = LogContainer::GetInstance();
                    s1.PutPara(p);
                } else {
                    PRINT_ERR_HEAD
                    print_err("set values fail[sip %s, dip %s, sport %s, dport %s]",
                              ptask->m_srcmulticastip, ptask->m_dstmulticastip, ptask->m_srcport, ptask->m_dstport);
                    delete p;
                }
            }
        }
    }
_out:
    ptask->reduceThread();
    return NULL;
}

MulticastMG::MulticastMG(void)
{
    m_task_num = 0;
    BZERO(m_task);
}

MulticastMG::~MulticastMG(void)
{
    clear();
}

/**
 * [MulticastMG::clear 清空]
 */
void MulticastMG::clear(void)
{
    PRINT_INFO_HEAD
    print_info("multicast mg clear begin");

    for (int i = 0; i < m_task_num; ++i) {
        m_task[i]->stop();
    }
    DELETE_N(m_task, m_task_num);
    m_task_num = 0;
    g_cardmg.clear(MULTICAST_MOD);
    PRINT_INFO_HEAD
    print_info("multicast mg clear over");
}

/**
 * [MulticastMG::addTask 新加一个任务]
 * @return  [任务指针]
 */
CMulticastTask *MulticastMG::addTask(void)
{
    if (m_task_num == ARRAY_SIZE(m_task)) {
        PRINT_ERR_HEAD
        print_err("reach max support muticastnum[%d]", ARRAY_SIZE(m_task));
        return NULL;
    }
    m_task[m_task_num] = new CMulticastTask(m_task_num);
    if (m_task[m_task_num] == NULL) {
        PRINT_ERR_HEAD
        print_err("new MulticastTask fail. current tasknum[%d]", m_task_num);
        return NULL;
    }
    m_task_num++;
    return m_task[m_task_num - 1];
}

/**
 * [MulticastMG::loadConf 导入组播策略]
 * @return            [成功返回E_OK]
 */
int MulticastMG::loadConf(void)
{
    char taskno[16] = {0};
    char subitem[32] = {0};
    int tasknum = 0;
    int indev = -1;
    int outdev = -1;
    int area = 0;
    CMulticastTask *mc = NULL;
    CFILEOP fileop;

    if (fileop.OpenFile(MULTICAST_CONF, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", MULTICAST_CONF);
        return E_OPENFILE_ERROR;
    }

    READ_INT(fileop, "MULTICAST", "TaskNum", tasknum, true, _out);

    PRINT_DBG_HEAD
    print_dbg("multicast tasknum[%d]", tasknum);

    for (int i = 0; i < tasknum ; i++) {
        mc = addTask();
        if (mc == NULL) {
            break;
        }

        sprintf(taskno, "Task%d", i);
        READ_STRING(fileop, taskno, "Name", mc->m_name, true, _out);
        READ_INT(fileop, taskno, "Area", area, true, _out);
        READ_INT(fileop, taskno, "InDev", indev, true, _out);
        READ_INT(fileop, taskno, "OutDev", outdev, true, _out);
        mc->m_secway.setway("", area, indev, outdev);
        READ_STRING(fileop, taskno, "SrcZuBoIp", mc->m_srcmulticastip, true, _out);
        READ_STRING(fileop, taskno, "SrcPort", mc->m_srcport, true, _out);
        READ_STRING(fileop, taskno, "RecvIp", mc->m_recvip, true, _out);
        READ_STRING(fileop, taskno, "DstZuBoIp", mc->m_dstmulticastip, true, _out);
        READ_STRING(fileop, taskno, "DstPort", mc->m_dstport, true, _out);
        READ_STRING(fileop, taskno, "SendIp", mc->m_sendip, true, _out);
        READ_INT(fileop, taskno, "Type", mc->m_type, false, _out);
        if ((mc->m_type != MULTICAST_SSM) && (mc->m_type != MULTICAST_SFM)) {
            mc->m_type = MULTICAST_ASM;
        }

        if (mc->m_type != MULTICAST_ASM) {
            READ_INT(fileop, taskno, "SrcIPNum", mc->m_srcnum, true, _out);
            if (mc->m_srcnum > MULTICAST_MAX_SRC_NUM) {
                PRINT_ERR_HEAD
                print_err("too many ip[%d],set to max support[%d]", mc->m_srcnum,
                          MULTICAST_MAX_SRC_NUM);
                mc->m_srcnum = MULTICAST_MAX_SRC_NUM;
            }

            for (int j = 0; j < mc->m_srcnum; j++) {
                sprintf(subitem, "SrcIP%d", j);
                READ_STRING(fileop, taskno, subitem, mc->m_srcip[j], true, _out);
            }
        }
        g_cardmg.add(MULTICAST_MOD, mc->m_secway.getindev(), mc->m_secway.getoutdev());
    }

    fileop.CloseFile();
    return E_OK;

_out:
    fileop.CloseFile();
    return E_FALSE;
}

/**
 * [MulticastMG::taskNum 任务数]
 * @return  [任务数]
 */
int MulticastMG::taskNum(void)
{
    return m_task_num;
}

/**
 * [MulticastMG::setTransparentIptables 设置透明模式下的iptables]
 */
void MulticastMG::setTransparentIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (m_task_num > 0) {
        MAKE_TABLESTRING(chcmd, "-A FILTER_MULTICAST -d 224.0.0.22 -j ACCEPT", false);
        sem_wait(g_iptables_lock);
        system(chcmd);
        sem_post(g_iptables_lock);

        for (int i = 0; i < m_task_num; ++i) {
            if (IfMulticastIP(m_task[i]->m_srcmulticastip)) {
                MAKE_TABLESTRING(chcmd, "-A FILTER_MULTICAST -d %s -p udp --dport %s %s -j ACCEPT",
                                 is_ip6addr(m_task[i]->m_srcmulticastip),
                                 m_task[i]->m_srcmulticastip, m_task[i]->m_srcport,
                                 m_task[i]->m_secway.iptables_bridge((DEVFLAG[0] == 'I'), g_linklan));
                sem_wait(g_iptables_lock);
                system(chcmd);
                sem_post(g_iptables_lock);
            } else {
                PRINT_ERR_HEAD
                print_err("not multicast ip[%s]", m_task[i]->m_srcmulticastip);
            }
        }
    }
    PRINT_INFO_HEAD
    print_info("multicast set transparent iptables over tasknum[%d]", m_task_num);
}

/**
 * [MulticastMG::clearTransparentIptables 清理透明模式下的iptables]
 */
void MulticastMG::clearTransparentIptables(void)
{
    sem_wait(g_iptables_lock);
    system("iptables -F FILTER_MULTICAST");
    system("ip6tables -F FILTER_MULTICAST");
    sem_post(g_iptables_lock);
    PRINT_INFO_HEAD
    print_info("multicast clear transparent iptables");
}

/**
 * [MulticastMG::setTmpIP 设置内部跳转使用的IP]
 * @param innum  [内网业务IP个数]
 * @param outnum [外网业务IP个数]
 * @return        [成功返回true]
 */
bool MulticastMG::setTmpIP(int innum, int outnum)
{
    if ((innum <= 0) || (outnum <= 0)) {
        PRINT_ERR_HEAD
        print_err("inipnum[%d] outipnum[%d]", innum, outnum);
        return false;
    }
    MakeV4NatIP(false, g_linklanipseg, innum + 1, m_out_tmpip, sizeof(m_out_tmpip));
    MakeV4NatIP(true, g_linklanipseg, outnum + 1, m_in_tmpip, sizeof(m_in_tmpip));
    PRINT_INFO_HEAD
    print_info("innum[%d] outnum[%d] m_in_tmpip[%s] m_out_tmpip[%s]", innum, outnum, m_in_tmpip, m_out_tmpip);
    return true;
}

/**
 * [MulticastMG::setTmpIP 为各个任务设置临时IP]
 * @return  [成功返回true]
 */
bool MulticastMG::setTmpIP(void)
{
    for (int i = 0; i < m_task_num; ++i) {
        m_task[i]->setTmpIP((m_task[i]->getArea() == 0) ? m_out_tmpip : m_in_tmpip);
    }
    return true;
}

/**
 * [MulticastMG::run 运行任务]
 */
void MulticastMG::run(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    bool ckflag = true;
    CLOGMANAGE logmg;
    logmg.Init();

    sem_wait(g_iptables_lock);
    system("iptables -t nat -F NAT_MULTICAST");
    system("ip6tables -t nat -F NAT_MULTICAST");
    sem_post(g_iptables_lock);
    setTmpIP();

    for (int i = 0; i < m_task_num; ++i) {
        ckflag = m_task[i]->configCheck();
        sprintf(chcmd, "%s[%s]:%s [%s]:%s",
                ckflag ? LOG_CONTENT_MULTICAST_CONF_CK_OK : LOG_CONTENT_MULTICAST_CONF_CK_ERR,
                m_task[i]->m_srcmulticastip, m_task[i]->m_srcport, m_task[i]->m_dstmulticastip, m_task[i]->m_dstport);
        logmg.WriteSysLog(LOG_TYPE_MULTICAST, ckflag ? D_SUCCESS : D_FAIL, chcmd);

        if (!ckflag) {
            PRINT_ERR_HEAD
            print_err("multicast config check fail");
            continue;
        }

        if (IsCloseToSRCObj(m_task[i]->getArea())) {
            m_task[i]->startMulticastTask(true);
        } else {
            m_task[i]->startMulticastTask(false);
            MAKE_TABLESTRING(chcmd, "-t nat -A NAT_MULTICAST -s %s -d %s -p udp --dport %s -j ACCEPT",
                             is_ip6addr(m_task[i]->m_sendip), m_task[i]->m_sendip,
                             m_task[i]->m_dstmulticastip, m_task[i]->m_dstport);
            sem_wait(g_iptables_lock);
            system(chcmd);
            sem_post(g_iptables_lock);
        }
    }
    logmg.DisConnect();
    PRINT_INFO_HEAD
    print_info("multicast run over");
}

/**
 * [IfMulticastIP 判断一个IP是不是组播IP]
 * @param  ip [输入IP]
 * @return    [是则返回true]
 */
bool IfMulticastIP(const char *ip)
{
    return (IfMulticastIPV4(ip) || IfMulticastIPV6(ip));
}

/**
 * [IfMulticastIPV4 判断一个IP是不是组播IP]
 * 合法组播地址范围[224.0.0.0—239.255.255.255]
 * @param  ip [输入IP]
 * @return    [是则返回true]
 */
bool IfMulticastIPV4(const char *ip)
{
    char ch[32] = {0};

    const char *p = strchr(ip, '.');
    if ((p != NULL) && ((p - ip) <= 3)) {
        memcpy(ch, ip, p - ip);
        if ((atoi(ch) >= 224) && (atoi(ch) <= 239)) {
            //第一个点号之后的部分暂不判断
            PRINT_DBG_HEAD
            print_dbg("multicast ipv4 range check ok[%s]", ip);
            return true;
        }
    }

    PRINT_INFO_HEAD
    print_info("not ipv4 multicast ip[%s]", ip);
    return false;
}

/**
 * [IfMulticastIPV6 判断一个IP是不是组播IP]
 * 合法组播地址范围[ff00::/8]
 * @param  ip [输入IP]
 * @return    [是则返回true]
 */
#define ishex(c) (isdigit(c) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')))
bool IfMulticastIPV6(const char *ip)
{
    if ((ip != NULL) && (strlen(ip) > 6)) {
        if (((ip[0] == 'f') || (ip[0] == 'F')) && ((ip[1] == 'f') || (ip[1] == 'F'))) {
            if (ishex(ip[2]) && ishex(ip[3]) && (ip[4] == ':')) {
                PRINT_DBG_HEAD
                print_dbg("multicast ipv6 range check ok[%s]", ip);
                return true;
            }
        }
    }

    PRINT_INFO_HEAD
    print_info("multicast ipv6 range check fail[%s]", ip);
    return false;
}
