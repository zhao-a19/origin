/******************************************************************
** 文件名: fcpacket.cpp
** Copyright (c) 2005
** 创建人:黄勇
** 日  期:2005-2-20
** 修改人:
** 日  期:
** 描  述:B/S通讯类
**
** 版  本:V1.1
**
*     修改函数WritePacket的返回值错误                ------> 2018-12-07 wjl
*     添加通过HA工具恢复用户配置功能                  ------> 2020-09-28
*     通过构造函数可以设置是否接收全部协议包,临时解决透明模式
*     双机热备不能使用的问题                          ------> 2021-04-07 wjl
*******************************************************************/
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "fcpacket.h"
#include "hardinfo.h"
#include "debugout.h"

CPACKET::CPACKET(int index, bool recvall, bool UseR, bool UseS)
{
    if (index < 0) {
        PRINT_ERR_HEAD
        print_err("index error[%d]", index);
        return;
    }

    SetRecvAll(recvall);
    m_sock = -1;
    memset(m_peerMac, 0xFF, sizeof(m_peerMac));
    memset(m_masterMac, 0xFF, sizeof(m_masterMac));
    memset(m_slaveMac, 0xFF, sizeof(m_slaveMac));
    memset(m_localMac, 0, sizeof(m_localMac));

    char ethname[10] = {0};
    sprintf(ethname, "eth%d", index);

    if (Open(ethname) < 0) {
        PRINT_ERR_HEAD
        print_err("open error[%s]", ethname);
    }

    if (!get_mac(index, NULL, m_localMac)) {
        PRINT_ERR_HEAD
        print_err("getmac error[%d]", index);
    }
}

CPACKET::~CPACKET()
{
    Close();
}

/**
 * [CPACKET::Open 创建原始套接字 ]
 * @param  eth [eth名]
 * @return     [成功返回0 失败返回负值]
 */
int CPACKET::Open(const char *eth)
{
    if (eth == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    Close();

    /* 这里只处理热备协议 */
    if ((m_sock = socket(PF_PACKET, SOCK_RAW, htons(m_recv_all ? ETH_P_ALL : ETH_P_HOTBAK))) == -1) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

#if 0
    //不需要混杂模式
    char chcmd[100] = {0};
    sprintf(chcmd, "ifconfig %s promisc up", eth);
    system(chcmd);
#endif

    bzero(&m_sa, sizeof(struct sockaddr_ll));
    m_sa.sll_family = PF_PACKET;
    m_sa.sll_protocol = htons(m_recv_all ? ETH_P_ALL : ETH_P_HOTBAK);
    m_sa.sll_halen = 8;             //length of hardware address
    //bcopy(source->ether_addr_octet, m_sa.sll_addr,8);
    m_sa.sll_ifindex = if_nametoindex(eth);
    m_sa.sll_pkttype = PACKET_OUTGOING;

#if 0
    //不需要混杂模式
    struct ifreq ifr;
    strcpy(ifr.ifr_name, eth);
    int res = ioctl(m_sock, SIOCGIFFLAGS, &ifr);
    if (res == -1) {
        PRINT_ERR_HEAD
        print_err("ioctl error[%s]", strerror(errno));
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    res = ioctl(m_sock, SIOCGIFFLAGS, &ifr);
    if (res == -1) {
        PRINT_ERR_HEAD
        print_err("ioctl error[%s]", strerror(errno));
        return -1;
    }
#endif

    if (bind(m_sock, (struct sockaddr *) &m_sa, sizeof(m_sa)) == -1) {
        PRINT_ERR_HEAD
        print_err("bind error[%s]", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * [CPACKET::Close 关闭socket]
 * @return [description]
 */
int CPACKET::Close()
{
    if (m_sock > 0) {
        close(m_sock);
    }
    m_sock = -1;
    return 0;
}

/**
 * [CPACKET::ReadPacket 读取数据]
 * @param  p_uchBuff [接收数据的缓冲区]
 * @param  iBuffLen  [缓冲区长度]
 * @param  kind      [数据所属类别]
 * @return           [成功返回>=0  -1：出错  -2：超时]
 */
int CPACKET::ReadPacket(unsigned char *p_uchBuff, int *iBuffLen, unsigned char &kind)
{
    if ((p_uchBuff == NULL) || (iBuffLen == NULL) || (*iBuffLen <= 0)) {
        *iBuffLen = -1;
        PRINT_ERR_HEAD
        print_err("para error[%d]", *iBuffLen);
        return -1;
    }

    int iRecvLen = 0;
    POPACKET ptr;

AGAIN:
    //接收
    iRecvLen = recvfrom(m_sock, p_uchBuff, *iBuffLen, 0, NULL, NULL);
    if ((iRecvLen == -1) && (errno == EAGAIN)) {
        *iBuffLen = -2;
        return -2;
    } else if (iRecvLen < (int)sizeof(OPACKET)) {
        *iBuffLen = -1;
        PRINT_ERR_HEAD
        print_err("recvfrom error[%d:%s]", iRecvLen, strerror(errno));
        return -1;
    }

    ptr = (POPACKET)p_uchBuff;
    //判断0801
    if (ptr->BZType[0] != 0x08 || ptr->BZType[1] != 0x01) {
        goto AGAIN;
    }

    //解出OPACKET结构
    OPACKET pkt;
    memcpy(&pkt, p_uchBuff, sizeof(pkt));

    int csize = 0;
    memcpy(&csize, pkt.CSize, 4);

    if ((csize < 0) || (csize > iRecvLen - (int)sizeof(OPACKET))) {
        *iBuffLen = -1;
        PRINT_ERR_HEAD
        print_err("csize err[%d]", csize);
        return -1;
    }

    switch (pkt.CKind) {
    case C_SERCHDEV:
    case C_INITDEV:
    case C_GETCTRL:
    case C_GETINFO:
    case C_INIT_USERCONF:
        //是管理PC发来的请求 把PC的MAC保存起来
        memcpy(m_peerMac, pkt.SMac, sizeof(m_peerMac));
        break;
    case C_HEARTBEAT:
    case C_GET_RULES:
        //是从设备向本机发来的请求 把从设备的MAC保存起来
        memcpy(m_slaveMac, pkt.SMac, sizeof(m_slaveMac));
        break;
    case C_HEARTBEAT_RES:
    case C_RULES_FILE:
        //是主设备发来的响应信息 把主设备的MAC保存起来
        memcpy(m_masterMac, pkt.SMac, sizeof(m_masterMac));
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown kind[%d]", pkt.CKind);
        break;
    }
    //指令类型通过参数传回
    kind = pkt.CKind;
    memmove(p_uchBuff, p_uchBuff + sizeof(OPACKET), csize);
    *iBuffLen = csize;
    return *iBuffLen;
}

/**
 * [CPACKET::WritePacket 发送数据]
 * @param  p_uchBuff [待发送的数据]
 * @param  iBuffLen  [数据长度]
 * @param  kind      [类型]
 * @return           [成功返回发送的长度(不包括OPACKET的长度)，失败返回负值]
 */
int CPACKET::WritePacket(const unsigned char *p_uchBuff, int iBuffLen, unsigned char kind)
{
    if ((m_sock < 0)
        || (p_uchBuff == NULL)
        || (iBuffLen < 0)
        || (iBuffLen > (MAX_PKTSIZE - (int)sizeof(OPACKET)))) {
        PRINT_ERR_HEAD
        print_err("para err[sock %d, len %d, kind %d]", m_sock, iBuffLen, kind);
        return -1;
    }

    //填充OPACKET
    OPACKET pack;
    memset(&pack, 0, sizeof(pack));
    memcpy(pack.SMac, m_localMac, sizeof(m_localMac));
    pack.BZType[0] = 0x08;
    pack.BZType[1] = 0x01;
    pack.CKind = kind;
    memcpy(pack.CSize, &iBuffLen, sizeof(pack.CSize));

    switch (kind) {
    case C_DEVID:
    case C_CTRL_INFO:
    case C_INFO:
    case C_INIT_USERCONF_RES:
        //是发送给管理PC的
        memcpy(pack.DMac, m_peerMac, sizeof(m_peerMac));
        break;
    case C_HEARTBEAT:
    case C_GET_RULES:
        //是发送给上级主机的
        memcpy(pack.DMac, m_masterMac, sizeof(m_masterMac));
        break;
    case C_HEARTBEAT_RES:
    case C_RULES_FILE:
        //是发送给下级备机的
        memcpy(pack.DMac, m_slaveMac, sizeof(m_slaveMac));
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown kind[%d]", kind);
        return -1;
        break;
    }

    //重组发送的内容
    unsigned char tmpbuf[MAX_PKTSIZE] = {0};
    memcpy(tmpbuf, &pack, sizeof(pack));
    memcpy(tmpbuf + sizeof(pack), p_uchBuff, iBuffLen);

    int iSendLen = sendto(m_sock, tmpbuf, iBuffLen + sizeof(pack), 0, (struct sockaddr *) &m_sa,
                          sizeof(m_sa));
    if (iSendLen != iBuffLen + (int)sizeof(pack)) {
        PRINT_ERR_HEAD
        print_err("sendto ret err[%d], expect [%d], %s", iSendLen, iBuffLen + (int)sizeof(pack),
                  strerror(errno));
        return -1;
    }
    return iBuffLen;
}

/**
 * [CPACKET::SetRecvTimeOut 设置接收超时]
 * @param  sec [秒]
 * @return     [成功返回0]
 */
int CPACKET::SetRecvTimeOut(int sec)
{
    //设置接收超时sec s
    struct timeval timeout = {sec, 0};
    if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0) {
        PRINT_ERR_HEAD
        print_err("setsockopt err[%s]", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * [CPACKET::SetRecvAll 设置接收是否接收全部协议]
 * @param flag [全部协议]
 */
void CPACKET::SetRecvAll(bool flag)
{
    PRINT_INFO_HEAD
    print_info("set recvall[%s]", flag ? "true" : "false");
    m_recv_all = flag;
}
