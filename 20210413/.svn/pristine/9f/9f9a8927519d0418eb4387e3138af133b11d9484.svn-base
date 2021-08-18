/******************************************************************
** 文件名: FCBSTX.cpp
** Copyright (c) 2005

** 创建人:黄勇
** 日  期:2005-2-20
** 修改人:
** 日  期:
** 描  述:B/S通讯类
**
** 版  本:V1.1
** 修  改：
**    使用zlog                                    ------> 2018-08-07
**    不是0x0801的包不转发                        ------> 2018-11-27
**    可以设置线程名称                             ------> 2021-02-23
**    透明模式接收所有协议包，解决透明模式不转发问题  ------> 2021-04-07 wjl
*******************************************************************/
#include "crt.h"
#include "FCThread.h"
#include "debugout.h"
#include "common.h"
#include "work_mode.h"

loghandle glog_p = NULL;
#define SYSSET_FILE "/var/self/rules/conf/sysset.cf"

struct SPRO {
    SockServer *src;
    SockServer *dst;
};

typedef struct OPACKET {
    unsigned char DMac[6];
    unsigned char SMac[6];
    unsigned char BZType[2];
    unsigned char OType[2];
    unsigned char CType;
    unsigned char CKind;
    unsigned char CSum[2];
    unsigned char CSize[4];
} OPACKET, *POPACKET;

static int res = 0;
CThread th_src;
CThread th_dst;

void *thPro(void *param)
{
    pthread_setname("crt");
    SPRO *mypro = (SPRO *)param;
    unsigned char pbuf[10000];
    OPACKET pkt;
    int res = 0;

    while (1) {
        res = mypro->src->Recv(pbuf, sizeof(pbuf));
        if (res <= 0) {
            printf("res=%d\n", res);
        } else {
            memcpy(&pkt, pbuf, sizeof(pkt));
            if (pkt.BZType[0] != 0x08 || pkt.BZType[1] != 0x01) {
                //PRINT_DBG_HEAD
                //print_dbg("recv info not 0801 [%d]", res);
            } else {
                PRINT_INFO_HEAD
                print_info("recv info [%d]", res);
                mypro->dst->Send(pbuf, res);
            }
        }
    }
}

/**
 * [ReadWorkFlag 读取工作模式 判断是否需要接收全部协议包]
 * @param isall [全部协议]
 */
void ReadWorkFlag(bool &isall)
{
    CCommon common;
    char buf[512] = {0};
    char cmd[512] = {0};
    sprintf(cmd, "cat %s |grep WorkFlag|grep %d", SYSSET_FILE, WORK_MODE_TRANSPARENT);

    if (common.Sysinfo(cmd, buf, sizeof(buf)) == NULL) {
        PRINT_INFO_HEAD
        print_info("not transparent mode");
        isall = false;
    } else {
        PRINT_INFO_HEAD
        print_info("transparent mode");
        isall = true;
    }
}



int main(int argv, char *argc[])
{
    if (argv < 3) {
        printf("please input srcname dstname\n");
        return -1;
    }

    _log_init_(glog_p, crt);
    char chcmd[512] = {0};
    sprintf(chcmd, "ifconfig %s promisc up", argc[1]);
    system(chcmd);
    sprintf(chcmd, "ifconfig %s promisc up", argc[2]);
    system(chcmd);
    sleep(5);

    SPRO ssock, dsock;
    SockServer src;
    SockServer dst;

    struct stat buf;
    time_t tprev = 0;
    bool isall = true;
    bool isall_prev = true;
    stat(SYSSET_FILE, &buf);
    tprev = buf.st_mtime;
    ReadWorkFlag(isall);
    isall_prev = isall;

    int isock = src.Open(argc[1], isall_prev);
    int osock = dst.Open(argc[2], isall_prev);
    //printf("isock=%d osock=%d\n", isock, osock);
    ssock.src = &src;
    ssock.dst = &dst;
    dsock.src = &dst;
    dsock.dst = &src;
    th_src.ThCreate(thPro, &ssock);
    th_dst.ThCreate(thPro, &dsock);
    while (1) {
        sleep(1);
        stat(SYSSET_FILE, &buf);
        if (buf.st_mtime != tprev) {
            usleep(1000);//保证文件传输完毕
            ReadWorkFlag(isall);
            if (isall_prev != isall) {
                isall_prev = isall;
                th_src.ThDelete();
                th_dst.ThDelete();
                usleep(1000);
                PRINT_INFO_HEAD
                print_info("reload thread. isall[%s]", isall_prev ? "true" : "false");
                isock = src.Open(argc[1], isall_prev);
                osock = dst.Open(argc[2], isall_prev);
                //printf("isock=%d osock=%d\n", isock, osock);
                th_src.ThCreate(thPro, &ssock);
                th_dst.ThCreate(thPro, &dsock);
            }
            tprev = buf.st_mtime;
        }
    }
    return 0;
}

int SockServer::Open(char *eth, bool isall)
{
    if (ser_sock > 0) { //通讯已经建立
        Close();
    }

    /* 这里只处理热备协议 */
    if ((ser_sock = socket(PF_PACKET, SOCK_RAW, htons(isall ? ETH_P_ALL : ETH_P_HOTBAK))) == -1) {
        printf("sock req err\n");
        return E_SOCK_FALSE;
    }

    bzero(&sa, sizeof(struct sockaddr_ll));
    bzero(&sa_send, sizeof(struct sockaddr_ll));
    bzero(&sa_recv, sizeof(struct sockaddr_ll));

#if 0
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_HOTBAK);
    sa.sll_halen = 8;                     //length of hardware address
    //bcopy(source->ether_addr_octet, sa.sll_addr,8);
    sa.sll_ifindex = if_nametoindex(eth); //this is firewire0
    sa.sll_pkttype = PACKET_OUTGOING;
    printf("the index=%d\n", sa.sll_ifindex);
#else
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(isall ? ETH_P_ALL : ETH_P_HOTBAK);
    sa.sll_ifindex = if_nametoindex(eth);
    sa.sll_pkttype = PACKET_OUTGOING;
    printf("the index=%d\n", sa.sll_ifindex);

    sa_send.sll_family = PF_PACKET;
    sa_send.sll_ifindex = if_nametoindex(eth);

    //sa_recv.sll_family = PF_PACKET;
    //sa_recv.sll_pkttype = PACKET_BROADCAST;
    //sa_recv.sll_protocol = htons(ETH_P_HOTBAK);
#endif

#if 0
    //不需要混杂模式
    struct ifreq ifr;
    strcpy(ifr.ifr_name, eth);
    int res = ioctl(ser_sock, SIOCGIFFLAGS, &ifr);
    if ( res < 0) {
        printf("io err!\n");
    }
    ifr.ifr_flags |= IFF_PROMISC;
    res = ioctl(ser_sock, SIOCGIFFLAGS, &ifr);
    if ( res < 0) {
        printf("io err!\n");
    }
#endif

    if (bind(ser_sock, (struct sockaddr *) &sa, sizeof(sa)) == -1 ) {
        perror("bind()err");
    }
    return E_SOCK_OK;
}

int SockServer::Close()
{

    if (ser_sock > 0) { //通讯已经建立
#ifdef UNIX
        close(ser_sock);
#endif
    }

    ser_sock = -1;

    return E_SOCK_OK;
}

int SockServer::Recv(unsigned char *p_uchBuff, int iBuffLen)
{
    int iRecvLen = 0;
    iRecvLen = recvfrom(ser_sock, p_uchBuff, iBuffLen, 0, NULL, NULL);
    //s = sizeof(sa_recv);
    //iRecvLen = recvfrom(ser_sock, p_uchBuff, iBuffLen, 0, (struct sockaddr *)&sa_recv, &s);

    return iRecvLen;
}

/*****************************************************************
** 函数名:Send
** 输  入: char *p_uchBuff,int iBuffLen
**       p_uchBuff---    数据包
**       iBuffLen---     数据包长度


** 输  出: 实际发送的长度

** 功能描述: 发送数据包

** 作  者:黄勇
** 日  期:2004-2-20
** 修  改:
** 日  期:
** 版本：V1.0
****************************************************************/
int SockServer::Send(unsigned char *p_uchBuff, int iBuffLen)
{
    int iSendLen = -1;
    if (ser_sock < 0 || p_uchBuff == NULL || iBuffLen <= 0) {
        return E_SOCK_FALSE;
    }
    iSendLen = sendto(ser_sock, p_uchBuff, iBuffLen, 0, (struct sockaddr *)&sa_send, sizeof(struct sockaddr_ll));
    PRINT_INFO_HEAD
    print_info("send 0801 data [%d]", iBuffLen);
    return iSendLen;
}
