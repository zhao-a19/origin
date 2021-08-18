/*******************************************************************************************
*文件:  checkmac.cpp
*描述:  获取MAC地址 比较是否冲突 冲突就报警
*作者:  王君雷
*日期:  2021-01-25
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;
#include <vector>
#include <string>
#include "common.h"
#include "hardinfo.h"
#include "debugout.h"
#include "fileoperator.h"

loghandle glog_p = NULL;
int g_linklan = -1;
#define ETH_P_CHECKMAC 0x88B6
#define ETH_P_CKMAC1 0x88
#define ETH_P_CKMAC2 0xB6

#define CHECKMAC_CONF "/var/self/sysinfo.cf"
#define BUFF_SIZE 65535
#define MAC_STR_LEN 17
#define SEND_TIME 60

#define NONE                 "\e[0m"
#define RED                  "\e[0;31m"
#define GREEN                "\e[0;32m"
#define UNDERLINE            "\e[4m"
#define BOLD                 "\e[1m"

typedef struct MACPACKET {
    unsigned char DMac[6];
    unsigned char SMac[6];
    unsigned char BZType[2];
    unsigned char MacNum[4];
    unsigned char Reserved[16];
} MACPACKET, *PMACPACKET;

/**
 * [summary 收集本侧MAC信息]
 * @param  vecmac [mac信息 出参]
 * @return        [成功返回0]
 */
int summary(vector<string> &vecmac)
{
//#define CONFLICT_TEST
#ifdef CONFLICT_TEST
    vecmac.push_back("aa:bb:cc:dd:ee:f1");
    vecmac.push_back("aa:bb:cc:dd:ee:f2");
#else
    CCommon common;
    int cardnum = 0;
    char buff[64] = {0};
    char tmpmac[64] = {0};

    if (common.Sysinfo("cat /proc/net/dev|grep eth|wc -l", buff, sizeof(buff)) == NULL) {
        PRINT_ERR_HEAD
        print_err("sysinfo fail");
        return -1;
    }
    cardnum = atoi(buff);
    //printf("SelfMacNum:%d\n", cardnum);

    for (int i = 0; i < cardnum; ++i) {
        if (get_mac(i, tmpmac)) {
            vecmac.push_back(tmpmac);
            //printf("SelfMAC%d: %s\n", i, tmpmac);
            PRINT_INFO_HEAD
            print_info("SelfMac%d: %s", i, tmpmac);
        } else {
            printf("get mac eth%d fail\n", i);
            return -1;
        }
    }
#endif
    return 0;
}

/**
 * [sockopen 创建原始套接字]
 * @return  [成功返回描述符 失败返回负值]
 */
int sockopen(void)
{
    int ser_sock = -1;
    struct sockaddr_ll sa;
    char eth[20] = {0};

    sprintf(eth, "eth%d", g_linklan);
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_CHECKMAC);
    sa.sll_halen = 8;
    sa.sll_ifindex = if_nametoindex(eth);
    sa.sll_pkttype = PACKET_OUTGOING;

    if ((ser_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CHECKMAC))) == -1) {
        printf("sock err %s\n", strerror(errno));
        return -1;
    }

    if (bind(ser_sock, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        printf("bind err %s\n", strerror(errno));
        close(ser_sock);
        return -1;
    }

    struct timeval timeout = {1, 0};
    if (setsockopt(ser_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0) {
        printf("setsockopt err %s\n", strerror(errno));
        close(ser_sock);
        return -1;
    }
    return ser_sock;
}

/**
 * [sendprocess 发送进程]
 * @param  vecmac [本端的MAC信息 需要发送给对端主机]
 * @return        [成功返回0]
 */
int sendprocess(vector<string> &vecmac)
{
    int fd = sockopen();
    if (fd < 0) {
        return -1;
    }

    char sendbuf[BUFF_SIZE] = {0};
    char macinfo[20] = {0};
    char eth[20] = {0};
    int num = vecmac.size();
    int len = 0;
    MACPACKET tmppack;
    struct sockaddr_ll sa;

    sprintf(eth, "eth%d", g_linklan);
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_CHECKMAC);
    sa.sll_halen = 8;
    sa.sll_ifindex = if_nametoindex(eth);
    sa.sll_pkttype = PACKET_OUTGOING;

    memset(&tmppack, 0, sizeof(tmppack));
    memset(&(tmppack.DMac), 0xFF, 6);
    memset(&(tmppack.SMac), 0xFF, 6);
    tmppack.BZType[0] = ETH_P_CKMAC1;
    tmppack.BZType[1] = ETH_P_CKMAC2;
    memcpy(&(tmppack.MacNum), &num, sizeof(num));
    memcpy(sendbuf, &tmppack, sizeof(tmppack));
    len += sizeof(tmppack);

    for (int i = 0; i < num; ++i) {
        sprintf(macinfo, "%s", vecmac[i].c_str());
        memcpy(sendbuf + len, macinfo, MAC_STR_LEN);
        len += MAC_STR_LEN;
    }

    for (int i = 0; i < SEND_TIME; ++i) {
        int slen = sendto(fd, sendbuf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (slen > 0) {
            //printf("[%2d]sendto success %d\n", i, slen);
        } else {
            printf("[%2d]sendto fail %d %s\n", i, slen, strerror(errno));
        }
        sleep(1);
    }
    close(fd);
    return 0;
}

/**
 * [Compare 比较内外网的MAC是否重复 并报警]
 * @param self_vecmac [内网本侧MAC]
 * @param peer_vecmac [外网对侧MAC]
 */
void Compare(vector<string> &self_vecmac, vector<string> &peer_vecmac)
{
    int snum = self_vecmac.size();
    int pnum = peer_vecmac.size();
    if (snum == pnum) {
        for (int i = 0; i < snum; ++i) {
            for (int j = 0; j < pnum; ++j) {
                if (self_vecmac[i] == peer_vecmac[j]) {
                    printf(RED "#########################################\n" NONE);
                    printf(RED "#  X  X  X  X  X  X  X  X  X  X  X  X  X \n" NONE);
                    printf(RED "# MAC CONFLICT: %s\n" NONE, peer_vecmac[j].c_str());
                    printf(RED "#  X  X  X  X  X  X  X  X  X  X  X  X  X \n" NONE);
                    printf(RED "#########################################\n" NONE);
                    return;
                }
            }
        }
        sleep(1);
        printf(GREEN "#########################################\n" NONE);
        printf(GREEN "#  √  √  √  √  √  √  √  √  √  √  √  √  √ \n" NONE);
        printf(GREEN "# MAC CHECK OK !\n" NONE);
        printf(GREEN "#  √  √  √  √  √  √  √  √  √  √  √  √  √ \n" NONE);
        printf(GREEN "#########################################\n" NONE);
    } else {
        printf("SelfCardNum %d, PeerMacNum %d\n", snum, pnum);
    }
    return;
}

/**
 * [recvprocess 接收进程]
 * @param  vecmac [本端的MAC信息 需要与对端发来的进行比较]
 * @return        [成功返回0]
 */
int recvprocess(vector<string> &vecmac)
{
    int fd = sockopen();
    if (fd < 0) {
        return -1;
    }

    char recvbuf[BUFF_SIZE] = {0};
    char macinfo[20] = {0};
    PMACPACKET ppack;
    int num = 0;
    vector<string> peer_vecmac;

    for (int i = 0; i < SEND_TIME; ++i) {
        int rlen = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        if (rlen < 0) {
            PRINT_INFO_HEAD
            print_info("[%2d]recv timeout! wait again! %d", i, rlen);
        } else {
            if (rlen > sizeof(MACPACKET)) {
                ppack = (PMACPACKET)recvbuf;
                memcpy(&num, &(ppack->MacNum), sizeof(num));
                //printf("PeerMacNum:%d\n", num);
                for (int j = 0; j < num; ++j) {
                    memcpy(macinfo, recvbuf + sizeof(MACPACKET) + j * MAC_STR_LEN, MAC_STR_LEN);
                    //printf("PeerMac%d: %s\n", j, macinfo);
                    PRINT_INFO_HEAD
                    print_info("PeerMac%d: %s", j, macinfo);
                    peer_vecmac.push_back(macinfo);
                }
                break;
            } else {
                printf("recvfrom len err %d\n", rlen);
            }
        }
    }
    close(fd);

    Compare(vecmac, peer_vecmac);
    return 0;
}

/**
 * [readlinklan 读取内联卡信息]
 * @return  [成功返回0]
 */
int readlinklan(void)
{
    CFILEOP fileop;
    if (fileop.OpenFile(CHECKMAC_CONF, "r") == E_FILE_FALSE) {
        printf("openfile error[%s]\n", CHECKMAC_CONF);
        return -1;
    }

    fileop.ReadCfgFileInt("SYSTEM", "LinkLan", &g_linklan);
    fileop.CloseFile();
    if (g_linklan < 0) {
        PRINT_ERR_HEAD
        printf("read LinkLan error[%d]!exit\n", g_linklan);
        return -1;
    }
    //printf("LinkLan: eth%d\n", g_linklan);
    return 0;
}

int main(int argc, char **argv)
{
    _log_init_(glog_p, checkmac);
    if (argc != 2) {
        printf("Usage: %s r/s\n", argv[0]);
        return -1;
    }

    vector<string> vecmac;
    if ((summary(vecmac) < 0)
        || (readlinklan() < 0)) {
        printf("fail\n");
        return -1;
    }

    char chcmd[1024] = {0};
    sprintf(chcmd, "ifconfig eth%d up", g_linklan);
    system(chcmd);

    if (strcmp(argv[1], "r") == 0) {
        printf("Receiver!\n");
        recvprocess(vecmac);
    } else {
        printf("Sender!\n");
        sendprocess(vecmac);
    }
    return 0;
}
