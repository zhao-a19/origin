/*******************************************************************************************
*文件:  localip_api.cpp
*描述:  输入目的IP 输出本地使用的IP
*作者:  王君雷
*日期:  2019-12-17
*修改:
*******************************************************************************************/
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "localip_api.h"
#include "struct_info.h"
#include "define.h"
#include "debugout.h"

extern int g_linklanipseg;
extern int g_linklanport;

/**
 * [get_localip 获取去往目的IP时 本地选用的IP]
 * @param  dstip    [去往的IP]
 * @param  localip  [本地IP 出参]
 * @param  buffsize [本地IP 缓冲区大小]
 * @return          [成功返回0]
 */
int get_localip(const char *dstip, char *localip, int buffsize)
{
    bool ipv6 = (strchr(dstip, ':') != NULL);
    int port = 5000;//任意测试端口
    struct sockaddr_storage srcaddr, dstaddr;
    socklen_t srcaddrlen = sizeof(srcaddr);
    socklen_t dstaddrlen = sizeof(dstaddr);
    memset(&srcaddr, 0, sizeof(srcaddr));
    memset(&dstaddr, 0, sizeof(dstaddr));
    memset(localip, 0, buffsize);

    if (ipv6) {
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&dstaddr;
        addr_v6->sin6_family = AF_INET6;
        addr_v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, dstip, &(addr_v6->sin6_addr)) <= 0) {
            perror("inet_pton");
            return -1;
        }
    } else {
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&dstaddr;
        addr_v4->sin_family = AF_INET;
        addr_v4->sin_port = htons(port);
        if (inet_pton(AF_INET, dstip, &(addr_v4->sin_addr)) <= 0) {
            perror("inet_pton");
            return -1;
        }
    }

    int fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        PRINT_ERR_HEAD
        print_err("socket fail[%s]", strerror(errno));
        return -1;
    }

    int ret = connect(fd, (struct sockaddr *)&dstaddr, dstaddrlen);
    if (ret < 0) {
        perror("connect");
        PRINT_ERR_HEAD
        print_err("connect fail[%s]", strerror(errno));
        close(fd);
        return -1;
    }

    if (getsockname(fd, (struct sockaddr *)&srcaddr, &srcaddrlen) == 0) {
        if (ipv6) {
            struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&srcaddr;
            inet_ntop(AF_INET6, &(addr_v6->sin6_addr), localip, buffsize);
        } else {
            struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&srcaddr;
            inet_ntop(AF_INET, &(addr_v4->sin_addr), localip, buffsize);
        }
        close(fd);

        PRINT_DBG_HEAD
        print_dbg("dstip[%s] ---> localip[%s]", dstip, localip);
        return 0;
    } else {
        perror("getsockname");
        PRINT_ERR_HEAD
        print_err("getsockname fail[%s]", strerror(errno));
        close(fd);
        return -1;
    }
}

/**
 * [get_localip 获取去往目的IP时 本地选用的IP]
 * @param  dstip    [去往的IP]
 * @param  localip  [本地IP 出参]
 * @param  buffsize [本地IP 缓冲区大小]
 * @param  times    [尝试次数]
 * @return          [成功返回0]
 */
int get_localip(const char *dstip, char *localip, int buffsize, int times)
{
    int ret = -1;
    for (int i = 0; i < times; ++i) {
        ret = get_localip(dstip, localip, buffsize);
        if (ret == 0) {
            break;
        } else {
            sleep(1);
        }
    }
    return ret;
}

/**
 * [get_peer_localip 获取 网闸对端 去往目的IP时自己使用的IP]
 * @param  dstip    [目的IP]
 * @param  localip  [自己使用的IP 出参]
 * @param  buffsize [缓冲区大小]
 * @return          [成功返回0]
 */
int get_peer_localip(const char *dstip, char *localip, int buffsize)
{
    if ((dstip == NULL) || (localip == NULL) || (buffsize < 0)) {
        PRINT_ERR_HEAD
        print_err("input para error dstip[%s] buffsize[%d]", dstip, buffsize);
        return -1;
    }
    memset(localip, 0, buffsize);
    unsigned int length = sizeof(length) + strlen(dstip);
    char sendbuf[MAX_BUF_LEN] = {0};
    HEADER header;
    memset(&header, 0, sizeof(header));
    header.appnum = GET_LOCAL_IP_TYPE;

    //按协议组装信息
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), dstip, strlen(dstip));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD;
        print_err("socket error[%s],dstip[%s]", strerror(errno), dstip);
        return -1;
    }

    //填写地址结构
    int ret = 0;
    char linkip[IP_STR_LEN] = {0};
    sprintf(linkip, "%d.0.0.%d", g_linklanipseg, DEVFLAG[0] == 'I' ? 253 : 254);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    ret = inet_pton(AF_INET, linkip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD;
        print_err("inet_pton error[%s],dstip[%s]", strerror(errno), dstip);
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //发送到对端
    ret = sendto(fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("sendto error[%s],dstip[%s]", strerror(errno), dstip);
        close(fd);
        return -1;
    }
    ret = recvfrom(fd, localip, buffsize, 0, NULL, NULL);
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("recvfrom err[%s],dstip[%s]", strerror(errno), dstip);
        close(fd);
        return -1;
    }
    close(fd);
    PRINT_DBG_HEAD
    print_dbg("dstip[%s] ---> localip[%s]", dstip, localip);
    return 0;
}

/**
 * [get_peer_localip 获取 网闸对端 去往目的IP时自己使用的IP]
 * @param  dstip    [目的IP]
 * @param  localip  [自己使用的IP 出参]
 * @param  buffsize [缓冲区大小]
 * @param  times    [尝试次数]
 * @return          [成功返回0]
 */
int get_peer_localip(const char *dstip, char *localip, int buffsize, int times)
{
    int ret = -1;
    for (int i = 0; i < times; ++i) {
        ret = get_peer_localip(dstip, localip, buffsize);
        if (ret == 0) {
            PRINT_DBG_HEAD
            print_dbg("dstip[%s]--->localip[%s]", dstip, localip);
            break;
        } else {
            sleep(1);
        }
    }
    return ret;
}
