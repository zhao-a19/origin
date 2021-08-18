/*******************************************************************************************
*文件:  socket.cpp
*描述:  socket相关操作函数
*作者:  王君雷
*日期:  2020-03-07
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "socket.h"
#include "debugout.h"

/**
 * [fill_addr 填充地址结构]
 * @param  ip      [IP]
 * @param  port    [端口]
 * @param  addr    [地址结构]
 * @param  addrlen [填充后的地址结构长度 出参]
 * @return         [成功返回true]
 */
bool fill_addr(const char *ip, int port, struct sockaddr_storage &addr, int &addrlen)
{
    if ((strchr(ip, ':') != NULL)) {
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
 * [server_socket 创建服务端检查套接字监听端口]
 * @param  ip   [IP]
 * @param  port [端口]
 * @return      [成功返回描述符 失败返回负值]
 */
int server_socket(const char *ip, int port)
{
    int addrlen = 0;
    struct sockaddr_storage serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    if (!fill_addr(ip, port, serveraddr, addrlen)) {
        return -1;
    }

    bool ipv6 = (strchr(ip, ':') != NULL);
    int sockfd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        PRINT_ERR_HEAD
        print_err("socket fail[%s].ip[%s] port[%d]", strerror(errno), ip, port);
        return -1;
    }
    int dwyes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&dwyes, sizeof(dwyes));

    if (bind(sockfd, (const struct sockaddr *) &serveraddr, addrlen) == -1) {
        PRINT_ERR_HEAD
        print_err("bind fail[%s].ip[%s] port[%d]", strerror(errno), ip, port);
        CLOSE(sockfd);
        return -1;
    }

    if (listen(sockfd, MAX_LISTEN_NUM) == -1) {
        PRINT_ERR_HEAD
        print_err("listen fail[%s].ip[%s] port[%d]", strerror(errno), ip, port);
        CLOSE(sockfd);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("server socket ok[%d]", sockfd);
    return sockfd;
}

/**
 * [client_socket 客户端连接服务器]
 * @param  ip   [IP]
 * @param  port [端口]
 * @return      [成功返回描述符 失败返回负值]
 */
int client_socket(const char *ip, int port)
{
    int addrlen = 0;
    struct sockaddr_storage serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    if (!fill_addr(ip, port, serveraddr, addrlen)) {
        PRINT_ERR_HEAD
        print_err("fill addr fail ip[%s] port[%d]", ip, port);
        return -1;
    }

    bool ipv6 = (strchr(ip, ':') != NULL);
    int sockfd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        PRINT_ERR_HEAD
        print_err("socket fail[%s].ip[%s] port[%d]", strerror(errno), ip, port);
        return -1;
    }

    if (connect(sockfd, (const struct sockaddr *) &serveraddr, addrlen) < 0) {
        PRINT_ERR_HEAD
        print_err("connect fail[%s].ip[%s] port[%d]", strerror(errno), ip, port);
        CLOSE(sockfd);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("client socket ok[%d]", sockfd);
    return sockfd;
}
