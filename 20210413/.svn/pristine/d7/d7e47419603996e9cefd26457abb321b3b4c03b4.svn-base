/*******************************************************************************************
*文件:    diffcfg.h
*描述:    后台配置文件扫描
*
*作者:    赵子昂
*日期:    2020-10-19
*修改:    创建文件                                             ------>     2020-10-19
*******************************************************************************************/
#ifndef _DIFFCFG_H_
#define _DIFFCFG_H_
#include "datatype.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SCAN_SOCK   "/tmp/scan.sock"
#define START       "DEV-INIT"
#define SYSTEM_STARTALL     "/etc/init.d/startall &"
#define MAX_MODNUM  15

#define BUFFALERT   "BUFFALERT"
#define FILTERFG    "FilterFlag"
#define FILTERKN    "FilterKeyNum"
#define FILETYPE    "FileType"
#define CKVIRUS     "CKVirus"
#define AUTOBAK     "AUTOBAK"
#define NETTIME     "NetTime"
#define SYSMAXCONN  "SYSMaxConn"
#define STARTALL    "startall"
#define SPECIAL     "special"

//共用通知协议
#define M_KEYWORD    "ckkeymod"//关键字审查 发送 同时sysset
#define M_FSYNC      "fsyncmod"//文件交换
#define M_PRIVFSYNC  "privfile"//私有文件交换
#define M_NEWDBSYNC  "ndbsync"//新数据库同步
#define M_WEBPROXY   "webproxy"//web代理
#define M_MULTICAST  "multicast"//组播
#define M_DISKALERT  "diskalert"
#define M_FILETYPE   "filetype"
#define M_CKVIRUS    "ckvirus"
#define M_AUTOBAK    "autorulebak"
#define M_NETTIME    "nettime"
#define M_MAXCONN    "maxconn"

enum {
    SYSSET = 0,
    RULE,
    KEY,
    KEYUTF8,
    DEV,
    BONDING,
    MULTICAST,
    SIP,
    SIP_INTER_CNT,
    PDT,
    LINK_SIP,
    FILESYNC,
    PRIV_FILESYNC,
    WEBPROXY,
    NEW_DBSYNC,
    EMPTY,
};

typedef struct module {
    char modname[128];
    int is_change;
} MODULE;

int Scancfg(void);

/**
 * [scan_server 本地套接字服务端]
 * @param  recvmsg [接收数据]
 * @param  size    [接收数据大小]
 * @return         [description]
 */
int scan_server(void *recvmsg, int size)
{
    PRINT_DBG_HEAD
    print_dbg("INFO: into scan_server");

    int listen_fd;
    int com_fd;
    int ret;
    socklen_t len;
    struct sockaddr_un clt_addr;
    struct sockaddr_un srv_addr;

    listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        PRINT_ERR_HEAD
        print_err("cannot create communication socket");
        return -1;
    }
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, SCAN_SOCK, sizeof(srv_addr.sun_path) - 1);
    unlink(SCAN_SOCK);

    ret = bind(listen_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret == -1) {
        PRINT_ERR_HEAD
        print_err("cannot bind server socket");
        close(listen_fd);
        unlink(SCAN_SOCK);
        return -1;
    }

    ret = listen(listen_fd, 1);
    if (ret == -1) {
        PRINT_ERR_HEAD
        print_err("cannot listen the client connect request");
        close(listen_fd);
        unlink(SCAN_SOCK);
        return -1;
    }

    len = sizeof(clt_addr);
    com_fd = accept(listen_fd, (struct sockaddr *)&clt_addr, &len);
    if (com_fd < 0) {
        PRINT_ERR_HEAD
        print_err("cannot accept client connect request");
        close(listen_fd);
        unlink(SCAN_SOCK);
        return -1;
    }

    int num = read(com_fd, recvmsg, size);
    PRINT_DBG_HEAD
    print_dbg("Message from client (%d)) :%s", num, recvmsg);

    close(com_fd);
    close(listen_fd);
    unlink(SCAN_SOCK);
    return 0;
}

/**
 * [scan_client 本地套接字客户端]
 * @param  sendmsg [发送数据]
 * @param  size    [发送数据大小]
 * @return         [description]
 */
int scan_client(void *sendmsg, int size)
{
    PRINT_DBG_HEAD
    print_dbg("INFO: into scan_client");
    int connect_fd;
    int ret;
    static struct sockaddr_un srv_addr;

    connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (connect_fd < 0) {
        PRINT_ERR_HEAD
        print_err("cannot create communication socket");
        return -1;
    }
    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, SCAN_SOCK);

    ret = connect(connect_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret == -1) {
        PRINT_ERR_HEAD
        print_err("cannot connect to the server");
        close(connect_fd);
        return -1;
    }
    PRINT_DBG_HEAD
    print_dbg("Message to server :%s", sendmsg);

    write(connect_fd, sendmsg, size);
    close(connect_fd);
    return 0;
}

#endif