/*******************************************************************************************
*文件: au_api.cpp
*描述: 授权服务程序 客户端API
*作者: 王君雷
*日期: 2018-09-20
*修改:
*      包含au_define.h头文件                                        ------> 2018-10-15
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include "au_api.h"
#include "au_define.h"
#include "ausvr.h"
#include "debugout.h"
#include "common.h"
#include "FCMD5.h"

/**
 * [connect_to_ausvr 连接心跳服务]
 * @return [成功返回描述符 失败返回负值]
 */
int connect_to_ausvr(void)
{
    struct sockaddr_un addr;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

    if (strlen(UNIX_AUTHSVR) >= sizeof(addr.sun_path)) {
        PRINT_ERR_HEAD
        print_err("unixpath too long[%s], max support %lu", UNIX_AUTHSVR, sizeof(addr.sun_path));
        close(fd);
        return -1;
    }
    BZERO(addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, UNIX_AUTHSVR);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PRINT_ERR_HEAD
        print_err("connect error[%s]", strerror(errno));
        close(fd);
        return -1;
    }

    struct timeval timeout = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
    return fd;
}

/**
 * [ausvr_api 授权服务 心跳检查]
 * @return [心跳成功返回true]
 */
bool ausvr_api(void)
{
    int fd = 0;
    int slen = 0, rlen = 0;
    char request[HEARTBEAT_REQUEST_LEN] = {0};
    CCommon common;
    unsigned char md5buff32[32] = {0};
    AU_RESPONSE response;
    BZERO(response);

    if ((fd = connect_to_ausvr()) > 0) {
        common.RandomHexChar(request, sizeof(request));

        //发送心跳
        slen = send(fd, request, sizeof(request), 0);
        if (slen != sizeof(request)) {
            PRINT_ERR_HEAD
            print_err("send request fail[%d:%s]", slen, strerror(errno));
            close(fd);
            return false;
        }

        //接收回应
        rlen = recv(fd, (char *)&response, sizeof(response), 0);
        if (rlen != sizeof(response)) {
            PRINT_ERR_HEAD
            print_err("recv response fail[%d:%s]", rlen, strerror(errno));
            close(fd);
            return false;
        }

        //校验请求与回应对应关系
        common.CharReplace(request, sizeof(request));
        if (!md5sum_buff(request, sizeof(request), NULL, md5buff32)) {
            PRINT_ERR_HEAD
            print_err("md5sum buff fail");
            close(fd);
            return false;
        }

        //关闭
        close(fd);

        if (memcmp(md5buff32, response.md5buff32, 32) != 0) {
            PRINT_ERR_HEAD
            print_err("not my response");
            return false;
        }

        if (response.result == AUSVR_RESULT_OK) {
            PRINT_DBG_HEAD
            print_dbg("ausvr return ok");
            return true;
        } else {
            PRINT_ERR_HEAD
            print_err("ausvr return fail");
            return false;
        }
    }

    return false;
}
