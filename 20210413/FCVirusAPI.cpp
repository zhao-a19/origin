/*******************************************************************************************
*文件:  FCVirusAPI.cpp
*描述:  查毒接口
*作者:  王君雷
*日期:  2016-03
*修改:
*      把病毒库查杀服务的本地套接字路径放到gap_config.h中               ------> 2018-08-07
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include "FCVirusAPI.h"
#include "debugout.h"

/**
 * [FileSearchVirus 文件病毒检查接口]
 * @param  chFileName [本地文件绝对路径]
 * @param  iCodeType  [是否编码]
 * @param  virusname  [返回病毒名称]
 * @return            [E_OK:没有病毒   E_FALSE:检查失败  E_FINDED_VIRUS:有病毒]
 */
int FileSearchVirus(char *chFileName, int iCodeType, char *virusname)
{
    char buf[1024] = {0};
    int recvlen = 0;
    int fd = 0;
    struct sockaddr_un addr = {0};

    PRINT_DBG_HEAD
    print_dbg("search virus begin [%s]", chFileName);

    if (chFileName == NULL || virusname == NULL) {
        PRINT_ERR_HEAD
        print_err("para err");
        return E_FALSE;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail(%s)", strerror(errno));
        return E_FALSE;
    }

    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s", UNIX_VIRUS_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        PRINT_ERR_HEAD
        print_err("connect fail(%s)", strerror(errno));
        return E_FALSE;
    }

    if (send(fd, chFileName, strlen(chFileName), 0) <= 0) {
        PRINT_ERR_HEAD
        print_err("send fail(%s) filename[%s]", strerror(errno), chFileName);
        close(fd);
        return E_FALSE;
    }

    if ((recvlen = recv(fd, buf, sizeof(buf), 0)) <= 0) {
        PRINT_ERR_HEAD
        print_err("recv fail(%s) filename[%s], recvlen[%d]", strerror(errno), chFileName, recvlen);
        close(fd);
        return E_FALSE;
    }

    close(fd);

    PRINT_DBG_HEAD
    print_dbg("search virus over filename[%s] result[%d]", chFileName, buf[0]);

    //传输协议：1有病毒  0没病毒 2检查失败
    if (buf[0] == '1') {
        memcpy(virusname, buf + 1, recvlen - 1);
        return E_FINDED_VIRUS;
    } else if (buf[0] == '2') {
        return E_FALSE;
    } else {
        return E_OK;
    }
}
