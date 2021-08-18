/*******************************************************************************************
*文件: FCPeerExecuteCMD.cpp
*描述: 让网闸对端执行命令
*作者: 王君雷
*日期: 2016-03
*修改:
*         函数命名统一风格                                              ------> 2018-04-23
*         添加PeerExecuteCMD2接口函数                                   ------> 2018-07-19
*         支持通过参数指定超时时间                                       ------> 2020-09-04
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "FCPeerExecuteCMD.h"
#include "struct_info.h"
#include "define.h"
#include "FCMsgAck.h"
#include "debugout.h"

extern int g_linklanipseg;
extern int g_linklanport;

/**
 * [PeerExecuteCMD 让网闸对端执行命令 需要确认是否收到  无需回应详细信息]
 * @param  cmd [命令]
 * @param  timeout [超时时间]
 * @return     [成功返回0]
 */
int PeerExecuteCMD(const char *cmd, int timeout)
{
    char ip[IP_STR_LEN] = {0};
    if (DEVFLAG[0] == 'I') {
        sprintf(ip, "%d.0.0.253", g_linklanipseg);
    } else {
        sprintf(ip, "%d.0.0.254", g_linklanipseg);
    }

    return PeerExecuteCMD2(cmd, ip, g_linklanport, timeout);
}

/**
 * [PeerExecuteCMD2 让网闸对端执行命令 需要确认是否收到  无需回应详细信息]
 * @param  cmd   [命令]
 * @param  dip   [对端IP]
 * @param  dport [对端端口]
 * @param  timeout [超时时间]
 * @return       [成功返回0]
 */
int PeerExecuteCMD2(const char *cmd, const char *dip, int dport, int timeout)
{
    if (cmd == NULL) {
        PRINT_ERR_HEAD;
        print_err("cmd null, dip[%s], dport[%d]", dip, dport);
        return -1;
    }

    unsigned int length = sizeof(length) + strlen(cmd);
    char sendbuf[MAX_BUF_LEN] = {0};
    HEADER header;
    memset(&header, 0, sizeof(header));
    header.appnum = CMD_EXECUTE_TYPE;

    //按协议组装信息
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), cmd, strlen(cmd));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD;
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

    //填写地址结构
    int ret = 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dport);
    ret = inet_pton(AF_INET, dip, (void *)&addr.sin_addr);
    if ( ret <= 0 ) {
        PRINT_ERR_HEAD;
        print_err("inet_pton error[%s]", strerror(errno));
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval to = {(timeout <= 0) ? MSG_ACK_TIME_SEC : timeout, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(struct timeval));

    while (1) {
        //发送到对端
        ret = sendto(fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            PRINT_ERR_HEAD;
            print_err("sendto error[%s]", strerror(errno));
            close(fd);
            return -1;
        }

        if (RecvMsgAck(fd, &addr, sizeof(addr), CMD_EXECUTE_TYPE) == 0) {
            break;
        }
        PRINT_ERR_HEAD
        print_err("peer timeout[%s], resend", cmd);
    }

    close(fd);
    return 0;
}
