/*******************************************************************************************
*文件:    FCTimeToPeer.cpp
*描述:    时间同步到对端
*作者:    王君雷
*日期:
*修改:
*         使用UTF8编码                                                ------> 2018-04-09
*******************************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "const.h"
#include "FCTimeToPeer.h"
#include "struct_info.h"
#include "define.h"
#include "FCMsgAck.h"
#include "debugout.h"

/**
 * [time_to_peer 时间同步到对端]
 * @param  ipseg [内部通讯使用的地址段]
 * @param  port  [内部通讯端口号]
 * @return       [成功返回0 失败返回负值]
 */
int time_to_peer(int ipseg, int port)
{
    struct timeval tv;
    char send_buf[256] = {0};
    char ip[IP_STR_LEN] = {0};
    unsigned int length = 0;
    int apptype = SYNC_MICRO_TIME_TYPE;
    struct sockaddr_in addr;
    HEADER header;

    BZERO(header);
    header.appnum = apptype;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("secket fail[%s]", strerror(errno));
        return -1;
    }

    BZERO(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (DEVFLAG[0] == 'I') {
        sprintf(ip, "%d.0.0.253", ipseg);
    } else {
        sprintf(ip, "%d.0.0.254", ipseg);
    }
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton fail[%s]", strerror(errno));
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    while (1) {
        gettimeofday(&tv, NULL);
        length = sizeof(tv) + sizeof(length);

        memcpy(send_buf, &header, sizeof(header));
        memcpy(send_buf + sizeof(header), &length, sizeof(length));
        memcpy(send_buf + sizeof(header) + sizeof(length), &tv, sizeof(tv));

        ret = sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("sendto fail[%s]", strerror(errno));
            close(fd);
            return -1;
        }

        if (RecvMsgAck(fd, &addr, sizeof(addr), apptype) == 0) {
            break;
        }
    }

    close(fd);
    return 0;
}
