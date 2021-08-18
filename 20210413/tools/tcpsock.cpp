/*******************************************************************************************
*文件:  tcpsock.cpp
*描述:  tcp socket测试工具 用于测试指定IP和端口是否可以建立tcp连接
*作者:  王君雷
*日期:
*修改:
*       可以支持IPV4和IPV6两种类型的测试                               ------> 2019-03-11
*       使用socket通信类                                               ------> 2019-03-18
*       Connect写zlog前保存errno 写完后恢复errno                       ------> 2019-04-12
*       修改TCP服务工具超时描述                                        ------> 2020-04-28
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "log_translate.h"
#include "FCBSTX.h"
#include "debugout.h"

loghandle glog_p = NULL;

/**
 * [tcp_sock_test TCP端口测试]
 * @param  ip     [IP]
 * @param  chport [端口]
 * @return        [成功返回0 失败返回负值]
 */
int tcp_sock_test(const char *ip, const char *chport)
{
    if ((ip == NULL) || (chport == NULL)) {
        printf("ip[%s] chport[%s] null\n", ip, chport);
        return -1;
    }

    bool conn_ok = false;

    CBSTcpSockClient cli;
    int fd = cli.CreateSock(ip, atoi(chport), true);
    if (fd < 0) {
        printf("Open[%s][%s] fail\n", ip, chport);
        return -1;
    }

    int ret = cli.Connect(fd);
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            int error = 0;
            struct timeval tv;
            fd_set writefds;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            FD_ZERO(&writefds);
            FD_SET(fd, &writefds);
            int sret = select(fd + 1, NULL, &writefds, NULL, &tv);
            if (sret > 0) {
                socklen_t len = sizeof(int);
                //下面的一句一定要，主要针对防火墙
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                conn_ok = (error == 0);
                //printf("select ret = %d! error[%d] %s\n", sret, error, strerror(errno));
            } else {
                conn_ok = false; //timeout or error happen
                printf("timeout(%d)\n", sret);
            }
        } else {
            conn_ok = false;
            printf("connect fail! %s\n", strerror(errno));
        }
    } else {
        conn_ok = true;
    }

    close(fd);

    printf("%s!\n", conn_ok ? TCP_PORT_TEST_OK : TCP_PORT_TEST_FAIL);
    return conn_ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("\nUsage:%s hostip port\n\n", argv[0]);
        return -1;
    }

    _log_init_(glog_p, tcpsock);
    printf("IP[%s] PORT[%s]\n", argv[1], argv[2]);
    tcp_sock_test(argv[1], argv[2]);
    return 0;
}
