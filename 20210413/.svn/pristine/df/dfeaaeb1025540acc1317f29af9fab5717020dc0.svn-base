/*******************************************************************************************
*文件:  cmdproxy.cpp
*描述:  命令代理程序，把命令行参数原封不动的传到外网去执行 该程序运行在内网端
*作者:  王君雷
*日期:
*修改:
*       格式整理                                                        ------> 2019-03-20
*       消息队列中的type类型，不准为0                                   ------> 2019-07-20
*       修改超时时间为60秒                                              ------> 2019-08-30
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include "define.h"
#include "struct_info.h"
#include "fileoperator.h"
#include "FCMsgAck.h"
#include "debugout.h"

loghandle glog_p = NULL;

#define CMDPROXY_VERSION "2019-03-20"

//
//协议:
//  HEADER|LEN|TYPE|buf
//  LEN 其自身长度以及紧随其后的部分的长度之和
//  TYPE 消息队列中的消息类型 发送和接收响应时用它来找对应关系
//  buf 可选，发向外网时为代理的命令及参数信息 发向内网时为执行代理命令的输出结果
//
/**
 * [readlinkseg 读取内联通信网段]
 * @return  [网段值]
 */
int readlinkseg(void)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail. use default 1.[%s]", SYSINFO_CONF);
        return 1;
    }

    char tmp[100] = {0};
    if (m_fileop.ReadCfgFile("SYSTEM", "LinkLanIPSeg", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read LinkLanIPSeg fail.use default 1");
        strcpy(tmp, "1");
    }
    m_fileop.CloseFile();

    int seg = atoi(tmp);
    if (seg < 1 || seg > 255) {
        return 1;
    }
    return seg;
}

/**
 * [readlinkport 读取内部通信使用的端口]
 * @return  [端口号]
 */
int readlinkport(void)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail. use default %d.[%s]", DEFAULT_LINK_PORT, SYSINFO_CONF);
        return DEFAULT_LINK_PORT;
    }

    char tmp[100] = {0};
    if (m_fileop.ReadCfgFile("SYSTEM", "LinkLanPort", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        strcpy(tmp, "");
    }
    m_fileop.CloseFile();

    int port = atoi(tmp);
    if (port < 1 || port > 65535) {
        return DEFAULT_LINK_PORT;
    }
    return port;
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        printf("\nUsage(%s):\n\t%s cmd_name [arg1] [arg2] ....\n\n",
               CMDPROXY_VERSION, argv[0]);
        return -1;
    }

    _log_init_(glog_p, cmdproxy);

    unsigned int length = 0;
    char sendbuf[MAX_BUF_LEN];
    char cmdlinepara[MAX_BUF_LEN];
    HEADER header;
    memset(sendbuf, 0, sizeof(sendbuf));
    memset(cmdlinepara, 0, sizeof(cmdlinepara));
    memset(&header, 0, sizeof(header));

    //设置应用号为 命令代理类型
    header.appnum = CMD_PROXY_TYPE;

    //组装命令行参数到cmdlinepara
    strcat(cmdlinepara, argv[1]);
    for (int i = 2; i < argc; i++) {
        strcat(cmdlinepara, " ");
        strcat(cmdlinepara, argv[i]);
    }

    //printf("%s\n",cmdlinepara);
    struct timeval tm1 = {0};
    gettimeofday(&tm1, NULL);

    long type = tm1.tv_usec;//微秒数
    if (type == 0) {
        type = 1;
    }
    length = sizeof(length) + sizeof(type) + strlen(cmdlinepara);
    //printf("type = %d\n",type);

    //按协议组装信息
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), &type, sizeof(type));
    memcpy(sendbuf + sizeof(header) + sizeof(length) + sizeof(type), cmdlinepara, strlen(cmdlinepara));

    //打开system V消息队列
    int mqid = msgget(ftok(CMD_PROXY_PATH, 0), O_RDONLY);
    if (mqid < 0) {
        perror("cmdproxy msgget");
        return -1;
    }

    //准备接收缓冲区
    struct msgbuf *recvbuff = NULL;
    recvbuff = (struct msgbuf *)malloc(MAX_BUF_LEN + 1);
    if (recvbuff == NULL) {
        perror("cmdproxy malloc");
        return -1;
    }

    memset(recvbuff, 0, MAX_BUF_LEN + 1);
    memcpy(recvbuff, &type, sizeof(type));
    int flag = IPC_NOWAIT | MSG_NOERROR;

    //保证消息队列中没有该类型的消息
    while (msgrcv(mqid, recvbuff, MAX_BUF_LEN - sizeof(long), type, flag) >= 0) {
        memset(recvbuff, 0, MAX_BUF_LEN + 1);
        memcpy(recvbuff, &type, sizeof(type));
    }

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("cmdproxy socket");
        free(recvbuff);
        return -1;
    }

    //填写地址结构
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    char ip[IP_STR_LEN] = {0};
    int seg = readlinkseg();
    sprintf(ip, "%d.0.0.253", seg);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(readlinkport());
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        perror("cmdproxy inet_pton");
        close(fd);
        free(recvbuff);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    for (int i = 0; i < 3; i++) {
        //发送到外网
        ret = sendto( fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("cmdproxy sendto");
            close(fd);
            free(recvbuff);
            return -1;
        }

        if (RecvMsgAck(fd, &addr, sizeof(addr), CMD_PROXY_TYPE) == 0) {
            break;
        }

        if (i == 2) {
            printf("No ACK has been received from the outnet, please check the status of outnet!\n");
            close(fd);
            free(recvbuff);
            return -1;
        }
    }

    //close
    close(fd);

    ///////////////////////////////上面已将命令发送出去，下面接收执行结果////////////////////////////////////////
    int n = 0;
    //最多等待接收约15s 没接收到就退出
    for (int i = 0; i < 60100; i++) {
        n = msgrcv(mqid, recvbuff, MAX_BUF_LEN - sizeof(long), type, flag);
        if (n < 0) {
            //perror("msgrcv");
            usleep(1000);
            continue;
        } else {
            printf("%s", (char *)recvbuff + sizeof(long));
            fflush(stdout);
            break;
        }
    }

    free(recvbuff);
    return 0;
}
