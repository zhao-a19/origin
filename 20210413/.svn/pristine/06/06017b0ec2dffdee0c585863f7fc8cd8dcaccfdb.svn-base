/*******************************************************************************************
*文件:  FCCmdProxy.cpp
*描述:  命令代理处理类
*作者:  王君雷
*日期:  2016-03
*修改:
*      线程ID使用pthread_t类型                                      ------> 2018-08-07
*      引入zlog                                                     ------> 2018-11-28
*      msgrcv出错时sleep延迟，防止记录太多zlog日志                  ------> 2018-12-18
*      向消息队列放数据时，非阻塞                                   ------> 2019-07-20
*      修改超时时间为60秒                                           ------> 2019-08-30
*      清理消息队列时，记录日志，方便拍错                           ------> 2020-05-13
*      解决ifconfig时的段错误                                      ------> 2020-10-29
*      可以设置线程名称                                            ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "define.h"
#include "struct_info.h"
#include "FCCmdProxy.h"
#include "quote_global.h"
#include "FCMsgAck.h"
#include "debugout.h"

/**
 * [CmdProxyInit 创建命令代理消息队列]
 * @return  [成功返回0]
 */
int CmdProxyInit(void)
{
    int oflag = O_RDONLY | O_WRONLY | O_RDONLY >> 3 | O_RDONLY >> 6 | IPC_CREAT | IPC_EXCL;

    //如果已经存在就先删除
    int tmpid = msgget(ftok(CMD_PROXY_PATH, 0), 0);
    if (tmpid >= 0) {
        msgctl(tmpid, IPC_RMID, NULL);
    }

    //创建
    int mqid = msgget(ftok(CMD_PROXY_PATH, 0), oflag);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s]", mqid, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * [cmdproxy_putmsg 把信息放入消息队列]
 * @param  cmd [命令]
 * @param  len [命令长度]
 * @return     [成功返回0]
 */
int cmdproxy_putmsg(const char *cmd, int len)
{
    if (len < (int)sizeof(long)) {
        PRINT_ERR_HEAD
        print_err("len error[%d]", len);
        return -1;
    }

    //打开system V消息队列
    int mqid = msgget(ftok(CMD_PROXY_PATH, 0), O_WRONLY);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s]", mqid, strerror(errno));
        return -1;
    }

    //准备好要发送到消息队列的消息缓冲区
    struct msgbuf *ptr = NULL;
    ptr = (struct msgbuf *)malloc(MAX_BUF_LEN + 1);
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc error[%s]", strerror(errno));
        return -1;
    }
    memset(ptr, 0, MAX_BUF_LEN + 1);
    memcpy(ptr, cmd, len);

    //发送
    int n = msgsnd(mqid, ptr, len - sizeof(long), IPC_NOWAIT);
    if (n < 0) {
        PRINT_ERR_HEAD
        print_err("msgsnd error[%d:%s]", n, strerror(errno));
        free(ptr);

        if (DEVFLAG[0] == 'I') {
            PRINT_INFO_HEAD
            print_info("cmdproxy queue full, queue init");
            CmdProxyInit();
        }
        return -1;
    }

    free(ptr);
    return 0;
}

/**
 * [mysystem 执行命令把输出存到临时文件 类似于系统函数system]
 * @param  cmd      [命令]
 * @param  filename [存放结果的文件路径]
 * @return          [成功返回0]
 */
int mysystem(const char *cmd, const char *filename)
{
    if ((cmd == NULL) || (filename == NULL)) {
        PRINT_ERR_HEAD
        print_err("para error[%s:%s]", cmd, filename);
        return -1;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        PRINT_ERR_HEAD
        print_err("fork error[%s]", strerror(errno));
        return -1;
    } else if (pid == 0) {
        char tmp[MAX_BUF_LEN] = {0};
        strcpy(tmp, cmd);
        strcat(tmp, " >");
        strcat(tmp, filename);
        strcat(tmp, " 2>&1 ");

        PRINT_DBG_HEAD
        print_dbg("%s", tmp);

        execl("/bin/sh", "sh", "-c", tmp, (char *)0);
        exit(127);//exec函数出错退出时才会执行这里
    } else {
        int ret = 0;
        for (int i = 0;; i++) {
            //15s
            ret = waitpid(pid, NULL, WNOHANG);
            if (ret == 0) {
                if (i < 60000) {
                    usleep(1000);
                    continue;
                }
                //kill child
                ret = kill(pid, SIGKILL);
                if (ret < 0) {
                    PRINT_ERR_HEAD
                    print_err("kill error[%s]", strerror(errno));
                }
            } else if (ret > 0) {
                return 0;
            } else {
                PRINT_ERR_HEAD
                print_err("error[%d]", ret);
                return -1;
            }
        }
    }
}

/**
 * [do_with_recvcmd 处理一条代理命令的线程函数]
 * @param  recvbuff [命令缓冲区]
 * @return          [未使用]
 */
void *do_with_recvcmd(void *recvbuff)
{
    pthread_setself("dowithcmd");
    long type = 0;
    char cmd[MAX_BUF_LEN] = {0};
    char sendbuf[MAX_BUF_LEN] = {0};
    char output[MAX_BUF_LEN] = {0};
    char tmpfile[256] = {0};
    unsigned int length = 0;
    HEADER header;
    BZERO(header);
    header.appnum = CMD_PROXY_TYPE;

    //取出type 和 命令
    memcpy(&type, recvbuff, sizeof(type));
    strcpy(cmd, (char *)recvbuff + sizeof(type));
    free(recvbuff);

    //临时文件名
    sprintf(tmpfile, "/tmp/%ld.tmp", type);

    PRINT_DBG_HEAD
    print_dbg("CMD[%s] tmpfile[%s]", cmd, tmpfile);

    //system执行这条命令 输出会存到临时文件中
    mysystem(cmd, tmpfile);

    //读取临时文件到output
    FILE *fp = NULL;
    if ((fp = fopen(tmpfile, "r")) != NULL) {
        if (fread(output, 1, sizeof(output) - sizeof(header) - sizeof(length) - sizeof(type) - 1, fp) < 0) {
            PRINT_ERR_HEAD
            print_err("fread error[%s] tmpfile[%s]", strerror(errno), tmpfile);
        }
        fclose(fp);
    }

    remove(tmpfile);

    //按协议组装信息
    length = sizeof(length) + sizeof(type) + strlen(output);
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), &type, sizeof(type));
    memcpy(sendbuf + sizeof(header) + sizeof(length) + sizeof(type), output, strlen(output));

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s] ret = %d", strerror(errno), fd);
        return NULL;
    }

    char ip[32] = {0};
    sprintf(ip, "%d.0.0.254", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton error[%s] ip[%s] port[%d]", strerror(errno), ip, g_linklanport);
        close(fd);
        return NULL;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //发送到内网 失败重发 最多发3次
    for (int i = 0; i < 3; i++) {
        ret = sendto(fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("sendto error. dip = %s, dport = %d, fd = %d, ret = %d, err = %s",
                      ip, g_linklanport, fd, ret, strerror(errno));
            close(fd);
            return NULL;
        }
        if (RecvMsgAck(fd, &addr, sizeof(addr), CMD_PROXY_TYPE) == 0) {
            PRINT_DBG_HEAD
            print_dbg("sendto innet ok[%s:%d:%d]", ip, g_linklanport, ret);
            break;
        }
        if (i == 2) {
            PRINT_ERR_HEAD
            print_err("sendto innet error. ip = %s, port = %d, fd = %d", ip, g_linklanport, fd);
        }
    }

    close(fd);
    return NULL;
}

/**
 * [cmdproxyserver 命令代理服务线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *cmdproxyserver(void *arg)
{
    pthread_setself("cmdproxy");
    //打开system V消息队列
    int mqid = msgget(ftok(CMD_PROXY_PATH, 0), O_RDONLY);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s]", mqid, strerror(errno));
        return NULL;
    }

    PRINT_INFO_HEAD
    print_info("cmdproxy server begin");
    while (1) {
        //准备接收缓冲区
        struct msgbuf *recvbuff = NULL;
        recvbuff = (struct msgbuf *)malloc(MAX_BUF_LEN + 1);
        if (recvbuff == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc error[%d:%s]", mqid, strerror(errno));
            sleep(1);
            continue;
        }
        memset(recvbuff, 0, MAX_BUF_LEN + 1);

        //阻塞接收队列中的第一条命令
        int n = msgrcv(mqid, recvbuff, MAX_BUF_LEN - sizeof(long), 0, MSG_NOERROR);
        if (n < 0) {
            PRINT_ERR_HEAD
            print_err("msgrcv error[id:%d ret:%d err:%s]", mqid, n, strerror(errno));
            free(recvbuff);
            usleep(100000);
            continue;
        }

        //为这条命令创建一个线程去执行 主线程继续接收新的命令
        pthread_t pthid = 0;
        if (pthread_create(&pthid, NULL, &do_with_recvcmd, (void *)recvbuff) != 0) {
            PRINT_ERR_HEAD
            print_err("pthread_create error[%s]", strerror(errno));
        }
        usleep(10000);
    }

    return NULL;
}

/**
 * [StartCmdProxyServer 开启命令代理服务]
 * @return  [成功返回0]
 */
int StartCmdProxyServer(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, cmdproxyserver, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread_create error[%s]", strerror(errno));
        return -1;
    }
    return 0;
}
