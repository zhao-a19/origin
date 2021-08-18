/*******************************************************************************************
*文件:  tbl_err_comm.cpp
*描述:  表损坏 内部通信
*作者:  王君雷
*日期:  2019-12-09
*修改:
*       修改内存拷贝时没有强转指针类型的BUG，表损坏时没有把表名成功传递给处理线程 ------> 2020-11-21
*******************************************************************************************/
#include "tbl_err_comm.h"
#include "define.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "debugout.h"

#define TABLE_BAD_PATH         "/etc/init.d/"

/**
 * [tbl_err_comm_init 表损坏内部通信初始化]
 * @return  [成功返回true]
 */
bool tbl_err_comm_init(void)
{
    int oflag = O_RDONLY | O_WRONLY | O_RDONLY >> 3 | O_RDONLY >> 6 | IPC_CREAT | IPC_EXCL;

    //如果已经存在就先删除
    int tmpid = msgget(ftok(TABLE_BAD_PATH, 0), 0);
    if (tmpid >= 0) {
        msgctl(tmpid, IPC_RMID, NULL);
    }

    //创建
    int mqid = msgget(ftok(TABLE_BAD_PATH, 0), oflag);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s]", mqid, strerror(errno));
        return false;
    }
    return true;
}

/**
 * [tbl_err_put_request 表已经损坏 发送修复请求]
 * @param  tblname [表名]
 * @param  tlen   [表名长度]
 * @return        [成功返回true]
 */
bool tbl_err_put_request(const char *tblname, int tlen)
{
    if (tlen <= 0) {
        PRINT_ERR_HEAD
        print_err("tblname is null[%s],ignore repair request", tblname);
        return false;
    }

    //打开system V消息队列
    int mqid = msgget(ftok(TABLE_BAD_PATH, 0), O_WRONLY);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s].ignore [%s]", mqid, strerror(errno), tblname);
        return false;
    }

    //准备好要发送到消息队列的消息缓冲区
    struct msgbuf *ptr = NULL;
    long type = 1;

    ptr = (struct msgbuf *)malloc(MAX_BUF_LEN + 1);
    if (ptr == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc error[%s]", strerror(errno));
        return false;
    }
    memset((char *)ptr, 0, MAX_BUF_LEN + 1);
    memcpy((char *)ptr, &type, sizeof(type));
    memcpy(((char *)ptr) + sizeof(type), tblname, tlen);

    //发送
    int n = msgsnd(mqid, ptr, tlen, IPC_NOWAIT);
    if (n < 0) {
        PRINT_ERR_HEAD
        print_err("msgsnd error[%d:%s]", n, strerror(errno));
        free(ptr);
        return false;
    }
    free(ptr);
    PRINT_INFO_HEAD
    print_info("send table[%s] repair request over.", tblname);
    return true;
}

/**
 * [tbl_err_get_request 非阻塞获取一条损坏通知]
 * @param  tblname [表名 出参]
 * @param  tlen   [缓冲区长度]
 * @return        [获取成功返回true]
 */
bool tbl_err_get_request(char *tblname, int tlen)
{
    memset(tblname, 0, tlen);
    int flag = IPC_NOWAIT | MSG_NOERROR;
    long type = 0;

    //打开system V消息队列
    int mqid = msgget(ftok(TABLE_BAD_PATH, 0), O_RDONLY);
    if (mqid < 0) {
        PRINT_ERR_HEAD
        print_err("msgget error[%d:%s]", mqid, strerror(errno));
        return false;
    }

    //准备接收缓冲区
    struct msgbuf *recvbuff = NULL;
    recvbuff = (struct msgbuf *)malloc(MAX_BUF_LEN + 1);
    if (recvbuff == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc error[%d:%s]", mqid, strerror(errno));
        return false;
    }
    memset(recvbuff, 0, MAX_BUF_LEN + 1);

    //非阻塞接收队列中的第一条命令
    int n = msgrcv(mqid, recvbuff, MAX_BUF_LEN - sizeof(long), 0, flag);
    if (n < 0) {
        free(recvbuff);
        return false;
    } else if (n >= tlen) {
        PRINT_ERR_HEAD
        print_err("buff too short.[%d][%d][%s]", tlen, n, (char *)recvbuff + sizeof(long));
        free(recvbuff);
        return false;
    } else {
        memcpy(&type, recvbuff, sizeof(type));
        memcpy(tblname, (char *)recvbuff + sizeof(type), n);
        free(recvbuff);
        PRINT_INFO_HEAD
        print_info("get one table repair request.tblname[%s] n[%d] type[%d] success", tblname, n, type);
        return true;
    }
}
