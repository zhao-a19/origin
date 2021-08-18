
/*******************************************************************************************
*文件:  recvfiletcp.cpp
*描述:  接收文件 TCP方式传输
*作者:  王君雷
*日期:  2020-02-24
*修改:
*       TCP文件上传服务 改用transfer程序                                 ------> 2020-03-10
*       可以设置线程名称                                                 ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <pthread.h>
#include "recvfiletcp.h"
#include "debugout.h"
#include "define.h"

extern int g_linklanipseg;
extern int g_linktcpfileport;

/**
 * [recvfiletcp TCP收取文件线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *recvfiletcp(void *arg)
{
    pthread_setself("recvfiletcp");
    char chcmd[CMD_BUF_LEN] = {0};

    while (1) {
        sprintf(chcmd, "killall transfer >/dev/null 2>&1");
        system(chcmd);
        sprintf(chcmd, "%s -S -a %d.0.0.%s -p %d -t 10", TRANSFER_FILE, g_linklanipseg,
                (DEVFLAG[0] == 'I') ? "254" : "253", g_linktcpfileport);
        system(chcmd);

        sleep(2);
        PRINT_ERR_HEAD
        print_err("pull up[%s]again", chcmd);
    }
    return NULL;
}

/**
 * [StartRecvFileTCP TCP方式接收文件]
 * @return  [成功返回0]
 */
int StartRecvFileTCP(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, recvfiletcp, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create thread recvfiletcp fail");
        return -1;
    }
    return 0;
}
