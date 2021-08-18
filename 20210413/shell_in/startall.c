/*******************************************************************************************
*文件:  start.c
*描述:  重启后台程序
*作者:  王君雷
*日期:
*修改:
*      格式化代码，统一使用unix风格，utf8格式                   ------> 2018-08-28
*      start时添加启动ausvr                                     ------> 2018-09-21
*      启动ausvr时传入管理口网卡名称                            ------> 2018-09-28
*      通过宏可以指定是否启用授权检查                           ------> 2019-04-11
*      start中注释掉不必要的启动autobak进程                     ------> 2019-06-27
*      支持蜂鸣器时才包含sys/io.h文件                           ------> 2020-05-15
*      支持飞腾平台                                             ------> 2020-07-27
*      添加调用NEW_DBSYNC_TOOL                                  ------> 2020-08-17
*      使用NOHUP_RUN宏                                          ------> 2020-09-20
*      把对NEW_DBSYNC_TOOL的调用移动到hotbakmain中               ------> 2021-04-11
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"
#ifdef SUPPORT_SPEACKER
#include <sys/io.h>
#endif

loghandle glog_p = NULL;

/**
 * [locktest 文件锁测试 为了避免多个进程同时调用start]
 * @return [成功返回0]
 */
int locktest()
{
    int pidfd = 0;
    char line[1024] = {0};

    pidfd = open(START_PID_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (pidfd < 0) {
        perror("open");
        return -1;
    }

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;

    if (fcntl(pidfd, F_SETLK, &fl) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            printf("already running\n");
            exit (-1);
        } else {
            printf("unable to lock %s\n", START_PID_PATH);
            return (-1);
        }
    }
    snprintf(line, sizeof(line), "%d", (long)getpid());
    if (ftruncate(pidfd, 0) < 0) {
        perror("ftruncate");
        return (-1);
    }

    if (write(pidfd, line, strlen(line)) < 0) {
        perror("write");
        return (-1);
    }

    return 0;
}

/**
 * [read_cslan 读取管理口号]
 * @param  ethno [网卡号 出参]
 * @return       [读取成功返回true]
 */
bool read_cslan(int &ethno)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        printf("OpenFile error[%s]\n", SYSINFO_CONF);
        return false;
    }

    if (fileop.ReadCfgFileInt("SYSTEM", "CSLan", &ethno) != E_FILE_OK) {
        printf("start read sclan fail.\n");
        fileop.CloseFile();
        return false;
    }

    fileop.CloseFile();
    return true;
}

int main(int argc, char **argv)
{
    int mancardno = -1;
    char chcmd[CMD_BUF_LEN] = {0};

    _log_init_(glog_p, startall);
    locktest();
    system("sync");
    system(STOP_IN_BUSINESS);

#ifdef SUPPORT_SPEACKER
    //关闭蜂鸣器
    iopl(3);
    outb(0xb6, 0x43);
#endif

    if (read_cslan(mancardno)) {
        if (USE_LICENSE_CHECK == 1) {
            sprintf(chcmd, "%s /initrd/abin/ausvr eth%d >/dev/null &", NOHUP_RUN, mancardno);
            system(chcmd);
        }
        sprintf(chcmd, "%s /initrd/abin/hotbakmain >/dev/null &", NOHUP_RUN);
        system(chcmd);
        system("killall -s SIGUSR1 recvmain");
    } else {
        printf("Starting fail!\n");
        return -1;
    }
    //sprintf(chcmd, "%s &", NEW_DBSYNC_TOOL);
    //system(chcmd);
    printf("Starting OK!\n");
    return 0;
}
