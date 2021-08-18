/*******************************************************************************************
*文件:  dbspeed.cpp
*描述:  mysql测试
*作者:  王君雷
*日期:  2018
*
*修改:
*       使用zlog记录日志                                              ------> 2018-07-23
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>
#include "FCLogManage.h"
#include "debugout.h"

loghandle glog_p = NULL;

int main(int argc, char *argv[])
{
    _log_init_(glog_p, dbspeed);

    CLOGMANAGE mlog;
    while (mlog.Init(true) != E_OK) {
        printf("mlog.Init fail!\n");
        sleep(1);
    }

    struct timeval t1, t2;

    while (1) {
        gettimeofday(&t1, NULL);
        for (int i = 0; i < 100; i++) {
            if (mlog.WriteLinkLog("192.168.1.100", "192.168.2.200", "8080", "9090", "writedbtest", "", "") != E_OK) {
                printf("mlog.WriteLinkLog fail1 %d\n", i);
            }
        }
        gettimeofday(&t2, NULL);

        unsigned  long diff;

        diff = 1000000 * (t2.tv_sec - t1.tv_sec) + t2.tv_usec - t1.tv_usec;

        printf("speed: %ld us\n", diff / 100);

        sleep(1);
    }

    mlog.DisConnect();

    return 0;
}

