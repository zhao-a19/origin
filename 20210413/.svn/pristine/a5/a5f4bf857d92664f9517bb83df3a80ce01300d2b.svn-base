/*******************************************************************************************
*文件:  mysqltest.cpp
*描述:  mysql测试
*作者:  王君雷
*日期:  2018
*
*修改:
*       使用zlog记录日志                                              ------> 2018-07-23
*       创建线程后，加延迟，防止参数失效                              ------> 2019-05-28
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include "FCLogManage.h"
#include "debugout.h"

typedef struct {
    int seq;
    int printtimes;
} ThreadPara;

loghandle glog_p = NULL;

/**
 * [fun 线程函数]
 * @param  arg [线程参数]
 * @return     [无]
 */
void *fun(void *arg)
{
    pthread_setself("mysqltest");
    if (arg == NULL) {
        printf("para error!\n");
        return NULL;
    }
    ThreadPara para = *((ThreadPara *)arg);
    free((ThreadPara *)arg);
    arg = NULL;

    CLOGMANAGE mlog;
    while (mlog.Init(true) != E_OK) {
        printf("mlog.Init fail,seq=%d\n", para.seq);
        sleep(1);
    }
    printf("mlog.Init ok[%d]\n", para.seq);

    for (int i = 0; i < para.printtimes; i++) {
        if (mlog.WriteLinkLog("192.168.1.100", "192.168.2.200", "8080", "9090", "writedbtest", "", "") != E_OK) {
            printf("mlog.WriteLinkLog fail,seq=%d\n", para.seq);
            break;
        }
        usleep(1000);
    }

    printf("Thread[%d] writeDB success!\n", para.seq);
    mlog.DisConnect();
    return NULL;
}

/**
*功能介绍：mysql数据库压力测试
*程序参数：./mysqltest threadnum printtimes
*参数含义：
*          threadnum 启动线程个数
*          printtimes 每个线程打印次数
*/
int main(int argc, char *argv[])
{
    _log_init_(glog_p, mysqltest);

    if (argc != 3) {
        printf("Usage:%s threadnum printtimes\n", argv[0]);
        return 0;
    }

    int threadnum = atoi(argv[1]) < 10000 ? atoi(argv[1]) : 10000;
    int printtimes = atoi(argv[2]);
    pthread_t pid[10000] = {0};

    //mysql_library_init(0,NULL,NULL);

    for (int i = 0; i < threadnum ; i++ ) {
        ThreadPara *ppara = NULL;
        ppara = (ThreadPara *)malloc(sizeof(ThreadPara));
        if (ppara == NULL) {
            perror("malloc");
            printf("malloc fail,i=%d\n", i);
            break;
        }
        memset(ppara, 0, sizeof(ThreadPara));
        ppara->seq = i;
        ppara->printtimes = printtimes;

        if (pthread_create(&(pid[i]), NULL, fun, ppara) < 0) {
            perror("pthread_create");
            printf("pthread_create fail,i=%d\n", i);
        }
        usleep(10000);
    }

    printf("main sleep!\n");
    while (1) {
        sleep(100);
    }
    //mysql_library_end();

    return 0;
}

