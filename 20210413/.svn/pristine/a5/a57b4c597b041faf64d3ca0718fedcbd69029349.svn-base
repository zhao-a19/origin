/*******************************************************************************************
*文件:  FCSyncTime.cpp
*描述:  开启同步系统时间线程
*作者:  王君雷
*日期:  2016-06-02
*修改:
*        线程ID使用pthread_t类型                                    ------> 2018-08-07
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "define.h"
#include "quote_global.h"
#include "FCTimeToPeer.h"
#include "debugout.h"

#define SYNC_TIME_CYCLE       300//内网向外网同步系统时间的周期s

//同步系统时间 内网->外网
void *sync_time(void *arg)
{
    pthread_setself("sync_time");

    while (1) {
        time_to_peer(g_linklanipseg, g_linklanport);
        sleep(SYNC_TIME_CYCLE);
    }
    return NULL;
}

bool StartSyncTime(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, sync_time, NULL) != 0) {
        return false;
    }
    return true;
}


