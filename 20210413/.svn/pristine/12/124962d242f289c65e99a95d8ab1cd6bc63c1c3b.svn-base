/*******************************************************************************************
*文件:  FCNetTimeSync.cpp
*描述:  开启同步网络时间线程
*作者:  王君雷
*日期:  2016-03
*修改:
*       线程ID使用pthread_t类型                                 ------> 2018-08-07
*       调用ntpclient，在所有输出行中搜索“SET TIME OK”串        ------> 2019-04-08
*******************************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "quote_global.h"
#include "FCTimeToPeer.h"
#include "gap_config.h"
#include "fileoperator.h"
#include "debugout.h"
#include "readcfg.h"
#include "define.h"

bool g_TimeChange;

/**
 * [ReadNetTimeConf 读取网络时间同步相关配置]
 * @param tserver    [时间服务器 出参]
 * @param serversize [时间服务器缓冲区长度]
 * @param cycle      [周期 分钟]
 * @param sync       [开关]
 */
void ReadNetTimeConf(char *tserver, int serversize, int &cycle, bool &sync)
{
    char server[128];
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSSET_CONF);
        return;
    }
    int tmpint = 0;
    READ_STRING(fileop, "SYSTEM", "NetTimeServer", server, false, _out);
    strcpy(tserver, server);
    READ_INT(fileop, "SYSTEM", "NetTimeCycle", cycle, false, _out);
    if (cycle <= 0) {
        cycle = DEFAULT_NET_TIME_CYCL;
    }
    READ_INT(fileop, "SYSTEM", "CKNetTime", tmpint, false, _out);
    sync = (tmpint == 1);
    fileop.CloseFile();

    PRINT_INFO_HEAD
    print_info("read net time info[%s][%d][%d]", tserver, cycle, sync);
    return;
_out:
    fileop.CloseFile();
}

/**
 * [CallNtpClient 调用ntpclient同步时间]
 * @param timeServer [时间服务器地址]
 */
void CallNtpClient(const char *timeServer)
{
    char cmd[1024] = {0};
    char line[1024] = {0};
    FILE *fp = NULL;

    if (timeServer[0] == 0) {
        PRINT_INFO_HEAD
        print_err("time server error[%s]", timeServer);
        return;
    }

    PRINT_INFO_HEAD
    print_info("call [%s]", NTPCLIENT);

    sprintf(cmd, "%s -h '%s' 2>& 1", NTPCLIENT, timeServer);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("popen [%s] fail.\n", cmd);
        return;
    }

    memset(line, 0, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "SET TIME OK") != NULL) {
            system("hwclock -w");
            time_to_peer(g_linklanipseg, g_linklanport);
            break;
        }
    }
    pclose(fp);
    fp = NULL;
}

/**
 * [NetTimeProcess 同步网络时间线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *NetTimeProcess(void *arg)
{
    pthread_setself("nettimeprocess");

    char timeServer[128];
    int timeCycle;
    bool timeSync;
    int cnt = 0;
    int totalcnt = 0;

    while (1) {
        sleep(1);
        if (g_TimeChange) {
            ReadNetTimeConf(timeServer, sizeof(timeServer), timeCycle, timeSync);
            g_TimeChange = false;
            cnt = 0;
            totalcnt = timeCycle * 60;
        }

        if (timeSync) {
            if (cnt == totalcnt) {
                cnt = 0;
                CallNtpClient(timeServer);
            } else {
                cnt++;
            }
        }
    }

    return NULL;
}

/**
 * [StartNetTimeSync 开启同步网络时间线程]
 * @return            [成功返回true]
 */
bool StartNetTimeSync(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, NetTimeProcess, NULL) != 0) {
        return false;
    }

    return true;
}
