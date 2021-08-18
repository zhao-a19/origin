/*******************************************************************************************
*文件:  FCLicenseCK.cpp
*描述:  授权期限检查
*作者:  王君雷
*日期:  2016-04-29
*修改:
*       使用zlog记录日志;
*       使用IPTABLES宏                                                    ------> 2018-08-13
*       使用宏STOP_IN_BUSINESS_LICENSE_CK                                 ------> 2018-08-28
*       设备期限授权重新设计，通过心跳去检查是否到期                      ------> 2018-09-21
*       授权到期清理时，考虑ip6tables相关清空操作                         ------> 2019-06-13
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include "FCLicenseCK.h"
#include "debugout.h"
#include "critical.h"
#include "au_api.h"
#include "au_logtrans.h"
#include "FCPeerExecuteCMD.h"
#include "FCLogManage.h"

#define AU_CHECK_CYCLE (5 * 60)

/**
 * [license_clear 授权到期后 清理操作]
 */
void license_clear(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    CLOGMANAGE mlog;

    if (mlog.Init() == E_OK) {
        mlog.WriteSysLog(LOG_TYPE_AUTH_CK, D_FAIL, AUTH_EXPIRED_VERSION);
        mlog.DisConnect();
    }

    system("rmmod bonding >/dev/null 2>&1 ");
    sprintf(chcmd, "%s -F", IPTABLES);
    system(chcmd);
    sprintf(chcmd, "%s -t nat -F", IPTABLES);
    system(chcmd);
    sprintf(chcmd, "%s -F", IP6TABLES);
    system(chcmd);
    sprintf(chcmd, "%s -t nat -F", IP6TABLES);
    system(chcmd);
    system("ebtables -F");
    PeerExecuteCMD(STOP_OUT_BUSINESS_LICENSE_CK);
    system(STOP_IN_BUSINESS_LICENSE_CK);
}

/**
 * [license_check 授权心跳检查]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *license_check(void *arg)
{
    pthread_setself("license_check");

    int failcnt = 0;//记录连续失败次数

    sleep(5);

    while (1) {
        if (ausvr_api()) {
            failcnt = 0;
            sleep(AU_CHECK_CYCLE);
        } else {
            sleep(1);
            failcnt++;
            //连续失败超过3次 即退出
            if (failcnt > 3) {
                PRINT_ERR_HEAD
                print_err("au heartbeat fail,exit");
                license_clear();
                exit(-1);
            } else {
                PRINT_ERR_HEAD
                print_err("auth heartbeat fail[failcnt:%d],retry...", failcnt);
            }
        }
    }
    return NULL;
}

/**
 * [StartLicenseCK 开启授权心跳检查线程]
 * @return  [成功返回0]
 */
int StartLicenseCK(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, license_check, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("thread create fail");
        return -1;
    }
    return 0;
}
