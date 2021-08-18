/*******************************************************************************************
*文件:  outcheck.cpp
*描述:  外网循环检查网卡的健康状态
*作者:  王君雷
*日期:  2020-06-22
*修改:
*******************************************************************************************/
#include <pthread.h>
#include "define.h"
#include "outcheck.h"
#include "debugout.h"
#include "FCPeerExecuteCMD.h"
#include "nic.h"

#define OUT_CHECK_CYCLE_SECONDS 10
#define CHECK_FAIL_TIME 4         //连续失败多少次 开始DOWN网卡

typedef struct _out_status{
    int linklan;        //内联卡号
    char chname[32];    //内联卡名 如 eth5
    uint64 link_rpkt;   //内联卡收包数
    int failcnt;        //检查失败计数
    bool isdown;        //当前网卡状态
} OUT_STATUS;

/**
 * [down_card DOWN掉内联卡之外的网卡]
 * @param  status [状态信息]
 * @return        [成功返回0]
 */
int down_card(OUT_STATUS* status)
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_ERR_HEAD
    print_err("down all cards. linklan[%s] linklan rpkt[%llu]", status->chname, status->link_rpkt);

    for (int i = 0; i < MAX_NIC_NUM; ++i) {
        if (i != status->linklan) {        
            sprintf(chcmd, "ifconfig eth%d down", i);
            system(chcmd);
        }
    }
    return 0;
}

/**
 * [out_check 外网循环检查线程函数]
 * @param arg [内联卡号]
 */
void* out_check(void* arg)
{
    pthread_setself("out_check");

    SNDEVINFO devinfo;
    OUT_STATUS last_status;
    memset(&last_status, 0, sizeof(last_status));
    last_status.isdown = false;
    last_status.linklan = *((int*)arg);
    sprintf(last_status.chname, "eth%d", last_status.linklan);

    PRINT_INFO_HEAD
    print_info("out check begin. linklan[%s]", last_status.chname);
    
    while(1) {
        sleep(OUT_CHECK_CYCLE_SECONDS);
        memset(&devinfo, 0, sizeof(devinfo));

        if (GetNetICValue(last_status.chname, &devinfo) < 0) {
            PRINT_ERR_HEAD
            print_err("get net[%s] devinfo fail", last_status.chname);
            continue;
        }

        if (devinfo.rpkt != last_status.link_rpkt) {
            last_status.link_rpkt = devinfo.rpkt;
            last_status.failcnt = 0;
            if (last_status.isdown) {
                PRINT_INFO_HEAD
                print_info("peer execute etc start. linklan[%s] linklan rpkt[%llu]", 
                    last_status.chname, last_status.link_rpkt);
                PeerExecuteCMD(ETC_START);
                last_status.isdown = !last_status.isdown;
            }
        } else {
            last_status.failcnt++;
            if (last_status.failcnt >= CHECK_FAIL_TIME) {
                if (!last_status.isdown) {
                    down_card(&last_status);
                    last_status.isdown = !last_status.isdown;
                }
                last_status.failcnt--;
            }
        }
    }
	return NULL;
}

/**
 * [StartOutCheck 开启授线程 周期性检查外网侧网口的状态]
 * @return  [成功返回0]
 */
int StartOutCheck(int* linklan)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, out_check, linklan) != 0) {
        PRINT_ERR_HEAD
        print_err("thread create fail");
        return -1;
    }
    return 0;
}
