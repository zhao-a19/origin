/*******************************************************************************************
*文件:  FCDPDK.cpp
*描述:  启动DPDK相关接口函数
*作者:  王君雷
*日期:  2016-11-29
*修改:
*        线程ID使用pthread_t类型                                    ------> 2018-08-07
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <algorithm>
#include <string>
#include <errno.h>

#include "FCDPDK.h"
#include "define.h"
#include "critical.h"
#include "quote_global.h"
#include "debugout.h"

#define DPDK_TMP_FILE "/tmp/dpdk.tmp"

DPDK_CONTAINER::DPDK_CONTAINER()
{
    m_bfilter = false;
}

DPDK_CONTAINER::~DPDK_CONTAINER()
{
}

void DPDK_CONTAINER::SetFilter(bool filter)
{
    m_bfilter = filter;
}

/**
 * [DPDK_CONTAINER::CombineString 组装启动DPDK的字符串]
 * @param  chcmd [输出字符串]
 * @return       [成功返回0]
 */
int DPDK_CONTAINER::CombineString(char *chcmd)
{
    if (chcmd == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    if (m_bfilter) {
        sprintf(chcmd, "%s -c 0x3 -n 2 -- -filter 1 -log %d >/dev/null 2>&1", SUL2FWD_FILE,
                g_iflog ? 1 : 0);
    } else {
        sprintf(chcmd, "%s -c 0x3 -n 2 -- -filter 0 >/dev/null 2>&1", SUL2FWD_FILE);
    }

    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);

    return 0;
}

/**
 * [DPDKDeamon 启用DPDK的线程函数  当dpdk异常退出时负责重新拉起]
 * @param  arg [未使用]
 * @return     [无特殊含义]
 */
void *DPDKDeamon(void *arg)
{
    pthread_setself("dpdkdeamon");

    char chcmd[CMD_BUF_LEN] = {0};
    DPDK_CONTAINER container;

    //只内网过滤 外网不过滤
    container.SetFilter(DEVFLAG[0] == 'I');

    //组调用串
    if (container.CombineString(chcmd) < 0) {
        PRINT_ERR_HEAD
        print_err("CombineString err");
        return NULL;
    }

    while (1) {
        system(chcmd);
        PRINT_ERR_HEAD
        print_err("%s is stop, run again!", SUL2FWD_FILE);
        sleep(5);
    }

    return NULL;
}

/**
 * [StartDPDK 启动DPDK线程]
 * @return [成功返回0]
 */
int StartDPDK()
{
    pthread_t thid;
    if (pthread_create(&thid, NULL, DPDKDeamon, NULL) != 0) {
        return -1;
    }
    return 0;
}

/**
 * [GetNoRecoverCard 获取未恢复到最初状态的网卡PCI地址 如:0000:03:00.0]
 * @param vec [返回参数]
 */
#define PCI_NAME_LEN 12
void GetNoRecoverCard(vector<string> &vec)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpchar[PCI_NAME_LEN + 1] = {0};
    char linebuf[1024] = {0};

    //把当前状态打印输出到临时文件
    sprintf(chcmd, "%s --status >%s 2>&1", DPDK_NIC_BIND_PY, DPDK_TMP_FILE);
    system(chcmd);

    //打开临时文件
    FILE *fp = fopen(DPDK_TMP_FILE, "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("open err[%s][%s]", DPDK_TMP_FILE, strerror(errno));
        return ;
    }

    //逐行读取
    while (!feof(fp)) {
        if (fgets (linebuf, sizeof(linebuf), fp) == NULL) {
            break;
        }

        //含"if=eth" 说明已经正常
        if (strstr(linebuf, "if=eth") != NULL) {
            continue;
        }

        //含串"drv=igb_uio"或者"unused=igb_uio" 说明尚未恢复
        //例: 0000:02:02.0 '82545EM Gigabit Ethernet Controller (Copper)' drv=igb_uio unused=e1000
        if ((strstr(linebuf, "drv=igb_uio") != NULL) || (strstr(linebuf, "unused=igb_uio") != NULL)) {

            memcpy(tmpchar, linebuf, PCI_NAME_LEN);
            vec.push_back(tmpchar);
            PRINT_DBG_HEAD
            print_dbg("get one no recover PCI[%s]", tmpchar);
        }

        memset(linebuf, 0, sizeof(linebuf));
    }

    fclose(fp);
    remove(DPDK_TMP_FILE);
    return;
}

/**
 * [SortByPCI 根据PCI排序]
 * @param  str1 [PCI字符串1]
 * @param  str2 [PCI字符串2]
 * @return      [str1小于str2返回true]
 */
bool SortByPCI(const string str1, const string str2)
{
    return (str1 < str2);
}

/**
 * [UnbindPCI 解绑定PCI网卡  把加入到DPDK中的网卡恢复]
 * @param  str   [PCI串]
 * @param  drive [驱动类型]
 * @return       [成功返回0]
 */
int UnbindPCI(string &str, char *drive)
{
    if (drive == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    char chcmd[CMD_BUF_LEN] = {0};
    char linebuf[1024] = {0};
    bool iferr = false;

    sprintf(chcmd, "%s -b %s %s >%s 2>&1", DPDK_NIC_BIND_PY, drive, str.c_str(), DPDK_TMP_FILE);
    PRINT_DBG_HEAD
    print_dbg("%s", chcmd);
    system(chcmd);

    //打开临时文件
    FILE *fp = fopen(DPDK_TMP_FILE, "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("open file error[%s][%s]", DPDK_TMP_FILE, strerror(errno));
        return -1;
    }

    //逐行读取
    while (!feof(fp)) {
        if (fgets (linebuf, sizeof(linebuf), fp) == NULL) {
            break;
        }

        if (strstr(linebuf, "Cannot bind to") != NULL) {
            iferr = true;
            break;
        }
        memset(linebuf, 0, sizeof(linebuf));
    }

    fclose(fp);
    remove(DPDK_TMP_FILE);

    return (iferr ? -1 : 0);
}


/**
 * [ClearDPDKBind 清空DPDK绑定信息]
 * @return [成功返回0]
 */
int ClearDPDKBind()
{
    vector<string> veccard;
    veccard.clear();

    //获取未恢复到最初状态的网卡PCI地址
    GetNoRecoverCard(veccard);

    PRINT_DBG_HEAD
    print_dbg("no recover card count[%d]", (int)veccard.size());

    //排序
    sort(veccard.begin(), veccard.end(), SortByPCI);

    for (int i = 0; i < (int)veccard.size(); i++) {
        //先按千兆网卡恢复 再按万兆网卡恢复
        if ((UnbindPCI(veccard[i], "e1000e") < 0)
            && (UnbindPCI(veccard[i], "e1000") < 0)
            && (UnbindPCI(veccard[i], "igb") < 0)
            && (UnbindPCI(veccard[i], "ixgbe") < 0)
            && (UnbindPCI(veccard[i], "i40e") < 0)) {
            //都失败，就退出
            PRINT_ERR_HEAD
            print_err("fail to clear dpdk bind[%s]", veccard[i].c_str());
            return -1;
        }
    }

    return 0;
}

/**
 * [ClearDPDK 清空DPDK相关信息]
 * @return [description]
 */
int ClearDPDK()
{
    system("killall sul2fwd");
    return ClearDPDKBind();
}
