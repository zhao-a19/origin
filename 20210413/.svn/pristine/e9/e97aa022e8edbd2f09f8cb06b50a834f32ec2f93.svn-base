/*******************************************************************************************
*文件:  pvt_filesync.cpp
*描述:  私有协议 文件同步任务类
*作者:  王君雷
*日期:  2018-08-30
*修改:
*       私有协议文件交换程序调用方法改变，通过命令行参数传递全局日志开关、关键字文件
*                                                                        ------> 2018-11-03
*       安全通道使用SEC_WAY类                                            ------> 2019-01-02
*       支持IPV6，支持IPV4和IPV6交叉同步                                 ------> 2019-06-05
*       支持分模块生效                                                   ------> 2020-11-05
*       所有任务总共只写一次配置文件                                      ------> 2021-01-11
*       fileclient每次重启都记录系统日志                                 ------> 2021-01-13
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>

#include "FCLogManage.h"
#include "define.h"
#include "pvt_filesync.h"
#include "readcfg.h"
#include "debugout.h"
#include "stringex.h"
#include "card_mg.h"
#include "common.h"

extern sem_t *g_iptables_lock;
extern CardMG g_cardmg;
extern bool g_ckkey;
extern bool g_iflog;

int g_pvtf_num = 0;//私有文件交换任务数
bool g_pvtf_change = false;//私有文件交换策略是否变化了

PVT_FILESYNC::PVT_FILESYNC(int task_id)
{
    m_taskid = task_id;
    snprintf(m_natport, sizeof(m_natport), "%d", (PVT_NAT_START_PORT + m_taskid) % 65535 + 1);
}

PVT_FILESYNC::~PVT_FILESYNC(void)
{

}

/**
 * [PVT_FILESYNC::loadConf 加载配置信息]
 * @return            [成功返回true]
 */
bool PVT_FILESYNC::loadConf(void)
{
    PRINT_DBG_HEAD
    print_dbg("load conf begin");

    bool bflag = false;
    char taskid[16] = {0};
    int indev = -1;
    int outdev = -1;
    int area = 0;

    CFILEOP fileop;
    if (fileop.OpenFile(PRIV_FILESYNC_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", PRIV_FILESYNC_CONF);
        goto _out;
    }

    sprintf(taskid, "DIR%d", m_taskid);
    READ_INT(fileop, taskid, "InDev", indev, true, _out);
    READ_INT(fileop, taskid, "OutDev", outdev, true, _out);
    READ_INT(fileop, taskid, "Area", area, true, _out);
    m_secway.setway("", area, indev, outdev);
    READ_STRING(fileop, taskid, "INSVRIP", m_insvrip, true, _out);
    READ_STRING(fileop, taskid, "OUTSVRIP", m_outsvrip, true, _out);
    READ_STRING(fileop, taskid, "INSVRPORT", m_insvrport, true, _out);
    READ_STRING(fileop, taskid, "OUTSVRPORT", m_outsvrport, true, _out);
    bflag = true;
    showConf();

_out:
    fileop.CloseFile();
    PRINT_DBG_HEAD
    print_dbg("load conf over(%s)", bflag ? "ok" : "fail");
    return bflag;
}

/**
 * [PVT_FILESYNC::showConf 显示配置信息]
 */
void PVT_FILESYNC::showConf(void)
{
    PRINT_DBG_HEAD
    print_dbg("ID = %d, Area = %d", m_taskid, m_secway.getarea());
    PRINT_DBG_HEAD
    print_dbg("InDev = %d, OutDev = %d", m_secway.getindev(), m_secway.getoutdev());
    PRINT_DBG_HEAD
    print_dbg("INSVRIP = %s, OUTSVRIP = %s", m_insvrip, m_outsvrip);
    PRINT_DBG_HEAD
    print_dbg("INSVRPORT = %s, OUTSVRPORT = %s", m_insvrport, m_outsvrport);
}

/**
 * [getSecway 获取安全通道]
 * @return  [安全通道的引用]
 */
SEC_WAY &PVT_FILESYNC::getSecway(void)
{
    return m_secway;
}

/**
 * [PVT_FILESYNC::setOutIptables 外网设置NAT跳转的iptables]
 */
void PVT_FILESYNC::setOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (is_ip6addr(m_outsvrip)) {
        MAKE_TABLESTRING(chcmd, "-t nat -A NAT_PRIV_FILE -d %s -p tcp --dport %s -j DNAT --to ['%s']:'%s'",
                         true, m_natip, m_natport, m_outsvrip, m_outsvrport);
    } else {
        MAKE_TABLESTRING(chcmd, "-t nat -A NAT_PRIV_FILE -d %s -p tcp --dport %s -j DNAT --to '%s':'%s'",
                         false, m_natip, m_natport, m_outsvrip, m_outsvrport);
    }
    sem_wait(g_iptables_lock);
    system(chcmd);
    sem_post(g_iptables_lock);
    PRINT_INFO_HEAD
    print_info("pvt filesync set out iptables[%s]", chcmd);
}

/**
 * [PVT_FILESYNC::setNatIP 设置跳转IP]
 * @param ip4 [IPV4地址]
 * @param ip6 [IPV6地址]
 */
void PVT_FILESYNC::setNatIP(const char *ip4, const char *ip6)
{
    if (is_ip6addr(m_outsvrip)) {
        strcpy(m_natip, ip6);
    } else {
        strcpy(m_natip, ip4);
    }
}

/**
 * [PVT_FILESYNC::writeConf 写配置文件]
 * @param  fileop [文件操作对象]
 * @return  [成功返回true]
 */
bool PVT_FILESYNC::writeConf(CFILEOP &fileop)
{
    char dirid[32] = {0};
    sprintf(dirid, "DIR%d", m_taskid);
    if (m_secway.getarea() == 0) {
        fileop.WriteCfgFile(dirid, "TOIP2", m_natip);
        fileop.WriteCfgFile(dirid, "TOIP", m_insvrip);
        fileop.WriteCfgFile(dirid, "PORT2", m_natport);
        fileop.WriteCfgFile(dirid, "PORT", m_insvrport);
    } else {
        fileop.WriteCfgFile(dirid, "TOIP2", m_insvrip);
        fileop.WriteCfgFile(dirid, "TOIP", m_natip);
        fileop.WriteCfgFile(dirid, "PORT2", m_insvrport);
        fileop.WriteCfgFile(dirid, "PORT", m_natport);
    }
    return true;
}

/**
 * [PvtFileSyncDeamon 私有协议文件同步程序线程函数]
 * @param  arg [未使用]
 * @return     [description]
 */
void *PvtFileSyncDeamon(void *arg)
{
    pthread_setself("pvtfilesync");

    char chcmd[CMD_BUF_LEN] = {0};
    CCommon common;

_LOOP:
    if (g_pvtf_num > 0) {
        CLOGMANAGE mlog;
        if (mlog.Init() == E_OK) {
            mlog.WriteSysLog(LOG_TYPE_FILE_SYNC, D_SUCCESS, LOG_CONTENT_RUN_PVT_FILE_SYNC);
            mlog.DisConnect();
        } else {
            PRINT_ERR_HEAD
            print_err("pvt filesync mysql init fail");
        }
        sprintf(chcmd, "%s %s %d %s >/dev/null 2>&1&", PRIVFSYNC, PRIV_FILESYNC_CONF, g_iflog ? 1 : 0,
                g_ckkey ? KEY_CONF : "NULL");
        system(chcmd);
        PRINT_INFO_HEAD
        print_info("chcmd[%s]", chcmd);
        sleep(3);
    }

    while (1) {
        sleep(1);
        if (g_pvtf_change) {
            system("killall fileclient >/dev/null 2>&1");
            g_pvtf_change = false;
            PRINT_INFO_HEAD
            print_info("pvt fileclient change.tasknum[%d]", g_pvtf_num);
            sleep(1);
            goto _LOOP;
        }

        if ((g_pvtf_num > 0) && (!common.ProcessRuning("fileclient"))) {
            PRINT_ERR_HEAD
            print_err("fileclient restart");
            goto _LOOP;
        }
    }
    return NULL;
}

/**
 * [PvtFileSyncProcess 启动私有协议文件同步程序]
 * @return  [成功返回0]
 */
int PvtFileSyncProcess(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, PvtFileSyncDeamon, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create pvt filesync thread error");
        return -1;
    }

    return 0;
}

PVT_FILESYNC_MG::PVT_FILESYNC_MG(void)
{
    m_task_num = 0;
    BZERO(m_task);
    BZERO(m_natip4);
    BZERO(m_natip6);
}

PVT_FILESYNC_MG::~PVT_FILESYNC_MG(void)
{
    clear();
}

/**
 * [PVT_FILESYNC_MG::clear 清空任务信息]
 */
void PVT_FILESYNC_MG::clear(void)
{
    DELETE_N(m_task, m_task_num);
    m_task_num = 0;
    g_cardmg.clear(FILESYNC_PRIV_MOD);
}

/**
 * [PVT_FILESYNC_MG::setNatIP 设置跳转IP 保存到管理类成员变量中]
 * @param ip4 [IPV4地址]
 * @param ip6 [IPV6地址]
 */
void PVT_FILESYNC_MG::setNatIP(const char *ip4, const char *ip6)
{
    if ((ip4 == NULL) || (ip6 == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null[%s][%s]", ip4, ip6);
        return;
    }
    strcpy(m_natip4, ip4);
    strcpy(m_natip6, ip6);
    PRINT_DBG_HEAD
    print_dbg("natip4[%s] natip6[%s]", m_natip4, m_natip4);
}

/**
 * [PVT_FILESYNC_MG::setNatIP 设置每一个任务的跳转IP]
 */
void PVT_FILESYNC_MG::setNatIP(void)
{
    for (int i = 0; i < m_task_num; ++i) {
        m_task[i]->setNatIP(m_natip4, m_natip6);
    }
}

/**
 * [PVT_FILESYNC_MG::loadConf 读取配置信息]
 * @return  [成功返回0]
 */
int PVT_FILESYNC_MG::loadConf(void)
{
    PRINT_DBG_HEAD
    print_dbg("import pvt filesync begin[%s]", PRIV_FILESYNC_CONF);

    int ret = -1;
    int dirnum = 0;
    char model[32] = {0};

    CFILEOP fileop;
    if (fileop.OpenFile(PRIV_FILESYNC_CONF, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", PRIV_FILESYNC_CONF);
        goto _out;
    }

    READ_INT(fileop, "SYS", "DIRNUM", dirnum, true, _out);

    if (dirnum > 0) {
        READ_STRING(fileop, "SYS", "MODEL", model, true, _out);
        if (strcmp(model, "TRAN") != 0) {
            PRINT_ERR_HEAD
            print_err("model[%s] should be TRAN", model);
            goto _out;
        }

        for (int i = 0; i < dirnum; i++) {
            PVT_FILESYNC *pvtfsync = addTask();
            if (pvtfsync == NULL) {
                break;
            } else {
                if (pvtfsync->loadConf()) {
                    g_cardmg.add(FILESYNC_PRIV_MOD,
                                 pvtfsync->getSecway().getindev(),
                                 pvtfsync->getSecway().getoutdev());
                } else {
                    goto _out;
                }
            }
        }
    }

    ret = 0;
_out:
    fileop.CloseFile();
    PRINT_DBG_HEAD
    print_dbg("import pvt filesync %s , dirnum[%d]", ret == 0 ? "ok" : "err", dirnum);
    return ret;
}

/**
 * [PVT_FILESYNC_MG::addTask 添加一个任务]
 * @return  [任务指针 失败返回空指针]
 */
PVT_FILESYNC *PVT_FILESYNC_MG::addTask(void)
{
    if (m_task_num == ARRAY_SIZE(m_task)) {
        PRINT_ERR_HEAD
        print_err("reach max support num[%d]", (int)ARRAY_SIZE(m_task));
        return NULL;
    }
    m_task[m_task_num] = new PVT_FILESYNC(m_task_num);
    if (m_task[m_task_num] == NULL) {
        PRINT_ERR_HEAD
        print_err("new PVT_FILESYNC fail. current tasknum[%d]", m_task_num);
        return NULL;
    }
    m_task_num++;
    return m_task[m_task_num - 1];
}

/**
 * [PVT_FILESYNC_MG::writeConf 每个任务回写自己的IP到配置文件]
 * @return  [成功返回true]
 */
bool PVT_FILESYNC_MG::writeConf(void)
{
    PRINT_INFO_HEAD
    print_info("pvtfilesync write conf begin. tasknum[%d]", m_task_num);

    CFILEOP fileop;
    bool ret = false;

    if (fileop.OpenFile(PRIV_FILESYNC_CONF, "r+") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("open file[%s] error", PRIV_FILESYNC_CONF);
        goto _out;
    }

    for (int i = 0; i < m_task_num; ++i) {
        ret = m_task[i]->writeConf(fileop);
        if (!ret) {
            PRINT_ERR_HEAD
            print_err("write conf fail. taskid[%d]", i);
            goto _out;
        }
    }

    PRINT_INFO_HEAD
    print_info("pvtfilesync write conf ok. tasknum[%d]", m_task_num);
    fileop.CloseFile();
    return true;
_out:
    PRINT_ERR_HEAD
    print_err("pvtfilesync write conf fail");
    fileop.CloseFile();
    return false;
}

/**
 * [PVT_FILESYNC_MG::setOutIptables 设置外网侧NAT跳转iptables]
 */
void PVT_FILESYNC_MG::setOutIptables(void)
{
    for (int i = 0; i < m_task_num; ++i) {
        m_task[i]->setOutIptables();
    }
}

/**
 * [PVT_FILESYNC_MG::clearOutIptables 清空外网侧 本模块相关的NAT跳转iptables]
 */
void PVT_FILESYNC_MG::clearOutIptables(void)
{
    sem_wait(g_iptables_lock);
    system("iptables -t nat -F NAT_PRIV_FILE");
    system("ip6tables -t nat -F NAT_PRIV_FILE");
    sem_post(g_iptables_lock);
    PRINT_INFO_HEAD
    print_info("clear out nat iptables");
}

/**
 * [PVT_FILESYNC_MG::taskNum 查询当前任务个数]
 * @return  [当前任务个数]
 */
int PVT_FILESYNC_MG::taskNum(void)
{
    return m_task_num;
}
