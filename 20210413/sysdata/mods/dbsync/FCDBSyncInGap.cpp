/*******************************************************************************************
*文件:  FCDBSyncInGap.cpp
*描述:  数据库同步功能集成到网闸内部，不再需要使用客户端软件
*作者:  王君雷
*日期:  2016-05-27
*修改:
*           线程ID使用pthread_t类型                                     ------> 2018-08-07
*           重新整理程序，不再使用map结构                                ------> 2019-06-20
*           引入zlog日志,添加函数头（宋宇）                              ------> 2019-06-24
*           数据库同步模块支持双机热备                                   ------> 2019-12-19 wjl
*******************************************************************************************/
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

#include "FCDBSyncInGap.h"
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"
#include "stringex.h"

/**
 * 构造函数
 * taskid                       ----> 数据库同步任务id
 */
CDBSyncTask::CDBSyncTask(int taskid)
{
    m_taskid = taskid;
    m_rulearea = 0;
    BZERO(m_rulename);
    BZERO(m_old_sser);
    BZERO(m_old_tser);
    BZERO(m_old_sport);
    BZERO(m_old_tport);
    BZERO(m_natip);
    BZERO(m_natport);

    BZERO(m_outsvrip);
    BZERO(m_outsvrport);
    BZERO(m_insvrip);
    BZERO(m_insvrport);
}

CDBSyncTask::~CDBSyncTask(void)
{
}

/**
 * [CDBSyncTask::setRuleName 设置规则名到成员变量中]
 * @param  chname [规则名]
 * @return        [0:成功 -1:失败]
 */
int CDBSyncTask::setRuleName(const char *chname)
{
    if (chname == NULL) {
        PRINT_ERR_HEAD;
        print_err("setRuleName para null!");
        return -1;
    }

    if (strlen(chname) >= sizeof(m_rulename)) {
        PRINT_ERR_HEAD;
        print_err("setRuleName para too long[%s].max suport[%d]", chname, (int)sizeof(m_rulename) - 1);
        return -1;
    }

    strcpy(m_rulename, chname);
    return 0;
}

/**
 * [CDBSyncTask::setRuleArea 设置同步方向到成员变量中]
 * @param  area [同步方向]
 * @return      [0:成功]
 */
int CDBSyncTask::setRuleArea(int area)
{
    m_rulearea = area;
    return 0;
}

/**
 * [CDBSyncTask::setOldSrcServer 读取源端服务器IP]
 * @param  chserver [源端数据库IP]
 * @return          [0:成功 -1:失败]
 */
int CDBSyncTask::setOldSrcServer(const char *chserver)
{
    if (chserver == NULL) {
        PRINT_ERR_HEAD;
        print_err("setOldSrcServer para null!");
        return -1;
    }

    if (strlen(chserver) >= sizeof(m_old_sser)) {
        PRINT_ERR_HEAD;
        print_err("setOldSrcServer para too long[%s].max suport[%d]", chserver, (int)sizeof(m_old_sser) - 1);
        return -1;
    }

    strcpy(m_old_sser, chserver);
    return 0;
}

/**
 * [CDBSyncTask::setOldDstServer 读取目的端服务器IP]
 * @param  chserver [目的端服务器IP]
 * @return          [0:成功 -1:失败]
 */
int CDBSyncTask::setOldDstServer(const char *chserver)
{
    if (chserver == NULL) {
        PRINT_ERR_HEAD;
        print_err("setOldDstServer para null!");
        return -1;
    }

    if (strlen(chserver) >= sizeof(m_old_tser)) {
        PRINT_ERR_HEAD;
        print_err("setOldDstServer para too long[%s].max suport[%d]", chserver, (int)sizeof(m_old_tser) - 1);
        return -1;
    }

    strcpy(m_old_tser, chserver);
    return 0;
}

/**
 * [CDBSyncTask::setOldSrcPort 读取源服务器端口]
 * @param  chport [源服务器端口]
 * @return        [0:成功 -1:失败]
 */
int CDBSyncTask::setOldSrcPort(const char *chport)
{
    if (chport == NULL) {
        PRINT_ERR_HEAD;
        print_err("setOldSrcPort para null!");
        return -1;
    }

    if (strlen(chport) >= sizeof(m_old_sport)) {
        PRINT_ERR_HEAD;
        print_err("setOldSrcPort para too long[%s].max suport[%d]", chport, (int)sizeof(m_old_sport) - 1);
        return -1;
    }

    strcpy(m_old_sport, chport);
    return 0;
}

/**
 * [CDBSyncTask::setOldDstPort 读取目的服务器端口]
 * @param  chport [目的服务器端口]
 * @return        [0:成功 -1:失败]
 */
int CDBSyncTask::setOldDstPort(const char *chport)
{
    if (chport == NULL) {
        PRINT_ERR_HEAD;
        print_err("setOldDstPort para null!");
        return -1;
    }

    if (strlen(chport) >= sizeof(m_old_tport)) {
        PRINT_ERR_HEAD;
        print_err("setOldDstPort para too long[%s].max suport[%d]", chport, (int)sizeof(m_old_tport) - 1);
        return -1;
    }

    strcpy(m_old_tport, chport);
    return 0;
}

/**
 * [CDBSyncTask::getRuleArea 获取同步方向]
 * @return  [description]
 */
int CDBSyncTask::getRuleArea(void)
{
    return m_rulearea;
}

/**
 * [CDBSyncTask::getRuleName 获取规则名]
 * @return  [规则名]
 */
const char *CDBSyncTask::getRuleName(void)
{
    return m_rulename;
}

/**
 * [getInSvr 获取内网服务器IP]
 * @return  [内网服务器IP]
 */
const char *CDBSyncTask::getInSvr(void)
{
    return m_insvrip;
}

/**
 * [getOutSvr 获取外网服务器IP]
 * @return  [外网服务器IP]
 */
const char *CDBSyncTask::getOutSvr(void)
{
    return m_outsvrip;
}

/**
 * [CDBSyncTask::getOldSrcServer 获取源服务器IP]
 * @return  [源服务IP]
 */
const char *CDBSyncTask::getOldSrcServer(void)
{
    return m_old_sser;
}

/**
 * [CDBSyncTask::getOldDstServer 获取目的服务IP]
 * @return  [目的服务IP]
 */
const char *CDBSyncTask::getOldDstServer(void)
{
    return m_old_tser;
}

/**
 * [CDBSyncTask::setNatInfo 设置内部跳转NAT信息]
 * @param  natip4 [NAT IPv4地址]
 * @param  natip6 [NAT IPv6地址]
 * @return        [true:成功 false:失败]
 */
bool CDBSyncTask::setNatInfo(const char *natip4, const char *natip6)
{
    if ((natip4 == NULL) || (natip6 == NULL)) {
        PRINT_ERR_HEAD;
        print_err("dbsync task set nat info ip error.natip4[%s] natip6[%s]", natip4, natip6);
        return false;
    }

    if (m_rulearea == 0) {
        strcpy(m_outsvrip, m_old_tser);
        strcpy(m_outsvrport, m_old_tport);
        strcpy(m_insvrip, m_old_sser);
        strcpy(m_insvrport, m_old_sport);
    } else {
        strcpy(m_outsvrip, m_old_sser);
        strcpy(m_outsvrport, m_old_sport);
        strcpy(m_insvrip, m_old_tser);
        strcpy(m_insvrport, m_old_tport);
    }

    if (is_ip6addr(m_outsvrip)) {
        strncpy(m_natip, natip6, sizeof(m_natip) - 1);
    } else {
        strncpy(m_natip, natip4, sizeof(m_natip) - 1);
    }
    snprintf(m_natport, sizeof(m_natport), "%d", (DBSYNC_NAT_START_PORT + m_taskid) % 65536);
    PRINT_DBG_HEAD;
    print_dbg("dbsync set nat info ok[%s][%s]", m_natip, m_natport);
    return true;
}

/**
 * [CDBSyncTask::writeConf 回写配置文件(映射IP和端口)]
 * @return  [true:成功 false:失败]
 */
bool CDBSyncTask::writeConf(void)
{
    //写配置文件
    CFILEOP myfileop;
    if (myfileop.OpenFile(DBSYNC_CONF, "r+") != E_FILE_OK) {
        PRINT_ERR_HEAD;
        print_err("Open File Err[%s]", DBSYNC_CONF);
        return false;
    }

    char item_tmp[512] = {0};
    if (m_rulearea == 0) {
        sprintf(item_tmp, "%s_tDBMS", m_rulename);
    } else {
        sprintf(item_tmp, "%s_sDBMS", m_rulename);
    }

    myfileop.WriteCfgFile(item_tmp, "Server", m_natip);
    myfileop.WriteCfgFile(item_tmp, "Port", m_natport);
    myfileop.CloseFile();
    return true;
}

/**
 * [CDBSyncTask::setOutIptables 设置外网侧iptables规则]
 */
void CDBSyncTask::setOutIptables(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (is_ip6addr(m_outsvrip)) {
        MAKE_TABLESTRING(chcmd, "-t nat -I PREROUTING -d %s -p tcp --dport %s -j DNAT --to ['%s']:'%s'",
                         true, m_natip, m_natport, m_outsvrip, m_outsvrport);
    } else {
        MAKE_TABLESTRING(chcmd, "-t nat -I PREROUTING -d %s -p tcp --dport %s -j DNAT --to '%s':'%s'",
                         false, m_natip, m_natport, m_outsvrip, m_outsvrport);
    }
    system_safe(chcmd);
    PRINT_DBG_HEAD;
    print_dbg("dbsync set out iptables[%s]", chcmd);
}

/**
 * [dbsync_deamon 启动数据库同步脚本（阻塞运行）]
 * @param  arg [暂时无用]
 * @return     [无]
 */
void *dbsync_deamon(void *arg)
{
    pthread_setself("dbsync_deamon");

    while (1) {
        system("/initrd/abin/dbsync/run.sh >/dev/null 2>&1");
        PRINT_ERR_HEAD
        print_err("dbsync restart!");
        sleep(5);
    }

    return NULL;
}

/**
 * [StartDBsync 启动数据库同步线程]
 * @return  [0:成功 -1:创建线程失败 -2:分离线程失败]
 */
int StartDBsync(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, dbsync_deamon, NULL) != 0) {
        return -1;
    }
    return 0;
}
