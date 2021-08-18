/*******************************************************************************************
*文件:  FCDBSyncInGap.h
*描述:  数据库同步功能集成到网闸内部，不再需要使用客户端软件
*作者:  王君雷
*日期:  2016-05-27
*修改:
*        数据库同步模块支持双机热备                               ------> 2019-12-19 wjl
*******************************************************************************************/
#ifndef __FC_DBSYNCINGAP_H__
#define __FC_DBSYNCINGAP_H__

#include "define.h"

#define DBSYNC_RULE_NAME_LEN 100
#define DBSYNC_NAT_START_PORT 1000

class CDBSyncTask
{
public:
    CDBSyncTask(int taskid);
    virtual ~CDBSyncTask(void);

    int setRuleName(const char *chname);
    int setRuleArea(int area);
    int setOldSrcServer(const char *chserver);
    int setOldDstServer(const char *chserver);
    int setOldSrcPort(const char *chport);
    int setOldDstPort(const char *chport);
    bool setNatInfo(const char *natip4, const char *natip6);
    bool writeConf(void);
    void setOutIptables(void);

    const char *getRuleName(void);
    int getRuleArea(void);
    const char *getOldSrcServer(void);
    const char *getOldDstServer(void);
    const char *getInSvr(void);
    const char *getOutSvr(void);

private:
    int m_taskid;
    int m_rulearea;
    char m_rulename[DBSYNC_RULE_NAME_LEN];
    char m_old_sser[IP_STR_LEN]; //源服务器
    char m_old_tser[IP_STR_LEN]; //目的服务器
    char m_old_sport[PORT_STR_LEN];
    char m_old_tport[PORT_STR_LEN];

    char m_outsvrip[IP_STR_LEN];
    char m_outsvrport[PORT_STR_LEN];
    char m_insvrip[IP_STR_LEN];
    char m_insvrport[PORT_STR_LEN];

    char m_natip[IP_STR_LEN];
    char m_natport[PORT_STR_LEN];
};

int StartDBsync(void);

#endif
