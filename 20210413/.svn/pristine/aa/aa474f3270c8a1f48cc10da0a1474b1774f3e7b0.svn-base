/*******************************************************************************************
*文件:  pvt_filesync.h
*描述:  私有协议 文件同步任务类
*作者:  王君雷
*日期:  2018-08-30
*修改:
*       安全通道使用SEC_WAY类                                      ------> 2019-01-02
*       任务最大支持数由10改为100                                  ------> 2019-07-20
*       所有任务总共只写一次配置文件                                    ------> 2021-01-11
*******************************************************************************************/
#ifndef __PVT_FILESYNC_H__
#define __PVT_FILESYNC_H__
#include "define.h"
#include "secway.h"
#include "fileoperator.h"

#define PVT_FILESYNC_TASK_NUM 100 //私有协议文件同步任务最大支持数
#define PVT_NAT_START_PORT 40000 //私有协议文件同步内部NAT跳转使用的首个端口 每多一个任务就加一

class PVT_FILESYNC
{
public:
    PVT_FILESYNC(int task_id);
    virtual ~PVT_FILESYNC(void);

    SEC_WAY &getSecway(void);
    bool loadConf(void);
    void setNatIP(const char *ip4, const char *ip6);
    void setOutIptables(void);
    bool writeConf(CFILEOP &fileop);

private:
    void showConf(void);

private:
    int m_taskid;
    SEC_WAY m_secway;
    char m_insvrip[IP_STR_LEN];
    char m_outsvrip[IP_STR_LEN];
    char m_insvrport[PORT_STR_LEN];
    char m_outsvrport[PORT_STR_LEN];

    char m_natip[IP_STR_LEN];
    char m_natport[PORT_STR_LEN];
    //char m_confpath[MAX_FILE_PATH_LEN];
};

class PVT_FILESYNC_MG
{
public:
    PVT_FILESYNC_MG(void);
    virtual ~PVT_FILESYNC_MG(void);
    void clear(void);
    int loadConf(void);
    void setNatIP(const char *ip4, const char *ip6);
    void setNatIP(void);
    bool writeConf(void);
    void setOutIptables(void);
    void clearOutIptables(void);
    int taskNum(void);

private:
    PVT_FILESYNC *addTask(void);

private:
    char m_natip4[IP_STR_LEN];
    char m_natip6[IP_STR_LEN];
    int m_task_num;
    PVT_FILESYNC *m_task[PVT_FILESYNC_TASK_NUM];
};

int PvtFileSyncProcess(void);
extern int g_pvtf_num;
extern bool g_pvtf_change;

#endif
