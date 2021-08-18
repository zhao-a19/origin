/*******************************************************************************************
*文件:  FCFileSync.h
*描述:  文件同步任务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       函数和变量统一风格；无参函数加void；使用zlog                    ------> 2018-09-05
*       支持IPV6                                                        ------> 2019-06-08
*       文件交换模块支持双机热备                                        ------> 2019-12-19 wjl
*       文件交换支持指定端口                                            ------> 2020-08-25
*       文件交换支持分模块生效                                          ------> 2020-11-10
*       所有任务总共只写一次配置文件                                     ------> 2021-01-11
*******************************************************************************************/
#ifndef __FC_FILESYNC_H__
#define __FC_FILESYNC_H__

#include <iostream>
#include <vector>
using namespace std;

#include "const.h"
#include "define.h"
#include "fileoperator.h"

#define MOUNT_PATH_LEN 256
#define FILE_SYS_TYPE_LEN 64

class CFileSyncTask
{
public:
    CFileSyncTask(int taskid);
    virtual ~CFileSyncTask(void);

    void setOutPath(const char *ch);
    void setOutBakFlag(const char *ch);
    void setOutBakPath(const char *ch);
    void setInPath(const char *ch);
    void setInBakFlag(const char *ch);
    void setInBakPath(const char *ch);

    void setOutPort(const char *ch);
    void setOutFileSys(const char *ch);
    void setOutBakPort(const char *ch);
    void setOutBakFileSys(const char *ch);

    bool getOutBakFlag(void);
    bool getInBakFlag(void);
    const char *getOutIP(void);
    const char *getOutBakIP(void);
    const char *getInIP(void);
    const char *getInBakIP(void);

    const char *getOutPort(void);
    const char *getOutBakPort(void);
    const char *getOutFileSys(void);
    const char *getOutBakFileSys(void);

    void setNatPath(const char *natip);
    void setNatBakPath(const char *natip);
    int writeConf(CFILEOP &fileop);
    void analysisIP(const char *ch, char *ipbuff, int bufflen);
private:

private:
    int m_taskid;
    char m_outpath[MOUNT_PATH_LEN];
    char m_outip[IP_STR_LEN];
    bool m_outbakflag;
    char m_outbakpath[MOUNT_PATH_LEN];
    char m_outbakip[IP_STR_LEN];

    char m_outmappath[MOUNT_PATH_LEN];
    char m_outbakmappath[MOUNT_PATH_LEN];

    char m_inpath[MOUNT_PATH_LEN];
    char m_inip[IP_STR_LEN];
    bool m_inbakflag;
    char m_inbakpath[MOUNT_PATH_LEN];
    char m_inbakip[IP_STR_LEN];

    char m_outport[PORT_STR_LEN];
    char m_outbakport[PORT_STR_LEN];
    char m_outfilesys[FILE_SYS_TYPE_LEN];
    char m_outbakfilesys[FILE_SYS_TYPE_LEN];
};

int StartMsync(void);

class FILESYNC_MG
{
public:
    FILESYNC_MG(void);
    virtual ~FILESYNC_MG(void);
    int loadConf(void);
    void clear(void);
    void setOffset(int offsetcnt);
    void makeNatIP(void);
    void setNatIP(void);
    void writeConf(void);
    void configNatIP(void);
    void setOutIptables(void);
    void clearOutIptables(void);
    int outFtpPortNum(void);
    int taskNum(void);

private:
    CFileSyncTask *addTask(void);
    void statistics(void);
    void push(vector<string> &vec, const char *str);
    int findIP(vector<string> &vec, const char *ip);

public:
    vector<string> m_indstip; //所有任务中 内网侧服务器IP
    vector<string> m_outdstip;//所有任务中 外网侧服务器IP
    vector<string> m_outnatip;//NAT跳转IP
    vector<string> m_ftpport; //所有任务中 外网侧FTP服务器端口号汇总

private:
    int m_offset;
    int m_task_num;
    CFileSyncTask *m_task[C_FILESYNC_MAXNUM];
};

extern int g_fsync_num;
extern bool g_fsync_change;

#endif
