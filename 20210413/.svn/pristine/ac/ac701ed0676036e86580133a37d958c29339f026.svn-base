/*******************************************************************************************
*文件:  FCLogContainer.h
*描述:  日志容器类
*作者:  王君雷
*日期:  2016-08-05
*描述:  把需要记录的日志放入容器内，让其他线程去写数据库，实现并行处理
*修改:
*       访问日志添加mac字段                                 ------> 2020-01-16 wjl
*******************************************************************************************/
#ifndef __FC_LOG_CONTAINER_H__
#define __FC_LOG_CONTAINER_H__

#include "FCLogManage.h"
#include <semaphore.h>
#include <queue>
using namespace std;

//日志类别
#define UNKNOWN_LOG_TYPE   -1
#define CALLLOG_TYPE      150
#define FILTERLOG_TYPE    160

#define LOG_CONTAINER_SEM "/logcontainer"
#define MAX_LOG_STORED    5000 //容器中支持存储的最大数目 超过该值会丢弃日志

//日志参数基类
class LogParaBase
{
public:
    LogParaBase(void);
    virtual ~LogParaBase(void);
    virtual bool WriteToDB(CLOGMANAGE &logman) = 0;
protected:
    int m_log_type;
};

//访问日志参数
class CallLogPara : public LogParaBase
{
public:
    CallLogPara(void);
    virtual ~CallLogPara(void);

    bool SetValues(const char *authname, const char *sip, const char *dip, const char *sport,
                   const char *dport, const char *smac, const char *dmac, const char *service, const char *cmd, const char *para,
                   const char *chresult, const char *remark);
    bool WriteToDB(CLOGMANAGE &logman);
private:
    char m_authname[AUTH_NAME_LEN];
    char m_sip[IP_STR_LEN];
    char m_dip[IP_STR_LEN];
    char m_sport[PORT_STR_LEN];
    char m_dport[PORT_STR_LEN];
    char m_srcmac[MAC_STR_LEN];
    char m_dstmac[MAC_STR_LEN];
    char m_asservice[APP_MODEL_LEN];
    char m_cmd[MAX_CMD_NAME_LEN];
    char m_parameter[MAX_PARA_NAME_LEN];
    char m_chresult[16];
    char m_remark[128];
};

//过滤日志参数
class FilterLogPara : public LogParaBase
{
public:
    FilterLogPara(void);
    virtual ~FilterLogPara(void);

    bool SetValues(const char *authname, const char *fname, const char *remark,
                   const char *service, const char *srcip, const char *dstip, const char *srcport, const char *dstport);
    bool WriteToDB(CLOGMANAGE &logman);

private:
    char m_authname[AUTH_NAME_LEN];
    char m_fname[64];
    char m_remark[800];
    char m_service[APP_MODEL_LEN];
    char m_srcip[IP_STR_LEN];
    char m_dstip[IP_STR_LEN];
    char m_srcport[PORT_STR_LEN];
    char m_dstport[PORT_STR_LEN];
};

//日志容器类  单例模式
class LogContainer
{
public:
    static LogContainer &GetInstance(void);
    virtual ~LogContainer(void);

    LogParaBase *GetPara(void);
    void PutPara(LogParaBase *para);

private:
    LogContainer(void);
    LogContainer(const LogContainer &other);
    LogContainer &operator=(const LogContainer &other);
    void init_lock(void);

    queue<LogParaBase *> m_log_queue;
    sem_t *m_lock;
};

int StartLogThread(void);

#endif
