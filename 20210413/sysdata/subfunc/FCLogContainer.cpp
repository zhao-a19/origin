/*******************************************************************************************
*文件:  FCLogContainer.cpp
*描述:  日志容器类
*作者:  王君雷
*日期:  2016-08-05
*描述:  把需要记录的日志放入容器内，让其他线程去记录，实现并行处理
*修改:
*        线程ID使用pthread_t类型                                    ------> 2018-08-07
*        使用zlog，完善注释                                         ------> 2019-01-22
*        访问日志添加mac字段                                        ------> 2020-01-16 wjl
*******************************************************************************************/
#include "FCLogContainer.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include "debugout.h"
#include "gap_config.h"
#include "fileoperator.h"

LogParaBase::LogParaBase(void)
{
    m_log_type = UNKNOWN_LOG_TYPE;
}

LogParaBase::~LogParaBase(void)
{
}

CallLogPara::CallLogPara(void)
{
    BZERO(m_authname);
    BZERO(m_sip);
    BZERO(m_dip);
    BZERO(m_sport);
    BZERO(m_dport);
    BZERO(m_srcmac);
    BZERO(m_dstmac);
    BZERO(m_asservice);
    BZERO(m_cmd);
    BZERO(m_parameter);
    BZERO(m_chresult);
    BZERO(m_remark);
    m_log_type = CALLLOG_TYPE;
}

CallLogPara::~CallLogPara(void)
{
}

/**
 * [CallLogPara::SetValues 为成员变量赋值]
 * @param  authname [用户名]
 * @param  sip      [源IP]
 * @param  dip      [目的IP]
 * @param  sport    [源端口]
 * @param  dport    [目的端口]
 * @param  smac     [源MAC]
 * @param  dmac     [目的MAC]
 * @param  service  [服务]
 * @param  cmd      [命令]
 * @param  para     [参数]
 * @param  chresult [结果]
 * @param  remark   [备注]
 * @return          [成功返回true]
 */
bool CallLogPara::SetValues(const char *authname, const char *sip, const char *dip, const char *sport,
                            const char *dport, const char *smac, const char *dmac, const char *service,
                            const char *cmd, const char *para, const char *chresult, const char *remark)
{
    if ((authname == NULL)
        || (sip == NULL)
        || (dip == NULL)
        || (sport == NULL)
        || (dport == NULL)
        || (service == NULL)
        || (cmd == NULL)
        || (para == NULL)
        || (chresult == NULL)
        || (remark == NULL)
        || (smac == NULL)
        || (dmac == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while set values in calllog para. authname[%s],sip[%s],dip[%s],sport[%s],dport[%s]",
                  authname, sip, dip, sport, dport);
        return false;
    }

    strncpy(m_authname, authname, sizeof(m_authname) - 1);
    strncpy(m_sip, sip, sizeof(m_sip) - 1);
    strncpy(m_dip, dip, sizeof(m_dip) - 1);
    strncpy(m_sport, sport, sizeof(m_sport) - 1);
    strncpy(m_dport, dport, sizeof(m_dport) - 1);
    strncpy(m_asservice, service, sizeof(m_asservice) - 1);
    strncpy(m_cmd, cmd, sizeof(m_cmd) - 1);
    strncpy(m_parameter, para, sizeof(m_parameter) - 1);
    strncpy(m_chresult, chresult, sizeof(m_chresult) - 1);
    strncpy(m_remark, remark, sizeof(m_remark) - 1);
    strncpy(m_srcmac, smac, sizeof(m_srcmac) - 1);
    strncpy(m_dstmac, dmac, sizeof(m_dstmac) - 1);
    return true;
}

/**
 * [CallLogPara::WriteToDB 写入数据库]
 * @param  logman [数据库操作对象]
 * @return        [成功返回true]
 */
bool CallLogPara::WriteToDB(CLOGMANAGE &logman)
{
    if (logman.WriteCallLog(m_authname, m_sip, m_dip, m_sport, m_dport, m_srcmac, m_dstmac, m_asservice, m_cmd,
                            m_parameter, m_chresult, m_remark) == E_FALSE) {
        PRINT_ERR_HEAD
        print_err("write call log fail.[%s][%s][%s][%s][%s][%s]", m_sip, m_dip, m_sport, m_dport, m_srcmac, m_dstmac);
        return false;
    } else {
        return true;
    }
}

FilterLogPara::FilterLogPara(void)
{
    BZERO(m_authname);
    BZERO(m_fname);
    BZERO(m_remark);
    BZERO(m_service);
    BZERO(m_srcip);
    BZERO(m_dstip);
    BZERO(m_srcport);
    BZERO(m_dstport);
    m_log_type = FILTERLOG_TYPE;
}

FilterLogPara::~FilterLogPara(void)
{
}

/**
 * [FilterLogPara::SetValues 为成员变量赋值]
 * @param  authname [用户名]
 * @param  fname    [内容]
 * @param  remark   [备注]
 * @param  service  [应用]
 * @param  srcip    [源IP]
 * @param  dstip    [目的IP]
 * @param  srcport  [源端口]
 * @param  dstport  [目的端口]
 * @return          [成功返回true]
 */
bool FilterLogPara::SetValues(const char *authname, const char *fname, const char *remark,
                              const char *service, const char *srcip, const char *dstip, const char *srcport, const char *dstport)
{
    if ((authname == NULL)
        || (fname == NULL)
        || (remark == NULL)
        || (service == NULL)
        || (srcip == NULL)
        || (dstip == NULL)
        || (srcport == NULL)
        || (dstport == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while set values in filterlog para.[%s:%s:%s]", authname, fname, remark);
        return false;
    }

    strncpy(m_authname, authname, sizeof(m_authname) - 1);
    strncpy(m_fname, fname, sizeof(m_fname) - 1);
    strncpy(m_remark, remark, sizeof(m_remark) - 1);
    strncpy(m_service, service, sizeof(m_service) - 1);
    strncpy(m_srcip, srcip, sizeof(m_srcip) - 1);
    strncpy(m_dstip, dstip, sizeof(m_dstip) - 1);
    strncpy(m_srcport, srcport, sizeof(m_srcport) - 1);
    strncpy(m_dstport, dstport, sizeof(m_dstport) - 1);
    return true;
}

/**
 * [FilterLogPara::WriteToDB 写入数据库]
 * @param  logman [数据库操作对象]
 * @return        [成功返回true]
 */
bool FilterLogPara::WriteToDB(CLOGMANAGE &logman)
{
    return (logman.WriteFilterLog(m_authname, m_fname, m_remark,
                                  m_service, m_srcip, m_dstip, m_srcport, m_dstport) != E_FALSE);
}

LogContainer::LogContainer(void)
{
    init_lock();
}

LogContainer::~LogContainer(void)
{
}

/**
 * [LogContainer::init_lock 初始化互斥锁]
 */
void LogContainer::init_lock(void)
{
    sem_unlink(LOG_CONTAINER_SEM);
    m_lock = sem_open(LOG_CONTAINER_SEM, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IRGRP | S_IWUSR | S_IROTH, 1);
    if (m_lock == SEM_FAILED) {
        PRINT_ERR_HEAD
        print_err("init lock fail in log container");
    } else {
        PRINT_INFO_HEAD
        print_info("init lock ok in log container");
    }
}

/**
 * [LogContainer::GetInstance 获取唯一的对象实例的引用]
 * @return  [唯一对象实例的引用]
 */
LogContainer &LogContainer::GetInstance(void)
{
    static LogContainer instance_;
    return instance_;
}

/**
 * [LogContainer::GetPara 从队列中取出一条需要记录日志的字段参数信息]
 * @return  [一条日志的字段参数对象指针]
 */
LogParaBase *LogContainer::GetPara(void)
{
    LogParaBase *p = NULL;

    sem_wait(m_lock);
    if (m_log_queue.empty()) {
    } else {
        p = m_log_queue.front();
        m_log_queue.pop();
    }
    sem_post(m_lock);

    return p;
}

/**
 * [LogContainer::PutPara 向队列中放入一条需要记录日志的字段参数新]
 * @param para [日志字段参数对象指针]
 */
void LogContainer::PutPara(LogParaBase *para)
{
    if (para == NULL) {
        PRINT_ERR_HEAD
        print_err("para null whilie log container put para");
        return;
    }

    sem_wait(m_lock);
    if (m_log_queue.size() >= MAX_LOG_STORED) {
        LogParaBase *ptmp = m_log_queue.front();
        delete ptmp;
        m_log_queue.pop();
    }
    m_log_queue.push(para);
    sem_post(m_lock);

    return;
}

/**
 * [read_recordlog 读取是否需要记录DB日志]
 * @return  [true表示需要记录]
 */
bool read_recordlog(void)
{
    bool flag = true;//默认记录
    int tmpint = 0;
    CFILEOP fop;
    if (fop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("read recordlog open[%s] fail", SYSSET_CONF);
    } else {
        fop.ReadCfgFileInt("SYSTEM", "RecordLog", &tmpint);
        fop.CloseFile();
        flag = (tmpint == 1);
        PRINT_DBG_HEAD
        print_dbg("read recordlog result %d", tmpint);
    }
    return flag;
}

/**
 * [logthread 从容器取出记录 然后插入数据库中 线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *logthread(void *arg)
{
    pthread_setself("logthread");

    LogContainer &s1 = LogContainer::GetInstance();
    LogParaBase *pb = NULL;

    CLOGMANAGE log;
    while (log.Init(read_recordlog()) != E_OK) {
        PRINT_ERR_HEAD
        print_err("logthread log init err,retry.");
        sleep(1);
    }

    while (1) {
        pb = s1.GetPara();
        if (pb == NULL) {
            usleep(10000);
        } else {
            if (!pb->WriteToDB(log)) {
                PRINT_ERR_HEAD
                print_err("write db fail.log connect again");
                log.DisConnect();
                log.Init();
            }
            delete pb;
            pb = NULL;
        }
    }
    return NULL;
}

/**
 * [StartLogThread 启动线程 负责从容器取出记录 然后插入数据库中]
 * @return  [description]
 */
int StartLogThread(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, logthread, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create logthread fail");
        return -1;
    }
    return 0;
}
