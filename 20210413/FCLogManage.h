/*******************************************************************************************
*文件:  FCLogManage.h
*描述:  数据库操作类
*作者:  王君雷
*日期:  2016-03
*修改:
*       日志类型宏移动到define.h中                          ------> 2018-01-22 王君雷
*       写日志的接口，添加参数chisout，可以选择填写日志区域 ------> 2018-07-19
*       去除在本文件中使用全局对象g_log                     ------> 2018-08-31
*       添加写文件交换日志的接口函数                        ------> 2018-09-03
*       吞吐量使用unsigned long long int类型表示            ------> 2018-09-27
*       添加DBGlobalPrepare静态成员函数                     ------> 2019-08-27
*       添加函数SlogReload，可以重新读取syslog开关          ------> 2020-07-06
*******************************************************************************************/
#ifndef __FC_LOGMANAGE_H__
#define __FC_LOGMANAGE_H__

#include <string.h>
#include "define.h"
#include "const.h"
#include "mysql.h"
#include "slog.h"

//日志记录结构体
class CLOGMANAGE
{
public:
    CLOGMANAGE(void);
    virtual ~CLOGMANAGE(void);
    //初始化
    int Init(bool brec = true, const char *chremote = DEFAULT_HOST);
    //写系统日志
    int WriteSysLog(const char *logtype, const char *result, const char *remark,
                    const char *chisout = NULL);
    //写内容过滤日志
    int WriteFilterLog(const char *user, const char *fname, const char *remark, const char *service,
                       const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                       const char *chisout = NULL);
    //写LINK日志
    int WriteLinkLog(const char *sip, const char *dip, const char *sport,
                     const char *dport, const char *remark, const char *srcmac, const char *dstmac, const char *chisout = NULL);

    int WriteCallLog(const char *user, const char *srcip, const char *dstip, const char *srcport,
                     const char *dstport, const char *srcmac, const char *dstmac,
                     const char *service, const char *cmd, const char *param,
                     const char *result, const char *remark, const char *chisout = NULL);

    int WriteSysStatusLog(int linknum, const char *cpuinfo, const char *diskinfo,
                          const char *meminfo, const char *netinfo, unsigned long long int netflow,
                          char devstatus, const char *descr, const char *chisout = NULL);
    int WriteFileSyncLog(int taskid, const char *taskname, const char *srcip, const char *dstip, const char *spath,
                         const char *dpath, const char *fname, const char *result, const char *remark, bool outtoin);
    int ConnectDB(const char *chremote = DEFAULT_HOST);
    int ReConnectDB(const char *chremote = DEFAULT_HOST);
    void DisConnect(void);
    void SetRecordFlag(bool brec);
    int  WriteToDB(const char *chsql);
    int  WriteToDB(const char *tbname, const char *chsql);
    static bool DBGlobalPrepare(void);
    bool ParseTblName(const char *chsql, char *name, int namelen);
    void SlogReload(void);

private:
    void SetTableName(const char *tbname);
    int ReleaseTableSpace(const char *tbname);
    bool SetIO(const char *ibuf);
    void GetSysTime(char *Result);
    void RepairRequst(void);

private:
    MYSQL m_csql;
    bool m_record;
    bool m_initok;
    bool m_tblerr;
    char m_tblname[40];

    SLOG_CLI_OPER slog;
};

#endif
