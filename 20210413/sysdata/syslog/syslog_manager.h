/*******************************************************************************************
*文件:  syslog_manager.h
*描述:  syslog发送管理者
*作者:  王君雷
*日期:  2019-06-29
*修改:
*******************************************************************************************/
#ifndef __SYSLOG_MANAGER_H__
#define __SYSLOG_MANAGER_H__

#include "quote_global.h"
#include "simple.h"
#include "debugout.h"

#include <list>
using namespace std;

//所有需要发送SYSLOG的表需要继承该基类
class LOGOBJ
{
public:
    LOGOBJ();
    virtual ~LOGOBJ();

    bool Query(void);
    bool GetNextRow(void);
    bool DoWithOneRecord(void);
    virtual bool MakeLogInfo(void) = 0;
    virtual bool MakeUpdateSql(void) = 0;
protected:
    bool SetQuery(const char *querystr);

private:
    bool Init(void);
    bool SendLog(void);
    bool UpdateLog(void);

protected:
    char m_condquery[200];//条件查询语句
    char m_loginfo[1500]; //存放将发生出去的syslog信息
    char m_updatestr[200];//存放更新记录时用的sql语句
    MYSQL m_query;
    MYSQL_ROW m_row;
    MYSQL_RES *m_res;
    bool m_b_initok;
};

class SYSLOG_MAN
{
private:
    list<LOGOBJ *> m_list;

public:
    SYSLOG_MAN();
    virtual ~SYSLOG_MAN();
    void Add(LOGOBJ *plog);
    void Remove(LOGOBJ *plog);
    void Travel(void);
};

int StartSysLog(int iPort, char *chServerIp);

#endif
