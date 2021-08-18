/*******************************************************************************************
*文件:    sysdb.h
*描述:    数据库访问
*
*作者:    张冬波
*日期:    2015-03-20
*修改:    创建文件                            ------>     2015-03-20
*         添加记录集数量接口                  ------>     2015-07-21
*         添加接口，支持多线程                ------>     2015-10-08
*         添加创建表接口，支持IF NOT EXISTS   ------>     2017-01-18
*         添加错误信息接口                    ------>     2017-09-27
*         修改用户连接接口                    ------>     2017-11-23
*         添加SQLITE支持                      ------>     2018-09-29
*
*******************************************************************************************/
#ifndef __SYSDB_H__
#define __SYSDB_H__

#include "datatype.h"
#ifdef SQLDB_LITE
#include "sqlite3.h"
typedef char **MYSQL_ROW;
#else
#include "mysql.h"
#endif

//#define SYSDB_THREADSAFE 1      //定义支持多线程

#ifdef __cplusplus
extern "C" {
#endif

class CSYSDB
{
public:
    CSYSDB();
    virtual ~CSYSDB();

    bool opendb(void);          //系统默认数据库
#ifdef SQLDB_LITE
    bool opendb(const pchar usrname, const pchar pwd, const pchar dbname, pchar info = NULL);
#else
    bool opendb(const pchar addr, uint16 port, const pchar usrname, const pchar pwd, const pchar dbname, pchar info = NULL);
#endif

    bool closedb(void);
    bool createtable(const pchar table, bool bigtbl, uint32 count, const pchar column, ...);
    bool createtable(const pchar table, bool bigtbl, uint32 count, const pchar column[]);
    bool createtableex(const pchar table, bool bigtbl, uint32 count, const pchar column[]);
    bool deletetable(const pchar table);
    bool cleartable(const pchar table);

    //查询处理, 建议sql关键字全部使用大写字母
    bool querysave(const pchar sql, uint32 &columns, pchar info = NULL);
    const void *queryresult(void);
    bool queryend(void);
    const int32 queryresultcnt(void);

    //只允许进程（主线程）调用
    static bool globalset_threadsafe(uint32 set);
    static const uint32 gSET_START = 0;
    static const uint32 gSET_END = 1;

public:
    bool runsql(const pchar sql, pchar info = NULL);
    pchar sqlescape(const pchar src, pchar dst);
    const pchar geterror(void);

private:
#ifdef SQLDB_LITE
    sqlite3 *sqldb;
    char **resdb;
    int rowdb;
    int rowidx;
    int coldb;
#else
    MYSQL sqldb;
    MYSQL_RES *resdb;
    MYSQL_ROW rowdb;
#endif

    char sqlcmd[2048];          //最近一次SQL语句
    char sqlerrormsg[2048];     //最近一次SQL语句错误

    char dbconnect[3][100];     //数据库连接参数，用户名，密码，库名
    uint32 errcount;            //错误记录
};

#ifdef __cplusplus
}
#endif

#endif

