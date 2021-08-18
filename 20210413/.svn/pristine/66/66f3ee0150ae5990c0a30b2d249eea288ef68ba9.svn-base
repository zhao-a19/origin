/*******************************************************************************************
*文件:    sysdb.cpp
*描述:    数据库访问
*
*作者:    张冬波
*日期:    2015-03-20
*修改:    创建文件                            ------>     2015-03-20
*         添加记录集数量接口                  ------>     2015-07-21
*         多线程调用不符合Mysql规范，注意修改
*                                             ------>     2015-10-08
*         修改bug                             ------>     2015-10-12
*         连接数据库支持默认库                ------>     2015-12-03
*         修改数据库未打开导致的段错误        ------>     2016-03-11
*         添加数据库安全判断                  ------>     2016-03-29
*         连接数据库方式关联my.cnf配置        ------>     2017-03-21
*         添加SQL内容检查                     ------>     2017-06-02
*         尝试修复连接数据库找不到sock定义配置的错误
*         添加修复数据库异表功能
*                                             ------>     2017-06-16
*         处理大表文件                        ------>     2017-10-16
*         添加SQLITE支持                      ------>     2018-09-29
*
*******************************************************************************************/
#include "datatype.h"
#include "stringex.h"
#include "sqldb.h"
#include "sysdb.h"
#include "debugout.h"

#ifdef SQLDB_LITE
#define  _SETINFO_ERR(i) {if((i) != NULL) strcpy((i), sqlite3_errmsg(sqldb));}
#else
#define  _SETINFO_ERR(i) {if((i) != NULL) strcpy((i), mysql_error(&sqldb));}
#endif

/*******************************************************************************************
*功能:    构造
*参数:
*
*注释:
*******************************************************************************************/
CSYSDB::CSYSDB()
{
#ifdef SQLDB_LITE
    sqldb = NULL;
    resdb = NULL;
    rowidx = rowdb = coldb = 0;

    if (!sqlite3_threadsafe()) {
        PRINT_DBG_HEAD;
        print_dbg("SQLITE NOT SAFE");
    }

#else
    memset(&sqldb, 0, sizeof(sqldb));
    resdb = NULL;
    rowdb = NULL;

    if (mysql_thread_safe() != 1) {
        PRINT_DBG_HEAD;
        print_dbg("MYSQL NOT SAFE = %d", mysql_thread_safe());
    }

#endif

    errcount = 0;
    sqlcmd[0] = 0;
    sqlerrormsg[0] = 0;
}

/*******************************************************************************************
*功能:    析构
*参数:
*
*注释:
*******************************************************************************************/
CSYSDB::~CSYSDB()
{
    closedb();
}

/*******************************************************************************************
*功能:    打开数据库
*参数:    addr                  ---->    数据库地址
*         port                  ---->    端口号，0默认
*         usrname               ---->    用户名
*         pwd                   ---->    密码
*         dbname                ---->    数据库名称
*         info                  ---->    错误信息
*         返回值                ---->    true 成功
*
*注释:
*
*******************************************************************************************/
#ifndef SQLDB_LITE
bool CSYSDB::opendb(const pchar addr, uint16 port, const pchar usrname, const pchar pwd, const pchar dbname, pchar info)
{
    //如果dbname为NULL,则连接默认库
    if (is_strempty(addr) || is_strempty(usrname) ||
        is_strempty(pwd)/* || is_strempty(dbname)*/)  return false;

    PRINT_DBG_HEAD;
    print_dbg("Connect DB = %s(%s), %s:%s", addr, dbname, usrname, pwd);

    //记录参数
    strcpy(dbconnect[0], usrname);
    strcpy(dbconnect[1], pwd);
    strcpy(dbconnect[2], dbname);

#ifdef SYSDB_THREADSAFE
    memset(&sqldb, 0, sizeof(MYSQL));
    sqldb.reconnect = 1;

    my_init();
    //char value = 1;
    //mysql_options(&sqldb, MYSQL_OPT_RECONNECT, &value);
    //mysql_options读取my.cnf文件，详情查看API
    mysql_options(&sqldb, MYSQL_READ_DEFAULT_GROUP, "client");
    PRINT_DBG_HEAD;
    print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
    PRINT_DBG_HEAD;
    print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

    if ((mysql_thread_init() == 0) &&
        (mysql_real_connect(&sqldb, addr, usrname, pwd, dbname, port, NULL, 0) != NULL)) {

        PRINT_DBG_HEAD;
        print_dbg("Connect DB = %s(%s), %s:%s success", addr, dbname, usrname, pwd);

        PRINT_DBG_HEAD;
        print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

        return true;
    }
#else
    if (mysql_init(&sqldb) != NULL) {
        //mysql_options读取my.cnf文件，详情查看API
        mysql_options(&sqldb, MYSQL_READ_DEFAULT_GROUP, "client");
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

        if (mysql_real_connect(&sqldb, addr, usrname, pwd, dbname, 0, NULL, 0) != NULL) {

            PRINT_DBG_HEAD;
            print_dbg("Connect DB = %s(%s), %s:%s success", addr, dbname, usrname, pwd);

            PRINT_DBG_HEAD;
            print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
            PRINT_DBG_HEAD;
            print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

            return true;
        }
    }
#endif

    //防止找不到my.cnf的错误处理
#ifdef SYSDB_THREADSAFE
    memset(&sqldb, 0, sizeof(MYSQL));
    sqldb.reconnect = 1;

    my_init();
    //char value = 1;
    //mysql_options(&sqldb, MYSQL_OPT_RECONNECT, &value);
    //mysql_options读取my.cnf文件，详情查看API
    mysql_options(&sqldb, MYSQL_READ_DEFAULT_FILE, "/etc/my.cnf");
    PRINT_DBG_HEAD;
    print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
    PRINT_DBG_HEAD;
    print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

    if ((mysql_thread_init() == 0) &&
        (mysql_real_connect(&sqldb, addr, usrname, pwd, dbname, 0, NULL, 0) != NULL)) {

        PRINT_DBG_HEAD;
        print_dbg("Connect DB = %s(%s), %s:%s success", addr, dbname, usrname, pwd);

        PRINT_DBG_HEAD;
        print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

        return true;
    }
#else
    if (mysql_init(&sqldb) != NULL) {
        //mysql_options读取my.cnf文件，详情查看API
        mysql_options(&sqldb, MYSQL_READ_DEFAULT_FILE, "/etc/my.cnf");
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
        PRINT_DBG_HEAD;
        print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

        if (mysql_real_connect(&sqldb, addr, usrname, pwd, dbname, 0, NULL, 0) != NULL) {

            PRINT_DBG_HEAD;
            print_dbg("Connect DB = %s(%s), %s:%s success", addr, dbname, usrname, pwd);

            PRINT_DBG_HEAD;
            print_dbg("Connect DB options = %s, %s, %s", sqldb.options.my_cnf_file, sqldb.options.my_cnf_group, sqldb.options.unix_socket);
            PRINT_DBG_HEAD;
            print_dbg("Connect DB options charset = %s, %s", sqldb.options.charset_dir, sqldb.options.charset_name);

            return true;
        }
    }
#endif

    _SETINFO_ERR(info);
    PRINT_ERR_HEAD;
    print_err("Connect DB error = %s", mysql_error(&sqldb));
    mysql_close(&sqldb);
    return false;
}

//系统默认数据库
bool CSYSDB::opendb(void)
{
    return opendb(SQLDB_ADDR, 0, SQLDB_NAME, SQLDB_PWD, SQLDB_DB);
}

#else
//SQLITE_OPEN_NOMUTEX标志表示数据库连接为多线程模式，SQLITE_OPEN_FULLMUTEX表示该连接为串行化模式
#define _SQLITE_FOPEN_ (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE)
bool CSYSDB::opendb(const pchar usrname, const pchar pwd, const pchar dbname, pchar info)
{
    PRINT_DBG_HEAD;
    print_dbg("SQLITE %s, %s:%s", dbname, usrname, pwd);

    strcpy(dbconnect[0], usrname);
    strcpy(dbconnect[1], pwd);
    strcpy(dbconnect[2], dbname);

    if (SQLITE_OK != sqlite3_open_v2(dbname, &sqldb, _SQLITE_FOPEN_, NULL)) {

        PRINT_ERR_HEAD;
        print_err("SQLITE Can't open %s[%s]", dbname, sqlite3_errmsg(sqldb));

        _SETINFO_ERR(info);
        closedb();
        return false;
    }

    if (!is_strempty(usrname) || !is_strempty(pwd)) {
        //加密连接
    }

    PRINT_DBG_HEAD;
    print_dbg("SQLITE %s, %s:%s success", dbname, usrname, pwd);

    return true;
}

//系统默认数据库
bool CSYSDB::opendb(void)
{
    return opendb(SQLDB_NAME, SQLDB_PWD, SQLDB_DB);
}
#endif

/*******************************************************************************************
*功能:    关闭数据库
*参数:
*
*注释:
*
*******************************************************************************************/
bool CSYSDB::closedb(void)
{
    queryend();

#ifdef SQLDB_LITE
    if (sqldb != NULL) {
        sqlite3_close_v2(sqldb);
        sqldb = NULL;
    }
#else
    mysql_close(&sqldb);

#ifdef SYSDB_THREADSAFE
    mysql_thread_end();
#endif

#endif

    return true;
}

/*******************************************************************************************
*功能:    执行SQL语句
*参数:    sql                   ---->    SQL语句
*         info                  ---->    错误信息
*
*注释:
*
*******************************************************************************************/
#ifdef SQLDB_LITE
bool CSYSDB::runsql(const pchar sql, pchar info)
{
    if (is_strempty(sql))   return false;

    pchar err = NULL;
    if (SQLITE_OK != sqlite3_exec(sqldb, sql, NULL, NULL, &err)) {
        if (err != NULL) {
            strncpy(sqlerrormsg, err, sizeof(sqlerrormsg) - 1);
            sqlite3_free(err) ;
        } else {
            strcpy(sqlerrormsg, "unknown");
        }

        if (info != NULL) sprintf(info, sqlerrormsg);
        PRINT_ERR_HEAD;
        print_err("SQLITE SQL %s = %s", sql, sqlerrormsg);

        return false;
    }

    return true;
}

#else
bool CSYSDB::runsql(const pchar sql, pchar info)
{

    if (is_strempty(sql))   return false;

_retry_:
    if (mysql_query(&sqldb, sql) != 0) {

        _SETINFO_ERR(info);

        strncpy(sqlerrormsg, mysql_error(&sqldb), sizeof(sqlerrormsg) - 1);
        PRINT_ERR_HEAD;
        print_err("Invalid DB SQL %s = %s, %d", sql, sqlerrormsg, errcount);

        //异常处理
        static const pchar _syserror[] = {  //不作为表损坏的判断条件
            "MySQL server has gone away",
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near",
            "Commands out of sync; you can't run this command now",
            "Lost connection to MySQL server during query",
            NULL,
        };
        int32 i = 0;
        while (_syserror[i] != NULL) {
            if ((strncmp(sqlerrormsg, _syserror[i], strlen(_syserror[i])) == 0)) break;
            i++;
        }

#if 1
        //防止误操作
        return (_syserror[i] != NULL);
#else
        if (_syserror[i] == NULL) {
            errcount++;
            if ((errcount > 0) && (errcount < 4)) {     //连续尝试修复3次
                //修复表
                char repair[200];
                sprintf(repair, "mysqlcheck -u%s -p%s -r -f %s", dbconnect[0], dbconnect[1], dbconnect[2]);
                system(repair);

                PRINT_ERR_HEAD;
                print_err("REPAIR DB = %s", repair);
                goto _retry_;

            } else if (errcount > 400) {
                //重建表
                /*char repair[200];
                sprintf(repair, "mysqlcheck -u%s -p%s -f --all-databases", dbconnect[0], dbconnect[1]);
                system(repair);

                PRINT_ERR_HEAD;
                print_err("REPAIR DB = %s", repair);*/
                errcount = 0;
            }
        }
#endif
        return false;
    }

    //errcount = 0;
    return true;
}
#endif

/*******************************************************************************************
*功能:    创建表
*参数:    table                 ---->    表名
*         bigtbl                ---->    大表文件
*         count                 ---->    字段数
*         column                ---->    字段信息，支持多参数
*
*注释:
*
*******************************************************************************************/
bool CSYSDB::createtable(const pchar table, bool bigtbl, uint32 count, const pchar column, ...)
{
    if (is_strempty(table) || is_strempty(column)) return false;

    char tmp[600];
    va_list args;

    sprintf(sqlcmd, "CREATE TABLE %s (", table);

    va_start(args, column);
    for (uint32 i = 0; i < count; i++) {
        if (i == (count - 1))
            sprintf(tmp, "%s", va_arg(args, pchar));
        else
            sprintf(tmp, "%s,", va_arg(args, pchar));

        strcat(sqlcmd, tmp);
    }
    va_end(args);

    if (bigtbl) //1亿记录
        sprintf(tmp, ") MAX_ROWS = 100000000 AVG_ROW_LENGTH = 100;");           //结束
    else
        sprintf(tmp, ");");           //结束
    strcat(sqlcmd, tmp);

    PRINT_DBG_HEAD;
    print_dbg("DB Table info = %s", sqlcmd);
    return runsql(sqlcmd);
}

bool CSYSDB::createtable(const pchar table, bool bigtbl, uint32 count, const pchar column[])
{
    if (is_strempty(table) || (column == NULL)) return false;

    char tmp[600];

    sprintf(sqlcmd, "CREATE TABLE %s (", table);

    for (uint32 i = 0; i < count; i++) {
        if (is_strempty(column[i])) {
            PRINT_ERR_HEAD;
            print_err("DB Table info = %d", i);
            continue;
        }
        if (i == (count - 1))
            sprintf(tmp, "%s", column[i]);
        else
            sprintf(tmp, "%s,", column[i]);

        strcat(sqlcmd, tmp);
    }

    if (bigtbl) //1亿记录
        sprintf(tmp, ") MAX_ROWS = 100000000 AVG_ROW_LENGTH = 100;");           //结束
    else
        sprintf(tmp, ");");           //结束
    strcat(sqlcmd, tmp);

    PRINT_DBG_HEAD;
    print_dbg("DB Table info = %s", sqlcmd);
    return runsql(sqlcmd);

}
bool CSYSDB::createtableex(const pchar table, bool bigtbl, uint32 count, const pchar column[])
{
    if (is_strempty(table) || (column == NULL)) return false;

    char tmp[600];

    sprintf(sqlcmd, "CREATE TABLE IF NOT EXISTS %s (", table);

    for (uint32 i = 0; i < count; i++) {
        if (is_strempty(column[i])) {
            PRINT_ERR_HEAD;
            print_err("DB Table info = %d", i);
            continue;
        }
        if (i == (count - 1))
            sprintf(tmp, "%s", column[i]);
        else
            sprintf(tmp, "%s,", column[i]);

        strcat(sqlcmd, tmp);
    }

    if (bigtbl) //1亿记录
        sprintf(tmp, ") MAX_ROWS = 100000000 AVG_ROW_LENGTH = 100;");           //结束
    else
        sprintf(tmp, ");");           //结束
    strcat(sqlcmd, tmp);

    PRINT_DBG_HEAD;
    print_dbg("DB Table info = %s", sqlcmd);
    return runsql(sqlcmd);

}


/*******************************************************************************************
*功能:    删除表
*参数:    table                 ---->    表名
*
*注释:
*
*******************************************************************************************/
bool CSYSDB::deletetable(const pchar table)
{
    if (is_strempty(table)) return false;

    sprintf(sqlcmd, "DROP TABLE %s;", table);

    PRINT_DBG_HEAD;
    print_dbg("DB Table info = %s", sqlcmd);
    return runsql(sqlcmd);
}

/*******************************************************************************************
*功能:    清空表记录
*参数:    table                 ---->    表名
*
*注释:
*
*******************************************************************************************/
bool CSYSDB::cleartable(const pchar table)
{
    if (is_strempty(table)) return false;

    sprintf(sqlcmd, "TRUNCATE TABLE %s;", table);

    PRINT_DBG_HEAD;
    print_dbg("DB Table info = %s", sqlcmd);
    return runsql(sqlcmd);
}


/*******************************************************************************************
*功能:    查询语句，并保持记录
*参数:    sql                   ---->    SQL语句
*         columns               ---->    字段数
*         info                  ---->    错误信息
*
*注释:      需要与queryresult，queryend配合使用
*
*******************************************************************************************/
bool CSYSDB::querysave(const pchar sql, uint32 &columns, pchar info)
{
#ifdef SQLDB_LITE
    char *err;
    columns = 0;

    if (SQLITE_OK == sqlite3_get_table(sqldb, sql, &resdb, &rowdb, &coldb, &err)) {
        rowidx = 0;
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("SQLITE query results = %lu, column = %lu", rowdb, coldb);
#endif
        columns = (uint32)coldb;
        return true;
    }

    if (err != NULL) {
        strncpy(sqlerrormsg, err, sizeof(sqlerrormsg) - 1);
        sqlite3_free(err) ;
    } else {
        strcpy(sqlerrormsg, "unknown");
    }

    if (info != NULL) sprintf(info, sqlerrormsg);
    PRINT_ERR_HEAD;
    print_err("SQLITE query %s = %s", sql, sqlerrormsg);

#else
    columns = 0;
    if (runsql(sql, info)) {
        if ((resdb = mysql_store_result(&sqldb)) != NULL) {
            columns = (uint32)mysql_num_fields(resdb);

#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("DB query results = %lu, column = %lu",
                      (uint32)mysql_num_rows(resdb), columns);
#endif
            return true;
        } else {
            PRINT_ERR_HEAD;
            print_err("DB %s = %s", sql, mysql_error(&sqldb));
        }
    }
#endif

    return false;
}

/*******************************************************************************************
*功能:    读取查询记录集中的一条记录
*参数:    返回值                   ---->   字段值指针，NULL失败
*
*注释:      结合数据库底层API，用户自行转义为"MYSQL_ROW"类型
*
*******************************************************************************************/
const void *CSYSDB::queryresult(void)
{

#ifdef SQLDB_LITE
    if (resdb == NULL) return NULL;

#if __DEBUG_MORE__
    char colname[1000] = {0};
    for (int i = 0; i < coldb; i++) {
        sprintf(colname + strlen(colname), "\"%s\", ", resdb[i]);
    }
    PRINT_DBG_HEAD;
    print_dbg("SQLITE query %s", colname);
#endif

    if (rowidx < rowdb) {
        return (const void *)(resdb + ((++rowidx) * coldb));
    }

    PRINT_DBG_HEAD;
    print_dbg("SQLITE query empty");
    return NULL;

#else
    if (resdb == NULL) return NULL;

    if ((rowdb = mysql_fetch_row(resdb)) == NULL) {
        PRINT_DBG_HEAD;
        print_dbg("DB query empty");
    }

    return (const void *) rowdb;
#endif
}

/*******************************************************************************************
*功能:    读取查询记录集数量
*参数:    返回值                   ---->   -1：失败
*
*注释:
*
*******************************************************************************************/
const int32 CSYSDB::queryresultcnt(void)
{
#ifdef SQLDB_LITE
    if (resdb == NULL) return -1;

    return (int32)rowdb;
#else
    if (resdb == NULL) return -1;

    return (int32)mysql_num_rows(resdb);
#endif
}

/*******************************************************************************************
*功能:    关闭查询记录集
*参数:
*
*注释:
*
*******************************************************************************************/
bool CSYSDB::queryend(void)
{
#ifdef SQLDB_LITE
    if (resdb == NULL) return false;

    sqlite3_free_table(resdb);
    resdb = NULL;
    rowidx = rowdb = coldb = 0;
#else
    if (resdb == NULL) return false;

    mysql_free_result(resdb);
    resdb = NULL;
#endif
    return true;
}

/*******************************************************************************************
*功能:   支持多线程
*参数:   set                   ---->    开始、结束
*
*注释:   只允许进程（主线程）调用
*
*******************************************************************************************/
bool CSYSDB::globalset_threadsafe(uint32 set)
{
#ifdef SQLDB_LITE
    return true;
#else
#ifdef SYSDB_THREADSAFE
    PRINT_DBG_HEAD;
    print_dbg("DB set = %d", set);

    switch (set) {
    case gSET_START:
        if (mysql_library_init(0, NULL, NULL) == 0)  return true;
        PRINT_ERR_HEAD;
        print_err("DB mysql_library_init");
        break;
    case gSET_END:
        mysql_library_end();
        return true;
    }

    PRINT_ERR_HEAD;
    print_err("DB set = %d", set);
    return false;
#else
    return true;
#endif
#endif
}


/*******************************************************************************************
*功能:   检查并修正sql语句内容
*参数:   src                   ---->    原始内容
*        dst                   ---->    修正内容
*        返回值                ---->    修正内容，NULL失败
*
*注释:   dst确保足够大，src的2倍空间
*
*******************************************************************************************/
pchar CSYSDB::sqlescape(const pchar src, pchar dst)
{
    if ((src == NULL) || (dst == NULL)) return NULL;

    unsigned long len = 0;
    PRINT_DBG_HEAD;
    print_dbg("DB check = %s", src);

#ifdef SQLDB_LITE
    strcpy(dst, src);
#else
    dst[0] = 0;
    len = mysql_escape_string(dst, src, strlen(src));
#endif
    PRINT_DBG_HEAD;
    print_dbg("DB check %lu = %s", len, dst);

    return dst;
}

/*******************************************************************************************
*功能:   获取错误信息
*参数:
*        返回值                ---->    错误描述
*
*注释:   必须在runsql失败后才能调用
*
*******************************************************************************************/
const pchar CSYSDB::geterror(void)
{
    return (const pchar)sqlerrormsg;
}
