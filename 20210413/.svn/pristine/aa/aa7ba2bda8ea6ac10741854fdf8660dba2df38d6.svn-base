/*******************************************************************************************
*文件:  log_mv.cpp
*描述:  把mysql中表数据移动到其他库表中
*作者:  王君雷
*日期:  2021-07-01
*
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "mysql.h"
#include "debugout.h"
#include "stringex.h"

loghandle glog_p = NULL;

/**
 * [mysql_init_connect mysql的初始化和连接]
 * @param  mysql [mysql对象指针]
 * @return       [成功返回0 失败返回负值]
 */
int mysql_init_connect(MYSQL *mysql, const char *dbname = NULL)
{
    //初始化数据库链接信息
    if (mysql_init(mysql) == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql_init err");
        return -1;
    }

    if (mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "client") != 0) {
        mysql_close(mysql);
        PRINT_ERR_HEAD
        print_err("mysql_options err");
        return -1;
    }

    if (mysql_real_connect(mysql, "localhost", "susqlroot", "suanmitsql",
                           (dbname == NULL) ? "sudb" : dbname, 0, NULL, 0) == NULL) {
        PRINT_ERR_HEAD
        print_err("Connect DB error");
        mysql_close(mysql);
        return -1;
    }

    return 0;
}

/**
 * [dbsynclog_move 把旧的日志转移到新表中]
 */
void dbsynclog_move(void)
{
    char chcmd[4096] = {0};
#if 0
    sprintf(chcmd,
            "mysql -e \"insert into sync_db.DBSYNCLOG(optime,name,logway,srcdb,srcip,destdb,destip,srctable,desttable,remark,ifsend,isout,alarm)" \
            "select optime,name,logway,srcdb,srcip,destdb,destip,srctable,desttable,remark,ifsend,isout,alarm from sudb.DBSYNCLOG order by id desc limit 200000\"");
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("dbsynclog move[%s]", chcmd);

    sprintf(chcmd, "/initrd/abin/createdb localhost DBSYNCLOG");
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("dbsynclog move[%s]", chcmd);
#else
    MYSQL mysql_sudb;
    MYSQL mysql_syncdb;
    MYSQL_RES *res;
    MYSQL_ROW row;
    int64 cid = 0, maxid = 0, minid = 0;
    char sql[4096] = {0}, isql[4096] = {0};
    char logway[64] = {0};
    char name[200] = {0};
    char srcdb[200] = {0};
    char destdb[200] = {0};
    char srctable[200] = {0};
    char desttable[200] = {0};
    char remark[2000] = {0};
    int cnt = 0;

    while (mysql_init_connect(&mysql_sudb, "sudb") != 0) {
        sleep(1);
        printf("mysql sudb init connect retry!");
    }

    while (mysql_init_connect(&mysql_syncdb, "sync_db") != 0) {
        sleep(1);
        printf("mysql sync_db init connect retry!");
    }
    mysql_set_character_set(&mysql_syncdb, "utf8");

    PRINT_INFO_HEAD
    print_info("connect ok");

    //查询总共有多少条
    sprintf(sql, "select count(id), max(id) from DBSYNCLOG");
    if (mysql_query(&mysql_sudb, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s][%s]", sql, mysql_error(&mysql_sudb));
        goto _out;
    }

    //查询结果放入res中
    res = mysql_store_result(&mysql_sudb);
    if (res == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store fail[%s]", mysql_error(&mysql_sudb));
        goto _out;
    }

    row = mysql_fetch_row(res);
    mysql_free_result(res);
    if (row == NULL) {
        PRINT_INFO_HEAD
        print_info("mysql fetch row fail[%s]", mysql_error(&mysql_sudb));
        goto _out;
    }

    cid = atoll(row[0]);
    if (cid == 0) {
        goto _out;
    }
    maxid = atoll(row[1]);

#define MAX_RECORD_NUM 200000 //最多转移多少条
#define SQL_LIMIT_VAL  10000  //每次select查询条数
    minid = MAX(maxid - MAX_RECORD_NUM + 1, 0);

    PRINT_INFO_HEAD
    print_info("cid[%lld] maxid[%lld] minid[%lld]", cid, maxid, minid);

    for (; minid <= maxid; minid += SQL_LIMIT_VAL) {
        sprintf(sql,
                "select optime,name,logway,srcdb,srcip,destdb,destip,srctable,desttable,remark,ifsend,isout,alarm "
                "from DBSYNCLOG where (id >= %lld) and (id <= %lld) order by id limit %d", minid, maxid, SQL_LIMIT_VAL);

        if (mysql_query(&mysql_sudb, sql) != 0) {
            PRINT_ERR_HEAD
            print_err("mysql query fail[%s][%s]", sql, mysql_error(&mysql_sudb));
            goto _out;
        }

        res = mysql_store_result(&mysql_sudb);
        if (res == NULL) {
            PRINT_ERR_HEAD
            print_err("mysql store fail[%s]", mysql_error(&mysql_sudb));
            goto _out;
        }

        while (1) {
            row = mysql_fetch_row(res);
            if (row == NULL) {
                break;
            }
            memset(logway, 0, sizeof(logway));
            memset(name, 0, sizeof(name));
            memset(srcdb, 0, sizeof(srcdb));
            memset(destdb, 0, sizeof(destdb));
            memset(srctable, 0, sizeof(srctable));
            memset(desttable, 0, sizeof(desttable));
            memset(remark, 0, sizeof(remark));
            strconv("GBK", row[2], "UTF-8", logway);
            strconv("GBK", row[1], "UTF-8", name);
            strconv("GBK", row[3], "UTF-8", srcdb);
            strconv("GBK", row[5], "UTF-8", destdb);
            strconv("GBK", row[7], "UTF-8", srctable);
            strconv("GBK", row[8], "UTF-8", desttable);
            strconv("GBK", row[9], "UTF-8", remark);

            sprintf(isql,
                    "insert into DBSYNCLOG(optime,name,logway,srcdb,srcip,"
                    "destdb,destip,srctable,desttable,remark,"
                    "ifsend,isout,alarm) "
                    "values('%s','%s','%s','%s','%s',"
                    "'%s','%s','%s','%s','%s',"
                    "'%s','%s','%s')",
                    row[0], name, logway, srcdb, row[4],
                    destdb, row[6], srctable, desttable, remark,
                    row[10], row[11], row[12]);
            if (mysql_query(&mysql_syncdb, isql) != 0) {
                PRINT_ERR_HEAD
                print_err("mysql query fail[%s][%s]", isql, mysql_error(&mysql_syncdb));
            } else {
                cnt++;
            }
        }
        mysql_free_result(res);
    }

    system("/initrd/abin/createdb localhost DBSYNCLOG");
    PRINT_INFO_HEAD
    print_info("clear table DBSYNCLOG");
_out:
    mysql_close(&mysql_sudb);
    mysql_close(&mysql_syncdb);
    PRINT_INFO_HEAD
    print_info("dbsynclog move over.cnt[%d]", cnt);
#endif
}


/**
*功能介绍：mysql数据库压力测试
*程序参数：./mysqltest threadnum printtimes
*参数含义：
*          threadnum 启动线程个数
*          printtimes 每个线程打印次数
*/
int main(int argc, char *argv[])
{
    _log_init_(glog_p, log_mv);

    if (argc != 5) {
        printf("Usage:%s old_db old_table new_db new_table\n", argv[0]);
        return 0;
    }

    if ((strcmp(argv[1], "sudb") == 0)
        && (strcmp(argv[2], "DBSYNCLOG") == 0)
        && (strcmp(argv[3], "sync_db") == 0)
        && (strcmp(argv[4], "DBSYNCLOG") == 0)) {
        dbsynclog_move();
    } else {
        PRINT_ERR_HEAD
        print_err("input unknown");
    }
    return 0;
}
