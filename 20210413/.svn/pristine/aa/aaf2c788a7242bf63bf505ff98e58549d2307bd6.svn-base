/*******************************************************************************************
*文件:  FCLogDel.cpp
*描述:  磁盘空间检测
*作者:  王君雷
*日期:  2014
*
*修改:
*       重新设计日志清理逻辑                                              ------> 2017-02-13
*       目录文件使用宏代替，使用linux风格，utf8编码                       ------> 2018-04-23
*       线程ID使用pthread_t类型                                           ------> 2018-08-07
*       使用zlog;添加对sqllite和zlog日志空间的监控清理                    ------> 2018-09-28
*       磁盘空间告警使用百分比                                            ------> 2018-11-19
*       添加AlertLog等函数                                                ------> 2018-12-07
*       不再枚举数据库表，程序去动态读取;原来超过100MB的表折半删除，现改为超过磁盘总容量
*       十分之一的表折半删除，适应大磁盘的情况                            ------> 2018-12-07
*       修改读取数据库表名称错误、su_gap_sessions表特殊处理等问题         ------> 2018-12-11
*       当剩余空间比大表大200M以上时才去折半删除，否则重建表；原来使用的是50M
*                                                                         ------> 2019-07-09
*       修改没有初始化就使用mysql操作对象写数据库的bug                    ------> 2019-12-06 wjl
*       其他线程写DB表失败，会通知本线程去修复对应表                      ------> 2019-12-15 wjl
*       web代理强制使用nginx实现，不用再去清webproxy的日志了             ------> 2020-11-19
*       可以设置线程名称                                                ------> 2021-02-23
*       解决文件交换表被删除后无限循环去修复的BUG                         ------> 2021-05-18
*******************************************************************************************/
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>
using namespace std;
#include <vector>

#include "FCLogManage.h"
#include "FCLogDel.h"
#include "const.h"
#include "define.h"
#include "simple.h"
#include "debugout.h"
#include "common.h"
#include "speaker.h"
#include "fileoperator.h"
#include "hardinfo.h"
#include "tbl_err_comm.h"

#define DISK_CHECK_PATH "/initrd/"     //磁盘空间检查时所检查的目录
#define SQLITE_PATH "/var/lib/sqlite/" //私有协议文件交换，增量传输时把sqlite数据库文件存放在这里
extern bool g_diskalertchange;
static bool g_readtable = true; //是否需要重新读取表名

#define DEFAULT_MAX_MB_PER_TABLE 512 //默认单表最多支持MB数

//磁盘告警紧张级别
enum {
    HIGH_LEVEL_WARN = 1,
    LOW_LEVEL_WARN,
};

/**
 * [DiskCheck 检查剩余磁盘空间是多少M]
 * @param  chpath [检查的路径]
 * @return        [成功返回剩余M数，失败返回负值]
 */
int DiskCheck(const char *chpath)
{
    if (chpath == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    struct statfs disk_statfs;
    if (statfs(chpath, &disk_statfs) != 0) {
        PRINT_ERR_HEAD
        print_err("statfs fail[%s]", strerror(errno));
        return -1;
    }

    return (disk_statfs.f_bsize / 1024 * disk_statfs.f_bavail / 1024);
}

/**
 * [DiskFreePercent 剩余磁盘空间百分比]
 * @param  chpath [检查的路径]
 * @return        [成功返回>=0，失败返回负值]
 */
int DiskFreePercent(const char *chpath)
{
    if (chpath == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    struct statfs disk_statfs;
    if (statfs(chpath, &disk_statfs) != 0) {
        PRINT_ERR_HEAD
        print_err("statfs fail[%s]", strerror(errno));
        return -1;
    }

    return (disk_statfs.f_bavail * 100 / disk_statfs.f_blocks);
}

/**
 * [TblSize 获取某个表对应的MYD文件占用磁盘空间的大小 MB]
 * @param  tabname [表名]
 * @return         [成功返回M数 失败返回负值]
 */
int TblSize(const char *tabname)
{
    char filepath[MAX_FILE_PATH_LEN] = {0};
    sprintf(filepath, "%s%s.MYD", MYSQL_SUDB_PATH, tabname);

    struct stat statbuff;
    if (stat(filepath, &statbuff) < 0) {
        PRINT_ERR_HEAD
        print_err("stat fail[%s:%s]", filepath, strerror(errno));
        return -1;
    } else {
        return (statbuff.st_size / (1024 * 1024)); //(MB)
    }
}

/**
 * [TMDDel 删除临时文件]
 */
void TMDDel(void)
{
    char chcmd[64] = {0};
    sprintf(chcmd, "rm -f %s*.TMD", MYSQL_SUDB_PATH);
    system(chcmd);
    system("sync");
}

/**
 * [TblRebuild 重建某个表]
 * @param tblname [表名]
 */
void TblRebuild(const char *tblname)
{
    char chcmd[64] = {0};

    if (tblname != NULL) {
        PRINT_DBG_HEAD
        print_dbg("rebuild table[%s]", tblname);
        sprintf(chcmd, "%s localhost %s", CREATEDB_FILE, tblname);
        system(chcmd);
    }
}

/**
 * [TblErr 表是否损坏了]
 * @param  tblname [表名]
 * @return        [表损坏了则返回true]
 */
bool TblErr(const char *tblname)
{
    char sql[MAX_SQL_LEN] = {0};
    bool berr = false;
    MYSQL mysql;

    while (mysql_init_connect(&mysql) != 0) {
        PRINT_ERR_HEAD
        print_err("connect mysql fail while check table[%s] status, retry", tblname);
        sleep(1);
    }

    sprintf(sql, "select * from %s where id < 1", tblname);
    if (mysql_query(&mysql, sql) != 0) {
        berr = true;
        PRINT_ERR_HEAD
        print_err("mysql query fail while execute[%s]", sql);
    }

    mysql_close(&mysql);
    return berr;
}

/**
 * [HealthCheck 表健康状态检查 损坏了就去修复]
 * @param freedisk   [磁盘剩余空间MB]
 * @param tblname     [表名]
 * @param berr       [true 表示已经知道它损坏了;false 表示需要通过检查来判断它是否损坏了]
 */
void HealthCheck(int freedisk, const char *tblname, bool berr)
{
    char sql[MAX_SQL_LEN] = {0};
    MYSQL mysql;
    int tabsize = 0;

    if (berr || TblErr(tblname)) {

        tabsize = TblSize(tblname);
        if ((tabsize == -1) && (strncmp(tblname, "msync_task", 10) == 0)) {
            PRINT_INFO_HEAD
            print_info("table[%s]may be removed", tblname);
            g_readtable = true;
            return;
        }

        //当剩余空间比该表占用的空间大100M以上时 才去repair表 否则可能会卡死
        if (freedisk > tabsize + 100) {

            PRINT_ERR_HEAD
            print_err("begin to repair[%s]. freedisk[%d]MB tabsize[%d]MB",
                      tblname, freedisk, tabsize);

            while (mysql_init_connect(&mysql) != 0) {
                PRINT_ERR_HEAD
                print_err("begin to repair[%s]. freedisk[%d]MB tabsize[%d]MB.mysql reconnect ...",
                          tblname, freedisk, tabsize);
                sleep(1);
            }

            sprintf(sql, "repair table %s", tblname);
            if (mysql_query(&mysql, sql) == 0) {
                mysql_close(&mysql);
                PRINT_INFO_HEAD
                print_info("repair ok[%s]", sql);
                return;
            } else {
                PRINT_ERR_HEAD
                print_err("repair fail[%s]", sql);
                mysql_close(&mysql);
            }
        }

        PRINT_INFO_HEAD
        print_info("begin to rebuild[%s]. freedisk[%d]MB tabsize[%d]MB",
                   tblname, freedisk, tabsize);
        TblRebuild(tblname);
    }
}

/**
 * [DirFileNum 查询目录下有多少文件]
 * @param  directory [目录]
 * @return           [返回目录下文件数 失败返回负值]
 */
int DirFileNum(const char *directory)
{
    CCommon common;
    char chcmd[CMD_BUF_LEN] = {0};
    char buff[64] = {0};

    if (directory == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    snprintf(chcmd, sizeof(chcmd), "ls %s 2>/dev/null |wc -l", directory);
    if (common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) {
        return atoi(buff);
    } else {
        PRINT_ERR_HEAD
        print_err("sysinfo[%s] fail", chcmd);
    }
    return -1;
}

/**
 * [FindOldFile 查找目录下最后修改时间最老的那个文件]
 * @param  path    [查找的路径]
 * @param  oldfile [最老的文件]
 * @param  told    [最老的文件的最后修改时间]
 * @return         [查找到了返回true]
 */
#define ONE_WEEK_SECONDS (7 * 24 * 60 * 60)
bool FindOldFile(const char *path, char *oldfile, time_t &told)
{
    if ((path == NULL) || (oldfile == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null");
        return false;
    }

    bool bret = false;
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char srcfile[MAX_FILE_PATH_LEN] = {0};

    told = time(NULL);
    if ((dirptr = opendir(path)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", path, strerror(errno));
        return false;
    }

    //扫描目录
    while ((entry = readdir(dirptr)) != NULL) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcfile, MAX_FILE_PATH_LEN, "%s%s", path, entry->d_name);
        if (lstat(srcfile, &statbuf) < 0) {
            PRINT_ERR_HEAD
            print_err("lstat[%s] error[%s]", srcfile, strerror(errno));
            closedir(dirptr);
            return false;
        }

        if (S_ISREG(statbuf.st_mode) && (statbuf.st_mtime < told) ) {
            told = statbuf.st_mtime;
            strcpy(oldfile, srcfile);
            bret = true;
        }
    }
    closedir(dirptr);
    if (!bret) {
        PRINT_ERR_HEAD
        print_err("not find old file in path[%s]", path);
    } else {
        PRINT_ERR_HEAD
        print_err("find old file[%s] in path[%s]", oldfile, path);
    }
    return bret;
}

/**
 * [SqliteCheck 维护sqlite表空间]
 * @param level [磁盘紧张级别 1为最高级别]
 */
void SqliteCheck(int level)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char oldfile[MAX_FILE_PATH_LEN] = {0};
    time_t oldtime = 0;

    if (DirFileNum(SQLITE_PATH) > 0) {
        switch (level) {
        case HIGH_LEVEL_WARN:
            //很紧张了
            PRINT_INFO_HEAD
            print_info("tool little space left. delete all sqlite db file");
            sprintf(chcmd, "rm -rf %s*", SQLITE_PATH);
            system(chcmd);
            sprintf(chcmd, "killall %s", PRIVFSYNC);
            system(chcmd);
            break;
        case LOW_LEVEL_WARN:
            //找出最后修改时间最早的 并且是1周以前的删除掉
            if (FindOldFile(SQLITE_PATH, oldfile, oldtime)
                && (oldtime - time(NULL) > ONE_WEEK_SECONDS)) {
                PRINT_INFO_HEAD
                print_info("little space left,delete file[%s]", oldfile);
                remove(oldfile);
                sprintf(chcmd, "killall %s", PRIVFSYNC);
                system(chcmd);
            }
            break;
        default:
            PRINT_ERR_HEAD
            print_err("unknown level %d", level);
            break;
        }
    }
}

/**
 * [HalfDel 折半删除表记录 删除较早插入的一半]
 * @param tblname [表名]
 */
void HalfDel(const char *tblname)
{
    char sql[MAX_SQL_LEN] = {0};
    MYSQL_RES *m_res;
    MYSQL_ROW m_row;
    MYSQL mysql;
    long long minid = 0;
    long long recordnum = 0;

    while (mysql_init_connect(&mysql) != 0) {
        PRINT_ERR_HEAD
        print_err("connect to mysql fail retry");
        sleep(1);
    }

    //查询表最小id及记录总数
    sprintf(sql, "select min(id),count(id) from %s", tblname);
    if (mysql_query(&mysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s],rebuild it", sql);
        mysql_close(&mysql);
        TblRebuild(tblname);
        return;
    }

    //查询结果放入m_res中
    if ((m_res = mysql_store_result(&mysql)) == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql store result fail[%s],rebuild it", tblname);
        mysql_close(&mysql);
        TblRebuild(tblname);
        return;
    }

    //fetch一行
    if ((m_row = mysql_fetch_row(m_res)) == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql fetch row fail[%s],rebuild it", tblname);
        mysql_free_result(m_res);
        mysql_close(&mysql);
        TblRebuild(tblname);
        return;
    }
    mysql_free_result(m_res);

    minid = atoll(m_row[0]);
    recordnum = atoll(m_row[1]);

    PRINT_INFO_HEAD
    print_info("tblname[%s] minid[%lld] count[%lld]", tblname, minid, recordnum);

    //删除
    sprintf(sql, "delete from %s where id < %lld", tblname, minid + recordnum / 2);
    if (mysql_query(&mysql, sql) != 0) {
        PRINT_ERR_HEAD
        print_err("mysql query fail[%s],rebuild it", sql);
        mysql_close(&mysql);
        TblRebuild(tblname);
    } else {

        PRINT_INFO_HEAD
        print_info("[%s] half delete ok,begin to optimize table", tblname);

        //执行优化
        sprintf(sql, "optimize table %s", tblname);
        if (mysql_query(&mysql, sql) != 0) {
            PRINT_ERR_HEAD
            print_err("mysql query fail[%s],rebuild it", sql);
            mysql_close(&mysql);
            TblRebuild(tblname);
        } else {
            PRINT_INFO_HEAD
            print_info("tblname[%s] half delete ok", tblname);
            mysql_close(&mysql);
        }
    }
}

/**
 * [LogDel 删除部分日志 （zlog、web代理log）]
 */
void LogDel(void)
{
    CCommon common;
    char chcmd[CMD_BUF_LEN] = {0};
    char buff[64] = {0};

    snprintf(chcmd, sizeof(chcmd), "ls %s.* 2>/dev/null |wc -l", RUN_LOG_PATH);
    if ((common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) && (atoi(buff) > 0)) {
        PRINT_INFO_HEAD
        print_info("delete %d run.log.* file", atoi(buff));
        snprintf(chcmd, sizeof(chcmd), "rm -rf %s.*", RUN_LOG_PATH);
        system(chcmd);
    }
#if 0
    BZERO(buff);
    snprintf(chcmd, sizeof(chcmd), "ls /tmp/webproxy*.log 2>/dev/null |wc -l");
    if ((common.Sysinfo(chcmd, buff, sizeof(buff)) != NULL) && (atoi(buff) > 0)) {
        PRINT_INFO_HEAD
        print_info("delete %d webproxy*.log file", atoi(buff));
        snprintf(chcmd, sizeof(chcmd), "rm -rf /tmp/webproxy*.log");
        system(chcmd);
    }
#endif
}

/**
 * [HandleSYSTEM_STATUS 处理SYSTEM_STATUS表  只保留一天的 因为保留1天之前的没用]
 * @return  [description]
 */
#define ONE_DAY_SECONDS (60 * 60 * 24)
bool HandleSYSTEM_STATUS(void)
{
    struct tm tmptm;
    char sqlbuff[MAX_SQL_LEN] = {0};
    CLOGMANAGE mlog;
    bool bret = false;

    time_t tnow = time(NULL);
    tnow -= ONE_DAY_SECONDS;
    localtime_r(&tnow, &tmptm);
    snprintf(sqlbuff, sizeof(sqlbuff),
             "delete from SYSTEM_STATUS where optime < '%04d-%02d-%02d %02d:%02d:%02d'",
             tmptm.tm_year + 1900, tmptm.tm_mon + 1, tmptm.tm_mday,
             tmptm.tm_hour, tmptm.tm_min, tmptm.tm_sec);

    mlog.Init();
    if (mlog.WriteToDB(sqlbuff) == E_FALSE) {
        PRINT_ERR_HEAD
        print_err("[%s]fail", sqlbuff);
    } else {
        PRINT_DBG_HEAD
        print_dbg("[%s]ok", sqlbuff);
        bret = true;
    }

    mlog.DisConnect();
    return bret;
}

/**
 * [AlertLog 写告警日志]
 * @param  freediskpercent [磁盘剩余空间百分比]
 * @param  bufalert        [告警阈值百分比]
 * @return                 [写日志成功返回true]
 */
bool AlertLog(int freediskpercent, int bufalert)
{
    char chsyslog[SYSLOG_BUF_LEN] = {0};
    sprintf(chsyslog, "%s[%d%%][%d%%]", LOG_CONTENT_DISK_ALARM, freediskpercent, bufalert);

    bool bret = false;
    CLOGMANAGE mlog;
    mlog.Init();
    if (mlog.WriteSysLog(LOG_TYPE_DISK_CK, D_SUCCESS, chsyslog) == E_FALSE) {
        PRINT_ERR_HEAD
        print_err("write to db fail while disk warn.[free:%d%%][alert:%d%%]", freediskpercent, bufalert);
    } else {
        bret = true;
    }
    mlog.DisConnect();
    return bret;
}

/**
 * [ReadAlertVal 读取告警阈值 百分比]
 * @param  alert [告警阈值 出参]
 * @param  maxMBPerTable [允许单表最大MB数]
 * @return       [成功返回true]
 */
bool ReadAlertVal(int &alert, int &maxMBPerTable)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile error[%s]", SYSSET_CONF);
        return false;
    }

    fileop.ReadCfgFileInt("SYSTEM", "BUFFALERT", &alert);
    if ((alert <= 0) || (alert >= 100)) {
        PRINT_ERR_HEAD
        print_err("alert err[%d], use default %d", alert, DEFAULT_BUFFALERT);
        alert = DEFAULT_BUFFALERT;
    }

    fileop.ReadCfgFileInt("SYSTEM", "MaxMBPerTable", &maxMBPerTable);
    if ((maxMBPerTable <= 0)) {
        PRINT_ERR_HEAD
        print_err("MaxMBPerTable err[%d], use default %d", maxMBPerTable, DEFAULT_MAX_MB_PER_TABLE);
        maxMBPerTable = DEFAULT_MAX_MB_PER_TABLE;
    }
    fileop.CloseFile();
    return true;
}

/**
 * [FilterMYD 读取目录下文件的过滤函数 只把想要的文件过滤出来]
 * @param  ent [结构指针]
 * @return     [打算过滤出来的返回1]
 */
int FilterMYD(const struct dirent *ent)
{
    if (ent->d_type != DT_REG) {
        return 0;
    }

    int slen = strlen(ent->d_name);
    int dlen = strlen(".MYD");
    if ((slen > dlen) && (strcmp(ent->d_name + slen - dlen, ".MYD") == 0)) {
        return 1;
    }
    return 0;
}

/**
 * [ReadTbl 读取sudb库下的所有表]
 * @param  tabname [存放表名的vector]
 * @return         [成功返回true]
 */
bool ReadTbl(vector<string> &tabname)
{
    tabname.clear();
    char tmpname[MAX_FILE_PATH_LEN] = {0};
    int len = 0;

    struct dirent **namelist;
    int n = scandir(MYSQL_SUDB_PATH, &namelist, FilterMYD, alphasort);
    if (n < 0) {
        PRINT_ERR_HEAD
        print_err("scandir error[%s:%s]", MYSQL_SUDB_PATH, strerror(errno));
        return false;
    } else {
        for (int i = 0; i < n; i++) {
            len = strlen(namelist[i]->d_name);
            BZERO(tmpname);
            memcpy(tmpname, namelist[i]->d_name, len - strlen(".MYD"));
            if (strcmp(tmpname, "su_gap_sessions") == 0) {
                //特殊表 不去监控
            } else {
                tabname.push_back(tmpname);
                PRINT_DBG_HEAD
                print_dbg("%s", tmpname);
            }
            free(namelist[i]);
        }
        free(namelist);
    }

    PRINT_INFO_HEAD
    print_info("tabname number[%d]", (int)tabname.size());
    return (tabname.size() > 0);
}

/**
 * [GetBiggestTbl 选出最大的表]
 * @param  tablename  [存放表名的vector]
 * @param  biggesttab [最大表 出参]
 * @return            [最大表的MB数 出错返回负值]
 */
int GetBiggestTbl(vector<string> &tablename, char *biggesttab)
{
    if (biggesttab == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    int ret = -1;
    for (int i = 0; i < (int)tablename.size(); i++) {
        int tabsize = TblSize(tablename[i].c_str());
        if (tabsize > ret) {
            ret = tabsize;
            strcpy(biggesttab, tablename[i].c_str());
        }
    }
    return ret;
}

/**
 * [DiskCheckProcess  磁盘容量检查线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *DiskCheckProcess (void *arg)
{
    pthread_setself("diskcheck");
    int bufalert = DEFAULT_BUFFALERT;
    int maxMBPerTable = DEFAULT_MAX_MB_PER_TABLE;
    vector<string> tablename;
    int biggesttabsize = 0;
    char biggesttab[32] = {0};
    char errtbl[40] = {0};
    int count = 0;
    int freedisk = 0;
    int freediskpercent = 0;
    int tabsize = 0;
    int totaldisk = 1000;//默认为1G

    TMDDel();
    get_disksize(totaldisk, DISK_CHECK_PATH);

    PRINT_INFO_HEAD
    print_info("totaldisk [%d]MB", totaldisk);

    while (1) {
        if (g_diskalertchange) {
            g_diskalertchange = false;
            ReadAlertVal(bufalert, maxMBPerTable);
            sleep(5);                //等待其他创建表的进程 确实已经创建完表了
            PRINT_INFO_HEAD
            print_info("bufalert %d, maxMBPerTable %d", bufalert, maxMBPerTable);
            count = 0;
        }
        sleep(1);
        count %= 60 * 60 * 24;
        count++;

        //每小时重新读取一次
        if (g_readtable || (count % (60 * 60) == 1)) {
            ReadTbl(tablename);
            g_readtable = false;
        }

        if (count % 120 == 1) {
            HandleSYSTEM_STATUS();         //每120s删除一次系统状态日志，保留1天的
            SqliteCheck(LOW_LEVEL_WARN);
            system("rm -rf /tmp/logs/*.log");
        }

        //获取剩余磁盘空间 剩余空间百分比
        if (((freedisk = DiskCheck(DISK_CHECK_PATH)) < 0)
            || ((freediskpercent = DiskFreePercent(DISK_CHECK_PATH)) < 0)) {
            continue;
        }

        //是否报警
        if (freediskpercent < bufalert) {
            if (count % 30 == 1) {
                AlertLog(freediskpercent, bufalert);
            }
            LogDel();
            speaker_disk_warn();
        }

        if (freedisk < 80) {
            biggesttabsize = GetBiggestTbl(tablename, biggesttab);
            if (biggesttabsize > 0) {
                PRINT_INFO_HEAD
                print_info("begin rebuild table[%s] tablessize[%d]MB", biggesttab, biggesttabsize);
                TblRebuild(biggesttab);
            }
            SqliteCheck(HIGH_LEVEL_WARN);
        }

        //其他程序通知表损坏
        while (tbl_err_get_request(errtbl, sizeof(errtbl))) {
            HealthCheck(freedisk, errtbl, true);
        }

        //表健康状态检查 损坏了就去修复
        for (int i = 0; i < (int)tablename.size(); i++) {
            HealthCheck(freedisk, tablename[i].c_str(), false);
        }

        //清理大于...的表
        if (count % 30 == 1) {
            for (int i = 0; i < (int)tablename.size(); i++) {
                tabsize = TblSize(tablename[i].c_str());
                if ((tabsize <= totaldisk / 10) && (tabsize < maxMBPerTable)) {
                    continue;
                }
                if (DiskCheck(DISK_CHECK_PATH) > tabsize + 200) {
                    //对半删除
                    PRINT_INFO_HEAD
                    print_info("half delete %s", tablename[i].c_str());
                    HalfDel(tablename[i].c_str());
                } else {
                    //重建表
                    PRINT_INFO_HEAD
                    print_info("rebuild %s", tablename[i].c_str());
                    TblRebuild(tablename[i].c_str());
                }
            }

        }
    }

    PRINT_ERR_HEAD
    print_err("disk check process is over");
    return NULL;
}

/**
 * [StartLogDel 启动磁盘空间检测与处理线程]
 * @return            [成功返回0 失败返回负值]
 */
int StartLogDel(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, DiskCheckProcess, NULL) != 0) {

        CLOGMANAGE mlog;
        mlog.Init();
        mlog.WriteSysLog(LOG_TYPE_DISK_CK, D_FAIL, LOG_CONTENT_RUN_DISK_CK_ERR);
        mlog.DisConnect();
        PRINT_ERR_HEAD
        print_err("start disk check thread fail");
        exit(0);  //关键线程 必须起来 否则可能会导致磁盘爆满
    }
    return 0;
}
