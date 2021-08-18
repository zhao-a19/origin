/*******************************************************************************************
 * *文件:    dbsync_task.h
 * *描述:    任务实现
 * *
 * *作者:    李亚洲
 * *日期:    2020-07-24
 * *修改:    创建文件                ------>     2020-07-24
 *           修改后端接口            ------>     2020-09-20
 * *         存放数据库密码的空间由64改为512 ------> 2021-03-21 wjl
 * *******************************************************************************************/
#ifndef __DBSYNC_TASK_H__
#define __DBSYNC_TASK_H__

#include "datatype.h"
#include "stringex.h"
#include "cJSON.h"
#include "debugout.h"
#include "FCLogManage.h"
#include "filename.h"
#include "sysdir.h"
#include "log_translate.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif
#define DBSYNC_TASKMAX     100      //支持的最大用户数
#define DBSYNC_FILTERMAX   500     //忽略文件后缀字符最大数
#define DBSYNC_HTTPBUF_MAX 20480
#define DBSYNC_TABLES_MAX  20480
#define DBSYNC_TABLES_NUM 1024 //同步tables最大值1024

#define DBSYNC_TASK_DEFAULT -1
#define DBSYNC_TASK_DEL 0
#define DBSYNC_TASK_START 1
#define DBSYNC_TASK_STOP 2

#define DBSYNC_TASK_SUCCESS 0
#define DBSYNC_TASK_FAILED -1


/**
 * 后台字符集
 */
#define DBSYNC_CHARSET_UTF8   "utf-8"
#define DBSYNC_UPDATE_URL "http://%d.0.0.254:8081/web/updateStrategy"
#define DBSYNC_TIME_URL "http://%d.0.0.254:8081/web/setTask"
#define DBSYNC_SETLOG_URL "http://%d.0.0.254:8081/web/setLogSwitch"
#define DBSYNC_STATUS_URL "http://%d.0.0.254:8081/web/status"
#define DBSYNC_STARTALL_URL "http://%d.0.0.254:8081/web/startAllStartegy"
#define DBSYNC_STOPALL_URL "http://%d.0.0.254:8081/web/stopAllStrategy"

#define DBConfigFile "/var/self/rules/precfg/PREDBSYNC"
#define DBConfigFileBak "/initrd/abin/PREDBSYNC-bak"
#define DBConfigFileTmp "/initrd/abin/PREDBSYNC-tmp"
#define SYSFile "/var/self/rules/conf/sysset.cf" // LogType sys RecordLog 策略
//mode参数
typedef enum {
    DBSYNC_TASKOUTER = 1,      //外网通讯
    DBSYNC_TASKINNER           //内网通讯
} DBSYNCMODE;

//dbsync_ctrl参数
#define set_dbsyncctrl(task,b) ((task).dbsync_ctrl |= (b))
#define clr_dbsyncctrl(task,b) ((task).dbsync_ctrl &= (~(b)))

#define DBSYNC_CTRL_USE        (1uL<<0)    //策略使用中
#define is_endbsyncuse(task)   ((bool)((task).dbsync_ctrl&DBSYNC_CTRL_USE))
#define en_dbsyncuse(task)     set_dbsyncctrl(task, DBSYNC_CTRL_USE)
#define dis_dbsyncuse(task)    clr_dbsyncctrl(task, DBSYNC_CTRL_USE)

#define DBSYNC_CTRL_INSERT     (1uL<<1)    //新增策略
#define is_endbsyncinsert(task)   ((bool)((task).dbsync_ctrl&DBSYNC_CTRL_INSERT))
#define en_dbsyncinsert(task)     set_dbsyncctrl(task, DBSYNC_CTRL_INSERT)
#define dis_dnsyncinsert(task)    clr_dbsyncctrl(task, DBSYNC_CTRL_INSERT)

#define DBSYNC_CTRL_UPDATE     (1uL<<2)    //修改策略
#define is_endbsyncupdate(task)   ((bool)((task).dbsync_ctrl&DBSYNC_CTRL_UPDATE))
#define en_dbsyncupdate(task)     set_dbsyncctrl(task, DBSYNC_CTRL_UPDATE)
#define dis_dbsyncupdate(task)    clr_dbsyncctrl(task, DBSYNC_CTRL_UPDATE)

#define DBSYNC_CTRL_SUCCESS     (1uL<<3)    //策略是否成功
#define is_endbsyncsuccess(task)   ((bool)((task).dbsync_ctrl&DBSYNC_CTRL_SUCCESS))
#define en_dbsyncsuccess(task)     set_dbsyncctrl(task, DBSYNC_CTRL_SUCCESS)
#define dis_dbsyncsuccess(task)    clr_dbsyncctrl(task, DBSYNC_CTRL_SUCCESS)

#define DBSYNC_FREE(param) { \
                   if (param != NULL) { \
                        free(param); \
                        param = NULL;\
                    } \
                }

/*
老版本数据库表信息

*/
typedef struct _dbsync_table {
    char SrcTblName[64];
    char SrcField[512];
    char SrcKey[64];
    char DstTblName[64];
    char DstField[512];
    char DstKey[64];
    char Filter[64];
    char CKInsert[10];
    char CKUpdate[10];
    char CKDelete[10];
    char CKCopy[64];
    char CKTmpTbl[64];
    char CKTrigger[64];
    char CKUpsert[64];
} dbsync_table, *pdbsync_table;

/*
PF任务初始化参数，

*/
typedef struct _dbsync_task {

    char name[100];   
    uint64 id;
    char sdbtype[64];
    char sdbcharset[64];
    char sdatabase[64];
    char sdbmsip[64];
    uint32 sport;
    char susername[64];
    char spassword[512];
    char tdbtype[64];
    char tdbcharset[64];
    char tdatabase[64];
    char tdbmsip[64];
    uint32 tport;
    char tusername[64];
    char tpassword[512];

    uint32 direction;   //方向
    uint32 doublesided; //双向
    uint32 tmptable;    //临时表
    uint32 enable;      //开启
    char *tables[DBSYNC_TABLES_NUM];
    uint32 tables_num;  //表的数目

    uint32 dbsync_ctrl;
    uint32 bak_num;
    pthread_t tid;
    bool update_flag;
    uint32 thread_num;   //线程数
    uint32 task_num;    //任务数

    char sowner[64];
    char objalias[64];
    char towner[64];
    char tempTableName[64];
    pdbsync_table table;
} dbsync_task, *pdbsync_task;
/*
定时人数数据
*/
typedef struct _dbsync_time {
    uint32 chsyncday;
    uint32 syncspe;
    char sysnctimer[64];
} dbsync_time, *pdbsync_time;

/*
是否开启日志数据

*/
typedef struct _dbsync_log {
    int32 syslog;
    int32 userlog;
} dbsync_log, *pdbsync_log;
/*******************************************************************************************
*功能:    策略处理
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    timre          定时任务信息
*    返回值  成功(DBSYNC_TASK_SUCCESS) 失败(DBSYNC_TASK_FAILED)
*注释:
*******************************************************************************************/
bool dbsync_task_check(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, dbsync_time timer);
/*******************************************************************************************
*功能:    更新源文件策略信息
* 参数：
*    taskcnt        新策略个数
*    tasks          新策略列表
*    cfg            文件名字
*    返回值  成功(0) 失败(-1)
*注释:
*******************************************************************************************/
int32 dbsync_update_taskinfo(int32 taskcnt, pdbsync_task tasks, pchar cfg = DBConfigFile);
/*******************************************************************************************
*功能:   备份策略信息
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    bakfile        备份策略成功信息文件
*    返回值          0成功 -1失败
*注释:
*******************************************************************************************/
int32 dbsync_back_task_info(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, pchar bakfile);
/*******************************************************************************************
*功能:    策略处理 线程
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    timre          定时任务信息
*    thread_num     开启线程个数
*    返回值  成功(DBSYNC_TASK_SUCCESS) 失败(DBSYNC_TASK_FAILED) 目前不使用
*注释:
*******************************************************************************************/
bool dbsync_task_check_thread(int32 taskcnt, pdbsync_task tasks, int32 taskcnt_bak, pdbsync_task tasks_bak, dbsync_time timer, uint32 thread_num);
/*******************************************************************************************
*功能:    设置日志是否开启
*参数:
*    logdata   日志参数
*注释:
*******************************************************************************************/
void dbsync_set_log(dbsync_log logdata);
/*******************************************************************************************
*功能:    服务状态
*注释:
*******************************************************************************************/
void dbsync_status(void);
/*******************************************************************************************
*功能:   备份策略信息
*参数:
*    taskcnt        新策略个数
*    tasks          新策略列表
*    taskcnt_bak    旧策略个数
*    tasks_bak      旧策略列表
*    bakfile        备份策略成功信息文件
*    返回值          0成功 -1失败
*注释:
*******************************************************************************************/
int32 dbsync_back_task_info_old(int32 taskcnt, pdbsync_task tasks, dbsync_time timer, pchar bakfile);
#ifdef __cplusplus
}
#endif

#endif


