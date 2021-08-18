/*******************************************************************************************
*文件:    main.cpp
*描述:    check_log
*
*作者:    李亚洲
*日期:    2020-08-08
*修改:    创建文件                            ------>     2020-08-08
*修改:    修复日志空间初始值                  ------>     2020-11-19
*修改:    延长检测频率                        ------>     2021-02-05
*         可以设置线程名称                     ------>     2021-02-23
*******************************************************************************************/
#include "datatype.h"
#include "debugout.h"
#include "check_log.h"
#include "fileoperator.h"
#include "sysdir.h"
#include "FCLogManage.h"

static pchar VersionNO = "2.0.1";     //版本号,尾号为偶数表示正式版本，奇数为测试

//读取配置文件信息
static int32 get_check_info(pcheck_log check_data, pchar cfg = CHECKLOG_FILE);
//读取配置文件信息
static int32 get_check_list(pcheck_log list, pchar cfg = CHECKLOG_FILE);
//检测日志空间线程
static void *check_log_space(void *arg);
//计算日志存储还剩余天数
static void *get_log_day(void *arg);
_log_preinit_(glog_p);

//---------------------------------------------------------------
int main (int argc, char  *argv[])
{
    _log_init_(glog_p, checklog);
    pthread_t tid_s = 0, tid_d = 0;
    //log空间统计
    if (pthread_create(&tid_s, NULL, check_log_space, NULL) != 0) {
        PRINT_ERR_HEAD;
        print_err("check log  create failed!!");
    }
    //log计算剩余天数
    if (pthread_create(&tid_d, NULL, get_log_day, NULL) != 0) {
        PRINT_ERR_HEAD;
        print_err("check log  create failed!!");
    }
    pthread_join(tid_s, NULL);
    pthread_join(tid_d, NULL);
finish:
    PRINT_ERR_HEAD;
    print_err("check_log EXIT!");

    _log_finish_(glog_p);
    return 1;
}
/*******************************************************************************************
*功能:    读取配置文件信息
*参数:    check_data          ---->   数据信息指针
*         cfg                 ---->   配置文件路径
*         返回值              ---->   当前任务个数
*
*注释:
*******************************************************************************************/
static int32 get_check_info(pcheck_log check_data, pchar cfg)
{
    pchar SYSROOT[3] = {"SYS", "COUNT", "TMPCOUNT"};
    pchar TASKCFG = "CHECKOUT_";

    //声明文件相关操作函数
    CFILEOP file;
    int32 checkcnt = 0, tmpcnt = 0;
    char tasktmp[64];
    int32 err = 0;

    if (check_data == NULL)    return -1;

    //打开系统配置文件文件
    if (file.OpenFile((char *)cfg, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("get_check_info OPEN CFG(%s) ERROR!!", cfg);
        return 0;
    }

    //读取任务数
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&checkcnt);
    if (checkcnt >= CHECKLOG_MAX) {
        PRINT_INFO_HEAD;
        print_info("get_check_info TASK IS OVERFLOW, CFG = %d", checkcnt);
        checkcnt = 0;

    }
    
    //读取临时任务数
    if (file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[2], (int *)&tmpcnt) > 0) {
        checkcnt = tmpcnt;
    }
    //读取最新一次数据
    int32 tmp;
    char idtmp[64] = {0};

    sprintf(tasktmp, "%s%d", TASKCFG, checkcnt); //读取最新一次数据

    file.ReadCfgFile(tasktmp, "START_TIME", idtmp, sizeof(idtmp));
    check_data->start_time = atoll(idtmp);
    file.ReadCfgFile(tasktmp, "START_SIZE", idtmp, sizeof(idtmp));
    check_data->start_size = atoll(idtmp);
    file.ReadCfgFile(tasktmp, "UPDATE_TIME", idtmp, sizeof(idtmp));
    check_data->update_time = atoll(idtmp);

    file.ReadCfgFile(tasktmp, "SUCCESS", idtmp, sizeof(idtmp));
    check_data->success_flag = atoll(idtmp);

    tmp = -1;
    file.ReadCfgFileInt(tasktmp, "SUCCESS", (int *)&tmp);
    if (tmp == -1) check_data->success_flag = 0;
    else check_data->success_flag = (uint32)tmp;

    file.ReadCfgFile(tasktmp, "END_SIZE", idtmp, sizeof(idtmp));
    check_data->end_size = atoll(idtmp);
    file.ReadCfgFile(tasktmp, "END_TIME", idtmp, sizeof(idtmp));
    check_data->end_time = atoll(idtmp);

    file.CloseFile();

    return checkcnt;
}
/*******************************************************************************************
*功能:    读取配置文件信息
*参数:    list                ---->   数据列表
*         cfg                 ---->   配置文件路径
*         返回值              ---->   当前任务个数
*
*注释:
*******************************************************************************************/
static int32 get_check_list(pcheck_log list, pchar cfg)
{
    pchar SYSROOT[2] = {"SYS", "COUNT"};
    pchar TASKCFG = "CHECKOUT_";

    CFILEOP file;
    int32 checkcnt = 0;
    char tasktmp[64];
    int32 err = 0;

    if (list == NULL)    return -1;

    if (file.OpenFile((char *)cfg, "rb", true) == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("get_check_list OPEN CFG(%s) ERROR!!", cfg);
        return 0;
    }

    //读取任务数
    file.ReadCfgFileInt((char *)SYSROOT[0], (char *)SYSROOT[1], (int *)&checkcnt);
    if (checkcnt > CHECKLOG_MAX) {
        PRINT_INFO_HEAD;
        print_info("get_check_list TASK IS OVERFLOW, CFG = %d", checkcnt);
        checkcnt = CHECKLOG_MAX;

    }

    //读取最新一次数据
    int32 tmp;
    char idtmp[64] = {0};
    for (int i = 0; i < checkcnt; i++) {

        sprintf(tasktmp, "%s%d", TASKCFG, i);

        file.ReadCfgFile(tasktmp, "START_TIME", idtmp, sizeof(idtmp));
        list[i].start_time = atoll(idtmp);
        file.ReadCfgFile(tasktmp, "START_SIZE", idtmp, sizeof(idtmp));
        list[i].start_size = atoll(idtmp);
        file.ReadCfgFile(tasktmp, "UPDATE_TIME", idtmp, sizeof(idtmp));
        list[i].update_time = atoll(idtmp);

        file.ReadCfgFile(tasktmp, "SUCCESS", idtmp, sizeof(idtmp));
        list[i].success_flag = atoll(idtmp);

        tmp = -1;
        file.ReadCfgFileInt(tasktmp, "SUCCESS", (int *)&tmp);
        if (tmp == -1) list[i].success_flag = 0;
        else list[i].success_flag = (uint32)tmp;

        file.ReadCfgFile(tasktmp, "END_SIZE", idtmp, sizeof(idtmp));
        list[i].end_size = atoll(idtmp);
        file.ReadCfgFile(tasktmp, "END_TIME", idtmp, sizeof(idtmp));
        list[i].end_time = atoll(idtmp);
    }

    file.CloseFile();

    return checkcnt;
}
/*******************************************************************************************
*功能:    检测日志空间线程
*参数:    arg          ---->   线程参数
*
*注释:
*******************************************************************************************/
static void *check_log_space(void *arg)
{
    pthread_setname("");
    check_log current_data;  //结构体
    int32 count = 0;
    bool last = true;

    memset(&current_data, 0, sizeof(current_data));

    //count == 小时总数
    //把配置文件中的信息读到结构体中
    count = get_check_info(&current_data);
    current_data.check_log_count = count;
    while (1) {
        //任务数 > 最大天数168/24=7
        if (count >= CHECKLOG_MAX) {
            PRINT_DBG_HEAD;
            print_dbg("log check time 7 day");
            current_data.check_log_count = 0; //循环记录最近7天的log空间数据
        }
        if ((current_data.start_time || current_data.success_flag) && last) {
            //实时检测日志空间 每十秒获取一次，退出循环为1小时
            check_log_size(current_data, true);
            current_data.check_log_count++;
            last = false;
        } else {
            check_log_size(current_data, false);
            current_data.check_log_count++;
        }
        count = current_data.check_log_count;
    }
}
/*******************************************************************************************
*功能:    计算日志存储还剩余天数
*参数:    arg          ---->   线程参数
*
*注释:
*******************************************************************************************/
static void *get_log_day(void *arg)
{
    pthread_setname("");
    check_log check_list[CHECKLOG_MAX];
    int32 count = 0;
    char cmd[255] = {0}, buff[64] = {0};
    int64 average_size = 0, avail_size = 0;
    memset(check_list, 0, sizeof(check_list));
    uint32 day = 0;

    //初始化显示默认值
    check_log_get_avail_size(false, buff, sizeof(buff));
    sprintf(cmd, "echo  \"%s,%d,%d\" > %s", buff, CHECKLOG_DEFAULT_DAY, CHECKLOG_MAX, CHECKLOG_DIST_FILE);
    system(cmd);

    while (1) {
        //每更新一次数据放入链表中
        count = get_check_list(check_list);
        if (count <= 0) {
            PRINT_DBG_HEAD;
            print_dbg("get list count <= 0");
            usleep(10 * 1000 * 1000);
            continue;
        }

        //计算平均每一天日志量
        average_size = check_log_get_average(check_list, count);
        if (average_size <= 0) {
            average_size = 1;
        }

        //剩余日志空间大小
        avail_size = check_log_get_avail_size(true, buff, sizeof(buff));

        PRINT_DBG_HEAD;
        print_dbg("average_size:%lld avail_size:%lld", average_size, avail_size);
        
        //日志存储还剩余天数
        day = avail_size / average_size;
        if (day > CHECKLOG_DEFAULT_DAY) {
            day = CHECKLOG_DEFAULT_DAY;
        }
        check_log_get_avail_size(false, buff, sizeof(buff));
        //显示剩余空间大小 剩余使用天数 还有任务个数
        sprintf(cmd, "echo  \"%s,%d,%d\" > %s", buff, day, count, CHECKLOG_DIST_FILE);
        system(cmd);
        usleep(10 * 1000 * 1000);
    }
}
