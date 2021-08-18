/*******************************************************************************************
 * *文件:    check_log.h
 * *描述:    任务实现
 * *
 * *作者:    李亚洲
 * *日期:    2020-08-08
 * *修改:    创建文件                ------>     2020-08-08
 * *修改:    修改记录日志空间文件目录 ------>     2020-10-30
 * *
 * *******************************************************************************************/
#ifndef __CHECK_LOG_H__
#define __CHECK_LOG_H__

#include "datatype.h"
#include "stringex.h"
#include "debugout.h"
#include "fileoperator.h"


#ifdef __cplusplus
extern "C" {
#endif
//#define CHECKLOG_MAX     6      //最大天数168/24=7
#define CHECKLOG_MAX     168      //最大天数168/24=7

#define CHECKLOG_FILE "/etc/init.d/checklog.cfg"
#define CHECKLOG_DIST_FILE "/initrd/abin/distinfo"
//#define CHECKLOG_ONE_HOUR_TIME 10
#define CHECKLOG_ONE_HOUR_TIME 60 * 60
#define CHECKLOG_DEFAULT_DAY 180

typedef struct _check_log {

    int32 check_log_count;
    int64 start_time;
    int64 start_size;
    int64 update_time;
    int32 success_flag;
    int64 end_size;
    int64 end_time;
} check_log, *pcheck_log;

void check_log_size(check_log check_data, bool last_data);
int64 check_log_get_average(pcheck_log list, uint32 len);
int64 check_log_get_avail_size(bool is_num, pchar buff, uint32 buff_len);

#ifdef __cplusplus
}
#endif

#endif


