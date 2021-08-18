/*******************************************************************************************
*文件:    check_log.cpp
*描述:
*
*作者:    李亚洲
*日期:    2020-08-08
*修改:    创建文件                          ------>     2020-08-08
*******************************************************************************************/
#include "check_log.h"
#include "sysdir.h"

/*******************************************************************************************
*功能:    获取日志使用空间大小
*
*返回值   空间大小
*
*注释:
*******************************************************************************************/
int64 check_log_get_use_size(void)
{
    uint64 size = 0;
    char cmd[255] = {0};
    char buff[64] = {0};
    snprintf(cmd, sizeof(cmd) - 1, "df %s|grep -v File | awk '{print $3}'", ModleDIR[0].path);
    sysinfo(cmd, buff, sizeof(buff));
    if (buff[0] != '\0') {
        size = atoll(buff);
        if (buff[strlen(buff) - 1] == 'G' || buff[strlen(buff) - 1] == 'g' ) {
            size = size * 1024 * 1024;
        } else if (buff[strlen(buff) - 1 ] == 'M' || buff[strlen(buff) - 1 ] == 'm' ) {
            size = size * 1024;
        }
    }
    return size;
}
/*******************************************************************************************
*功能:    剩余日志空间大小
*参数:    is_num          ---->   是否获取空间大小 true获取数字 false 获取空间大小字符串
          buff            ---->   返回数据buff
          buff_len        ---->   空间长度
*返回值   空间大小
*
*注释:
*******************************************************************************************/
int64 check_log_get_avail_size(bool is_num, pchar buff, uint32 buff_len)
{
    uint64 size = 0;
    char cmd[255] = {0};
    //获取文件磁盘使用情况
    snprintf(cmd, sizeof(cmd) - 1, "df -h %s|grep -v File | awk '{print $4}'", ModleDIR[0].path);
    sysinfo(cmd, buff, buff_len);
    if (is_num && buff[0] != '\0') {
        //转换出longlong类型的数据，内容为文件大小
        size = atoll(buff);
        if (buff[strlen(buff) - 1] == 'G' || buff[strlen(buff) - 1] == 'g' ) {
            size = size * 1024 * 1024;
        } else if (buff[strlen(buff) - 1] == 'M' || buff[strlen(buff) - 1] == 'm' ) {
            size = size * 1024;
        }
    }
    return size;
}
/*******************************************************************************************
*功能:    记录每一小时空间使用情况
*参数:    check_data          ---->   每一时刻空间使用信息
          first               ---->   是否第一次记录
          flag                ---->   数据信息是否记录完成
          filepath            ---->   存储数据文件地址
*返回值   -1 失败 0 成功
*
*注释:
*******************************************************************************************/
static int32 write_log_info(check_log check_data, bool first, bool flag, pchar filepath = CHECKLOG_FILE)
{
    time_t t = 0;
    CFILEOP file;
    pchar SYSROOT[3] = {"SYS", "COUNT", "TMPCOUNT"};
    pchar TASKCFG = "CHECKOUT_";
    char tasktmp[64] = {0};
    uint32 checkcnt = 0;

    t = time(NULL);
    //当前时间
    check_data.update_time = t;
    //打开文件
    if (file.OpenFile(filepath, "wb") == E_FILE_FALSE) {
        PRINT_ERR_HEAD;
        print_err("write_log_info CFG(%s) ERROR!!", filepath);
        return -1;
    }

    char tmp[64] = {0};
    sprintf(tasktmp, "%s%d", TASKCFG, check_data.check_log_count);
    sprintf(tmp, "%lld", t);
    //当前时间写入配置文件
    file.WriteCfgFile(tasktmp, "UPDATE_TIME", tmp);

    //结束空间大小写入配置文件
    sprintf(tmp, "%lld", check_data.end_size);
    file.WriteCfgFile(tasktmp, "END_SIZE", tmp);

    if (flag) {
        //更改标志位， 记录结束时间
        file.WriteCfgFileInt(tasktmp, "SUCCESS", 1);
        sprintf(tmp, "%lld", t);
        file.WriteCfgFile(tasktmp, "END_TIME", tmp);
        file.ReadCfgFileInt(SYSROOT[0], SYSROOT[1], (int *)&checkcnt);
        if (checkcnt <  CHECKLOG_MAX) { //循环记录log空间数据
            file.WriteCfgFileInt(SYSROOT[0], SYSROOT[1], check_data.check_log_count + 1);
        } else {
            file.WriteCfgFileInt(SYSROOT[0], SYSROOT[2], check_data.check_log_count + 1);
        }
    }
    //第一次记录
    if (first) {
        //记录开始时间和开始大小
        sprintf(tmp, "%lld", check_data.start_time);
        file.WriteCfgFile(tasktmp, "START_TIME", tmp);
        sprintf(tmp, "%lld", check_data.start_size);
        file.WriteCfgFile(tasktmp, "START_SIZE", tmp);
    }

    file.WriteFileEnd();
    return 0;
}
/*******************************************************************************************
*功能:    实时检测日志空间
*参数:    check_data          ---->   每一时刻空间使用信息
          last_data           ---->   上一次中断信息
*
*注释:
*******************************************************************************************/
void check_log_size(check_log check_data, bool last_data)
{
    int64 time_tmp = 0;
    char buff[64] = {0};
    if (last_data) {
        time_tmp = CHECKLOG_ONE_HOUR_TIME - (check_data.update_time - check_data.start_time);
        //更新开始时间防止update time 和start time 记录有误
        check_data.start_time = time(NULL) - (check_data.update_time - check_data.start_time);
        //将结构体中的信息写入日志
        write_log_info(check_data, true, false);

        while (time_tmp > 0) {
            //获取日志使用空间大小
            check_data.end_size = check_log_get_use_size();
            write_log_info(check_data, false, false);
            usleep(10 * 1000 * 1000);
            time_tmp -= 10;
        }
        write_log_info(check_data, false, true);
    } else {
        time_tmp = CHECKLOG_ONE_HOUR_TIME;
        check_data.start_time = time(NULL);
        check_data.start_size = check_log_get_use_size();
        while (time_tmp > 0) {
            check_data.end_size = check_log_get_use_size();
            write_log_info(check_data, true, false);
            usleep(10 * 1000 * 1000);
            time_tmp -= 10;
        }
        write_log_info(check_data, true, true);
    }
}
/*******************************************************************************************
*功能:    计算平均每一天日志量
*参数:    list          ---->   数据链表
          len           ---->   数据链表个数
*返回值   平均每一天日志量
*
*注释:
*******************************************************************************************/
int64 check_log_get_average(pcheck_log list, uint32 len)
{
    int64 sum_size = 0;
    for (int i = 0; i < len; i++) {
        int64 tmp = (list[i].end_size - list[i].start_size);
        sum_size += tmp >= 0 ? tmp : 0;
    }
    return sum_size / len * 24;
}
