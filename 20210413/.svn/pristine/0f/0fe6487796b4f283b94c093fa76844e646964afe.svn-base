/*******************************************************************************************
*文件:    task_manager.cpp
*描述:    任务管理模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10
1.简化网络异常检测逻辑                                         ------> 2020-03-05
*
*******************************************************************************************/
#include "task_manage.h"
#include "common_func.h"
#include "connect_manage.h"

/*******************************************************************************************
*功能:      获取服务器规则信息
*参数:      rule               ----> 规则
*           over_pid           ----> 异常结束进程id
*                    
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int reload_over_task(fs_rule_t *rule, pid_t over_pid) {

    pid_t tmp_pid = 0;
    for (int i = 0; i < rule[i].task_count; i++) {
        if (rule[i].task_pid == over_pid) {
            PRINT_ERR_HEAD;
            print_err("group = [TASK%d] ,task name = %s is over !", i, rule[i].task_name);
            rule[i].del_record = FSYNC_TURN_OFF;
            tmp_pid = fork();
            if (tmp_pid < 0) {
                PRINT_ERR_HEAD;
                print_err("reload group = [TASK%d] child process failed !", i);
                return -1;
            } else if (tmp_pid == 0) {
                create_task(&(rule[i]));
                exit(0);
            } else {
                rule[i].task_pid = tmp_pid;
                PRINT_INFO_HEAD;
                print_info("reload group = [TASK%d] ,task name = %s success ,new pid = %u", rule[i].task_id,
                           rule[i].task_name, rule[i].task_pid);
                break;
            }
        }
    }


    return 0;
}

bool check_process_stat(fs_rule_t *rule, int check_times) {

    for (int i = 0; i < check_times * 10; ++i) {
        if (rule->task_stat == FSYNC_QUIT_NOW) {
            PRINT_INFO_HEAD;
            print_info("[TASK%d] is over !", rule->task_id);
            return false;
        }
        usleep(100000);
    }

    return true;
}

/*******************************************************************************************
*功能:      任务监控
*参数:       send_rule               ----> 发送信息 
*                    
*           返回值                   ----> 
*
*注释:
*******************************************************************************************/
void *task_monitor(void *send_rule) {

    bool bret = false;
    struct timeval old_stat;
    fs_send_t *send_msg = (fs_send_t *) send_rule;
    fs_rule_t *rule = send_msg->rule;
    CLOGMANAGE web_log;
    web_log.Init(rule->syslog_flag);
    int send_block_times = 0;
    int scan_block_times = 0;

    while (1) {
        while (g_async_queue_length_unlocked(send_msg->ready_queue) > (0 - rule->pthread_count)) {
            if (memcmp(&old_stat, send_msg->work_stat, sizeof(old_stat)) == 0) {
                send_block_times++;
                PRINT_INFO_HEAD;
                print_info("[TASK%d] read write block %d times !", rule->task_id, send_block_times);
            } else {
                mempcpy(&old_stat, send_msg->work_stat, sizeof(old_stat));
                send_block_times = 0;
                PRINT_DBG_HEAD;
                print_dbg("[TASK%d] read write work normal !", rule->task_id);
            }
            if (send_block_times > FSYNC_BLOCK_MAX_TIMES) {
                if (rule->log_flag == FSYNC_TURN_ON) {
                    web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip,
                                             rule->out_srv.real_ip, rule->int_srv.sub_path, rule->out_srv.sub_path, "",
                                             S_FAILED, RW_FAILED, false);
                    web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip,
                                             rule->out_srv.real_ip, rule->out_srv.sub_path, rule->int_srv.sub_path, "",
                                             S_FAILED, RW_FAILED, true);
                }
                PRINT_ERR_HEAD;
                print_err("[TASK%d] read write is block !", rule->task_id);
                goto _exit;
            }
            if (!check_process_stat(rule, FSYNC_MONITOR_TIME)) {
                goto _exit;
            }
        }

        bret = check_all_internet(rule);
        if (!bret) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d]  connect unreachable !", rule->task_id);
            goto _exit;
        }

        if (memcmp(&old_stat, send_msg->work_stat, sizeof(old_stat)) == 0) {
            scan_block_times++;
        } else {
            mempcpy(&old_stat, send_msg->work_stat, sizeof(old_stat));
            scan_block_times = 0;
        }
        if (scan_block_times > ((600 + rule->scan_time + rule->delay_time) / FSYNC_MONITOR_TIME)) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d]  scan mod is block !", rule->task_id);
            goto _exit;
        }


        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] connect is working normal !", rule->task_id);
        if (!check_process_stat(rule, FSYNC_MONITOR_TIME)) {
            goto _exit;
        }
    }

    _exit:

    return NULL;
};