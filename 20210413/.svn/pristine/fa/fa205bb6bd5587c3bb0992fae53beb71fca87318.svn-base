/*******************************************************************************************
*文件:    file_sync.cpp
*描述:    文件同步模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------> 2019-11-10
*1.合并差异化扫描函数。                                        ------> 2020-02-24
*2.修改单向删除源文件及目录策略下的扫描逻辑漏洞                ------> 2020-02-26
*3.增加挂载状态检测逻辑                                        ------> 2020-03-01
*4.分离写日志与文件发送的逻辑                                  ------> 2020-03-03
*5.封装全量扫描与增量扫描                                      ------> 2020-03-05
*6.文件发送前进行挂载状态检测                                  ------> 2020-03-05
*7.添加文件传输完成重命名后校验文件大小,文件重命名逻辑修改     ------> 2020-03-10
*8.只在单项不启用删除和双向不启用删除策略下进入增量扫描逻辑    ------> 2020-03-13
*9 优化任务方向判别，扫描即赋值。合并传输结束目录处理列表。    ------> 2020-03-13
*10.传输任务类型加入结构体，文件传输不再更新目录               ------> 2020-03-17
*11.发送列表改为计数器，双向删除文件函数去除目录增改操作       ------> 2020-03-18
*12.修改性能模式下，文件扫描bug                                ------> 2020-03-31
*13.遍历哈希表时加锁                                           ------> 2020-08-03
*14.解决哈希表数据向链表拷贝时产生的段错误                     ------> 2020-08-03
*15.解决文件交换变量扫描，源端路径拼接错误引起的传输错误       ------> 2020-08-04
*16.单向传输，传输完删除源文件失败时，记录删除失败日志，无逻辑改动 ------> 2021-08-04
*17.双向传输，同步删除时，判断删除的返回值，删除失败记录失败日志   ------> 2021-08-04
*******************************************************************************************/

#include <pthread.h>
#include <signal.h>
#include <execinfo.h>

#include "file_sync.h"
#include "parse_conf.h"
#include "common_func.h"
#include "connect_manage.h"
#include "task_manage.h"
#include "utf8_code.h"
#include "ftp_sync.h"
#include "sftp_sync.h"
#include "ftps_sync.h"
#include "curl_sftp_sync.h"

#define DUMP_STACK_DEPTH_MAX   16

bool work_mod(fs_send_t *send_msg);

void *scan_mod(void *task_rule);

bool scan_all(fs_send_t *scan_msg, recorder_t *recorder);

bool scan_dir(bool in_to_out, fs_send_t *scan_msg, const char *dir_name);

void *sync_mod(void *send_rule);

bool get_new_task(fs_send_t *send_msg, fs_task_t **tmp_task, fs_sync_t *sync_info, fs_work_t *int_worker,
                  fs_work_t *out_worker, fs_work_t *intbak_worker, fs_work_t *outbak_worker);

bool get_target_path(const fs_rule_t *rule, fs_sync_t *sync_info);

bool check_update(fs_work_t *worker, fs_task_t *tmp_task, struct stat *stat_buf);

int sync_dir(fs_send_t *send_msg, fs_sync_t *sync_info, fs_log_t *log_info, recorder_t *recorder, CLOGMANAGE *web_log);

int sync_file(fs_send_t *send_msg, fs_sync_t *sync_info, fs_log_t *log_info, recorder_t *recorder, CLOGMANAGE *web_log);


bool check_file_change(int file_type, recorder_t *recorder, const char *path_name, unsigned long file_size,
                       unsigned long file_time, const char *user, int *row_num, char *remark = NULL);

int check_virus_file(fs_rule_t *rule, recorder_t *recorder, const char *file_name, struct stat *file_stat,
                     char *virus_name);

bool check_dir_change(int file_type, recorder_t *recorder, const char *path_name, const char *user, int *row_num);

int one_way_dir_sync(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder);

int both_way_dir_sync(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder);

int both_way_check_file(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int target_row);

bool
both_way_file_over(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int source_row, int target_row);

bool one_way_file_over(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int source_row, fs_log_t *log_info, CLOGMANAGE *web_log);

bool add_dir_change(fs_work_t *worker, bool is_add, bool in_to_out, const char *dir_path, GHashTable *dir_hash_table,
                    pthread_mutex_t *dir_hash_mut, struct stat *dir_stat);


bool
change_dir_record(fs_rule_t *rule, recorder_t *recorder, GHashTable *dir_hash_table, pthread_mutex_t *dir_hash_mut);

bool is_clean_table(fs_rule_t *rule);

bool rewrite_record_file(fs_rule_t *rule);

bool make_log_info(fs_rule_t *rule, fs_sync_t *sync_info, fs_log_t *log_info);

fs_work_t *create_worker_obj(int protocol);

bool connect_all_server(fs_rule_t *rule, fs_work_t *int_obj, fs_work_t *out_obj, fs_work_t *intbak_obj,
                        fs_work_t *outbak_obj);


void close_all_server(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                      fs_work_t *outbak_worker);

bool create_all_data_connect(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                             fs_work_t *outbak_worker);

bool check_all_server(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                      fs_work_t *outbak_worker);

bool check_all_path(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                    fs_work_t *outbak_worker);

bool make_tmp_name(bool is_make_tmp_file, fs_rule_t *rule, fs_sync_t *sync_info, fs_work_t *dst_worker,
                   char *tmp_dst_file, fs_work_t *bak_worker, char *tmp_bak_file);

bool copy_file(bool in_to_out, fs_send_t *send_msg, CLOGMANAGE *web_log, fs_log_t *log_info, fs_work_t *src_worker,
               const char *src_file, struct stat *src_stat, fs_work_t *dst_worker, const char *dst_file,
               fs_work_t *bak_worker, const char *bak_file);

bool curl_copy_file(bool in_to_out, fs_send_t *send_msg, CLOGMANAGE *web_log, fs_log_t *log_info, fs_work_t *src_worker,
                    const char *src_file, struct stat *src_stat, fs_work_t *dst_worker, const char *dst_file,
                    fs_work_t *bak_worker, const char *bak_file);

void umount_local_path(fs_rule_t *rule);

fs_rule_t *fsync_rule;

static pthread_mutex_t *lock_cs;
static long *lock_count;

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long) pthread_self());
}

void thread_setup(void)
{
    int i;

    lock_cs = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = (long *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);

}

/*******************************************************************************************
*功能:      打印栈信息
*参数:      stack_file_fd       ----> 输出文件描述符
*
*           返回值              ---->
*
*注释:
*******************************************************************************************/
void dump(FILE *stack_file_fd)
{
    void *stack_trace[DUMP_STACK_DEPTH_MAX] = {0};
    char **stack_strings = NULL;
    int stack_depth = 0;
    int i = 0;

    stack_depth = backtrace(stack_trace, DUMP_STACK_DEPTH_MAX);

    stack_strings = (char **) backtrace_symbols(stack_trace, stack_depth);
    if (stack_strings == NULL) {
        PRINT_ERR_HEAD;
        printf(" Memory is not enough while dump Stack Trace! ");
        return;
    }

    for (i = 0; i < stack_depth; ++i) {
        fwrite(stack_strings[i], sizeof(char), strlen(stack_strings[i]), stack_file_fd);
        fwrite("\r\n", sizeof(char), strlen("\r\n"), stack_file_fd);
    }

    free(stack_strings);
    stack_strings = NULL;

    return;
}

/*******************************************************************************************
*功能:      信号处理函数
*参数:      signo               ----> 信号
*
*           返回值              ---->
*
*注释:
*******************************************************************************************/
void signal_handler(int signo)
{
    char stack_info_path[FSYNC_PATH_MAX_LEN] = {0};
    char buf[FSYNC_PATH_MAX_LEN] = {0};
    mkdir_r(FSYNC_CONF_RECORD_PATH, 777);
    sprintf(stack_info_path, "%s%s", FSYNC_CONF_RECORD_PATH, FSYNC_STACK_INFO_NAME);

    FILE *stack_file_fd = fopen(stack_info_path, "w+");
    if (stack_file_fd == NULL) {
        PRINT_ERR_HEAD;
        print_err("open %s failed:%s", stack_info_path, strerror(errno));
    } else {
        sprintf(buf, "--------------------Dump stack start--------------------\n");
        fwrite(buf, sizeof(char), strlen(buf), stack_file_fd);

        //打印栈信息
        dump(stack_file_fd);

        //打印时间
        time_t local_time = time(NULL);
        sprintf(buf, "\ntime = %s", ctime(&local_time));
        fwrite(buf, sizeof(char), strlen(buf), stack_file_fd);

        //打印规则名称
        sprintf(buf, "task name = %s\n", fsync_rule->task_name);
        fwrite(buf, sizeof(char), strlen(buf), stack_file_fd);

        sprintf(buf, "--------------------Dump stack end--------------------\n");
        fwrite(buf, sizeof(char), strlen(buf), stack_file_fd);
        fclose(stack_file_fd);
    }
    exit(signo);
}

void block_signo(int signo)
{
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, signo);
    sigprocmask(SIG_BLOCK, &signal_mask, NULL);
}

void release_mount_path(int signum)
{

    fsync_rule->task_stat = FSYNC_QUIT_NOW;
    PRINT_INFO_HEAD;
    print_info("[TASK%d] recv signal = %d ", fsync_rule->task_id, signum);

}

/*******************************************************************************************
*功能:      创建任务
*参数:      rule               ----> 策略信息
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/

bool create_task(fs_rule_t *rule)
{

    fsync_rule = rule;
    block_signo(SIGPIPE); // 忽略掉SIGPIPE消息
    signal(SIGSEGV, signal_handler);
    signal(SIGTERM, release_mount_path);

    bool bret = false;
    fs_send_t send_msg;
    memset(&send_msg, 0, sizeof(send_msg));
    pthread_mutex_t dir_hash_mut = PTHREAD_MUTEX_INITIALIZER;
    struct timeval work_stat;

    send_msg.rule = rule;
    send_msg.ready_queue = g_async_queue_new();
    send_msg.dir_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
    send_msg.dir_hash_mut = &dir_hash_mut;
    send_msg.work_stat = &work_stat;

    if (rule->keyword_flag == FSYNC_TURN_ON) {
        read_keyword(FSYNC_KEYWORD_UTF_FILE_PATH, &(send_msg.keyword_list), UTF_CODE_TYPE);
        read_keyword(FSYNC_KEYWORD_GBK_FILE_PATH, &(send_msg.keyword_list), GBK_CODE_TYPE);
    }

    fs_work_t *int_obj = create_worker_obj(rule->int_srv.protocol);
    int_obj->init_worker_obj(int_obj, &rule->int_srv);
    fs_work_t *out_obj = create_worker_obj(rule->out_srv.protocol);
    out_obj->init_worker_obj(out_obj, &rule->out_srv);
    fs_work_t *intbak_obj = NULL;
    if (rule->int_bak_flag == FSYNC_TURN_ON) {
        intbak_obj = create_worker_obj(rule->int_bak.protocol);
        intbak_obj->init_worker_obj(intbak_obj, &rule->int_bak);
    }
    fs_work_t *outbak_obj = NULL;
    if (rule->out_bak_flag == FSYNC_TURN_ON) {
        outbak_obj = create_worker_obj(rule->out_bak.protocol);
        outbak_obj->init_worker_obj(outbak_obj, &rule->out_bak);
    }

    while (!bret) {              //网络检测
        bret = check_all_internet(rule);
        if (!bret) {
            sleep(FSYNC_RETRY_TIME);
        }
    }

    bret = false;
    while (!bret) {              //连接服务器
        bret = connect_all_server(rule, int_obj, out_obj, intbak_obj, outbak_obj);
        if (!bret) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d] mount/connect server failed !", rule->task_id);
            sleep(FSYNC_RETRY_TIME);
        }
    }

    bret = false;
    while (!bret) {              //同步路径检测
        bret = check_all_path(rule, int_obj, out_obj, intbak_obj, outbak_obj);
        if (!bret) {
            sleep(FSYNC_RETRY_TIME);
        }
    }

    if (bret) {                 //同步记录表清除
        is_clean_table(rule);
    }

    if (bret) {                   //策略记录写入
        rewrite_record_file(rule);
    }

    thread_setup();
    //进入工作模块
    bret = work_mod(&send_msg);
    if (!bret) {
        exit(-1);
    }

    //关闭不再使用的对象
    close_all_server(rule, int_obj, out_obj, intbak_obj, outbak_obj);

    //监测模块
    task_monitor((void *) &send_msg);
    thread_cleanup();

    sleep(1);

    umount_local_path(rule);

    return bret;
}


/*******************************************************************************************
*功能:       工作模块
*参数:       send_msg               ----> 发送信息
*
*           返回值                  ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool work_mod(fs_send_t *send_msg)
{
    int ret = 0;
    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
    if (send_msg->rule->keyword_flag == FSYNC_TURN_ON) {
        recorder->create_table(recorder, send_msg->rule->task_name, KEYWORD_FILE_TYPE);
    }
    if (send_msg->rule->virus_flag == FSYNC_TURN_ON) {
        recorder->create_table(recorder, send_msg->rule->task_name, VIRUS_FILE_TYPE);
    }

    if ((((fs_oneway_t *) (send_msg->rule->diff_info))->del_source != FSYNC_RM_ALL) ||
        (send_msg->rule->sync_area == FSYNC_BOTH_WAY)) {
        recorder->create_table(recorder, send_msg->rule->task_name, INT_FILE_TYPE);
        recorder->create_table(recorder, send_msg->rule->task_name, INT_DIR_TYPE);
        recorder->create_table(recorder, send_msg->rule->task_name, OUT_FILE_TYPE);
        recorder->create_table(recorder, send_msg->rule->task_name, OUT_DIR_TYPE);
    }
    recorder->close_db(recorder);

    pthread_t send_id = 0;
    for (int i = 0; i < send_msg->rule->pthread_count; i++) {
        ret = pthread_create(&send_id, NULL, sync_mod, (void *) send_msg);
        if (ret == 0) {
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] create send pthread success ,tid = %lu", send_msg->rule->task_id, send_id);
        } else {
            PRINT_ERR_HEAD;
            print_err("[TASK%d] create send pthread success failed:%s", send_msg->rule->task_id, strerror(ret));
            return false;
        }
    }

    pthread_t scan_id = 0;
    ret = pthread_create(&scan_id, NULL, scan_mod, (void *) send_msg);
    if (ret == 0) {
        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] create scan dir pthread success ,tid = %lu", send_msg->rule->task_id, scan_id);
    } else {
        PRINT_ERR_HEAD;
        print_err("[TASK%d] create scan dir pthread success failed:%s", send_msg->rule->task_id, strerror(ret));
        return false;
    }

    return true;
}

/*******************************************************************************************
*功能:      目录扫描模块
*参数:      task_rule           ----> 扫描信息
*
*           返回值              ----> NULL
*
*注释:
*******************************************************************************************/
void *scan_mod(void *task_rule)
{

    pthread_setself("scan_th");

    fs_send_t *scan_msg = (fs_send_t *) task_rule;
    int failed_times = 0;
    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);

    while (failed_times < FSYNC_RETRY_TIME) {
        if (scan_all(scan_msg, recorder)) {
            PRINT_DBG_HEAD;
            print_dbg("sleep %ds for next scan", scan_msg->rule->scan_time);
            failed_times = 0;
        } else {
            failed_times++;
        }
        sleep(scan_msg->rule->scan_time);

    }

    recorder->close_db(recorder);
    PRINT_ERR_HEAD;
    print_err("scan mod is failed %d time,will exit!", FSYNC_RETRY_TIME);
    sleep(FSYNC_BLOCK_MAX_TIMES);
    exit(-1);

}

/*******************************************************************************************
*功能:      目录全量扫描
*参数:      scan_msg                  ----> 扫描信息
*           recorder                  ----> 记录管理对象
*
*           返回值                    ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool scan_all(fs_send_t *scan_msg, recorder_t *recorder)
{

    fs_rule_t *rule = scan_msg->rule;

    bool bret = true;
    bool in_to_out = false;
    const char *dir_name = NULL;
    int del_flag = rule->sync_area == FSYNC_BOTH_WAY ? ((fs_bothway_t *) rule->diff_info)->sync_del
                   : ((fs_oneway_t *) rule->diff_info)->del_source;
    bool base_mod = (rule->sync_area != FSYNC_BOTH_WAY) && ((del_flag == FSYNC_RM_ALL) || (del_flag == FSYNC_RM_FILE));


    in_to_out = rule->sync_area == 0 ? true : false;  //双向模式下则为false,在下面双向逻辑中取反恢复为true


    if (rule->sync_area != FSYNC_BOTH_WAY) {
        gettimeofday(scan_msg->work_stat, NULL);
        dir_name = in_to_out ? rule->int_srv.scan_path : rule->out_srv.scan_path;
        bret = scan_dir(in_to_out, scan_msg, dir_name);

        if (!base_mod) {
            change_dir_record(rule, recorder, scan_msg->dir_hash_table, scan_msg->dir_hash_mut);
        }
    } else {
        for (int i = 0; i < 2; i++) {
            gettimeofday(scan_msg->work_stat, NULL);
            in_to_out = !in_to_out;
            dir_name = in_to_out ? rule->int_srv.scan_path : rule->out_srv.scan_path;
            bret = scan_dir(in_to_out, scan_msg, dir_name);

            if (!bret) {
                break;
            }
            change_dir_record(rule, recorder, scan_msg->dir_hash_table, scan_msg->dir_hash_mut);
            sleep(rule->scan_time);
        }
    }


    PRINT_DBG_HEAD;
    print_dbg("scan all over");

    return bret;
}

/*******************************************************************************************
*功能:      扫描变更目录
*参数:      in_to_out                ----> 同步方向
*           scan_msg                 ----> 扫描信息
*           path_list                ----> 扫描目录列表
*           recorder                 ----> 文件记录管理对象
*
*           返回值                    ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool scan_dir(bool in_to_out, fs_send_t *scan_msg, const char *dir_name)
{

    bool bret = true;
    fs_rule_t *rule = scan_msg->rule;
    GList *file_list = NULL;
    GList *dir_list = NULL;

    fs_work_t *scan_worker = create_worker_obj(in_to_out ? rule->int_srv.protocol : rule->out_srv.protocol);
    scan_worker->init_worker_obj(scan_worker, in_to_out ? &rule->int_srv : &rule->out_srv);

    if ((scan_worker->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE) {
        bret = scan_worker->connect_server(scan_worker->handle);
        if (!bret) {
            scan_worker->destroy_worker_obj(scan_worker);
            return false;
        }
    }
    if (!scan_worker->check_server_connect(scan_worker->handle)) {
        PRINT_ERR_HEAD;
        print_err("check scan dir connect failed!");
        scan_worker->destroy_worker_obj(scan_worker);
        return false;
    }

    //第一次扫描
    PRINT_DBG_HEAD;
    print_dbg("[TASK%d] first scan dir = %s", rule->task_id, dir_name);
    bret = scan_worker->first_scan(scan_worker->handle, in_to_out, dir_name, &dir_list, &file_list,
                                   scan_msg->ready_queue, rule->delay_time);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] first scan %s over", rule->task_id, dir_name);
    } else {
        PRINT_ERR_HEAD;
        print_err("[TASK%d] first scan %s error!", rule->task_id, dir_name);
        goto _exit;
    }


    if (rule->delay_time > 0) {                                              //第二次扫描
        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] wait %ds to second scan", rule->task_id, rule->delay_time);
        sleep(rule->delay_time);
        bret = scan_worker->check_server_connect(scan_worker->handle);
        if (!bret) {
            bret = scan_worker->connect_server(scan_worker->handle);
        }
        if (!bret) {
            goto _exit;
        }
        scan_worker->second_scan(scan_worker->handle, &file_list, scan_msg->ready_queue);
        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] file list second scan over ", rule->task_id);
    } else {
        move_list_queue(&file_list, scan_msg->ready_queue);
    }

    while (g_async_queue_length(scan_msg->ready_queue) > (0 - rule->pthread_count)) {
        sleep(FSYNC_QUERY_TIME);
    }
    //添加所有目录至任务队列
    PRINT_DBG_HEAD;
    print_dbg("start to send dir");
    move_list_queue(&dir_list, scan_msg->ready_queue);

    while (g_async_queue_length(scan_msg->ready_queue) > (0 - rule->pthread_count)) {
        sleep(FSYNC_QUERY_TIME);
    }

_exit:
    g_list_free_full(file_list, free);
    g_list_free_full(dir_list, free);

    scan_worker->disconnect(scan_worker->handle);
    scan_worker->destroy_worker_obj(scan_worker);

    PRINT_DBG_HEAD;
    print_dbg("scan  dir is over");
    return bret;
}


/*******************************************************************************************
*功能:      任务发送
*参数:      send_rule           ----> 任务发送信息
*
*           返回值              ---->
*
*注释:
*******************************************************************************************/
void *sync_mod(void *send_rule)
{

    fs_rule_t *rule = ((fs_send_t *) send_rule)->rule;
    fs_send_t *send_msg = (fs_send_t *) send_rule;
    static pthread_mutex_t sync_mutex = PTHREAD_MUTEX_INITIALIZER;
    static int sync_id = 0;
    char sync_name[15] = {0};
    pthread_mutex_lock(&sync_mutex);
    sprintf(sync_name, "sync_th_%d", sync_id++);
    pthread_setself(sync_name);
    pthread_mutex_unlock(&sync_mutex);

    CLOGMANAGE web_log;
    web_log.Init(rule->syslog_flag);
    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
    fs_task_t *tmp_task;
    int del_flag = rule->sync_area != FSYNC_BOTH_WAY ? ((fs_oneway_t *) rule->diff_info)->del_source
                   : ((fs_bothway_t *) rule->diff_info)->sync_del;
    bool bret = true;
    int failed_times = 0;

    fs_log_t log_info;
    fs_sync_t sync_info;
    fs_work_t *int_worker = create_worker_obj(rule->int_srv.protocol);
    int_worker->init_worker_obj(int_worker, &rule->int_srv);
    fs_work_t *out_worker = create_worker_obj(rule->out_srv.protocol);
    out_worker->init_worker_obj(out_worker, &rule->out_srv);
    fs_work_t *intbak_worker = NULL;
    fs_work_t *outbak_worker = NULL;
    if (rule->int_bak_flag == FSYNC_TURN_ON) {
        intbak_worker = create_worker_obj(rule->int_bak.protocol);
        intbak_worker->init_worker_obj(intbak_worker, &rule->int_bak);
    }
    if (rule->out_bak_flag == FSYNC_TURN_ON) {
        outbak_worker = create_worker_obj(rule->out_bak.protocol);
        outbak_worker->init_worker_obj(outbak_worker, &rule->out_bak);
    }

    create_all_data_connect(rule, int_worker, out_worker, intbak_worker, outbak_worker);

    while (1) {
        tmp_task = NULL;
        gettimeofday(send_msg->work_stat, NULL);
        memset(&sync_info, 0, sizeof(sync_info));

        //获取任务
        get_new_task(send_msg, &tmp_task, &sync_info, int_worker, out_worker, intbak_worker, outbak_worker);
        if (rule->task_stat == FSYNC_QUIT_NOW) {
            PRINT_DBG_HEAD;
            print_dbg("task stat is QUIT");
            break;
        }
        //设置删除开关
        sync_info.del_flag = del_flag;
        //挂载点状态检测
        bret = check_all_server(rule, int_worker, out_worker, intbak_worker, outbak_worker);
        if (!bret) {
            void *p_tmp = NULL;
            while ((p_tmp = g_async_queue_try_pop(send_msg->ready_queue)) != NULL) {
                free(p_tmp);
            }
            failed_times++;
            if (failed_times > FSYNC_RETRY_TIME) {
                break;
            }
        } else {
            failed_times = 0;
        }

        //再次检查文件/文件夹更新
        if (bret) {
            bret = check_update(sync_info.src_worker, tmp_task, &sync_info.src_stat);
            if (!bret) {
                PRINT_DBG_HEAD;
                print_dbg("[TASK%d] file = %s third check is changed,not send !", rule->task_id, tmp_task->path);
            }
        }
        //根据源目录获取目的目录
        if (bret) {
            get_target_path(rule, &sync_info);
            //获取文件名
            strcpy(sync_info.file_name, basename(tmp_task->path));
            PRINT_DBG_HEAD;
            print_dbg("file name = %s", sync_info.file_name);
            //单向重命名检查
            if ((rule->sync_area != FSYNC_BOTH_WAY) && (sync_info.file_type == FSYNC_IS_FILE)) {
                if ((((fs_oneway_t *) rule->diff_info)->rename_flag == FSYNC_TURN_ON) &&
                    (sync_info.dst_worker->check_access(sync_info.dst_worker->handle, sync_info.dst_file))) {
                    make_back_name(sync_info.dst_file, 1);
                    if (sync_info.is_bak) {
                        make_back_name(sync_info.bak_file, 1);
                    }
                }
            }
            //生成日志信息
            if (rule->log_flag != FSYNC_TURN_OFF) {
                memset(&log_info, 0, sizeof(log_info));
                make_log_info(rule, &sync_info, &log_info);
            }
        }
        //文件夹/文件同步
        if (bret) {
            if (sync_info.file_type == FSYNC_IS_DIR) {
                sync_info.src_type = sync_info.in_to_out ? INT_DIR_TYPE : OUT_DIR_TYPE;
                sync_info.dst_type = sync_info.in_to_out ? OUT_DIR_TYPE : INT_DIR_TYPE;
                sync_dir(send_msg, &sync_info, &log_info, recorder, &web_log);
            } else {
                sync_info.src_type = sync_info.in_to_out ? INT_FILE_TYPE : OUT_FILE_TYPE;
                sync_info.dst_type = sync_info.in_to_out ? OUT_FILE_TYPE : INT_FILE_TYPE;
                sync_file(send_msg, &sync_info, &log_info, recorder, &web_log);
            }
        }

        if (tmp_task != NULL) {
            free(tmp_task);
        }

    }

    recorder->close_db(recorder);

    PRINT_INFO_HEAD;
    print_info("[TASK%d]sync pthread will exit", rule->task_id);

    return NULL;
}

/*******************************************************************************************
*功能:      获取新任务
*参数:      send_msg            ----> 任务发送信息
*           tmp_task            ----> 临时任务
*           sync_info           ----> 同步任务信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool get_new_task(fs_send_t *send_msg, fs_task_t **tmp_task, fs_sync_t *sync_info, fs_work_t *int_worker,
                  fs_work_t *out_worker, fs_work_t *intbak_worker, fs_work_t *outbak_worker)
{

    *tmp_task = (fs_task_t *) g_async_queue_pop(send_msg->ready_queue);
    PRINT_DBG_HEAD;
    print_dbg("get new task path = %s", (*tmp_task)->path);

    sync_info->in_to_out = (*tmp_task)->in_to_out;
    strcpy(sync_info->src_file, (*tmp_task)->path);
    sync_info->file_type = (*tmp_task)->type;

    if (sync_info->in_to_out) {
        sync_info->src_protocol = send_msg->rule->int_srv.protocol;
        sync_info->src_worker = int_worker;

        sync_info->dst_protocol = send_msg->rule->out_srv.protocol;
        sync_info->dst_worker = out_worker;

        sync_info->bak_protocol = send_msg->rule->int_bak.protocol;
        sync_info->bak_worker = intbak_worker;
    } else {
        sync_info->src_protocol = send_msg->rule->out_srv.protocol;
        sync_info->src_worker = out_worker;

        sync_info->dst_protocol = send_msg->rule->int_srv.protocol;
        sync_info->dst_worker = int_worker;

        sync_info->bak_protocol = send_msg->rule->out_bak.protocol;
        sync_info->bak_worker = outbak_worker;
    }

    return true;
}

/*******************************************************************************************
*功能:      解析源目录并获取目的目录
*参数:       rule                ----> 策略信息
*           sync_info          ----> 同步任务信息
*
*           返回值              ----> 同步方向  true 内到外 false 外到内
*
*注释:
*******************************************************************************************/
bool get_target_path(const fs_rule_t *rule, fs_sync_t *sync_info)
{

    PRINT_DBG_HEAD;
    print_dbg("source file = %s", sync_info->src_file);

    if (sync_info->in_to_out) {
        deal_path(rule->out_srv.scan_path, sync_info->src_file + strlen(rule->int_srv.scan_path),
                  sync_info->dst_file);
        PRINT_DBG_HEAD;
        print_dbg("make target path = %s", sync_info->dst_file);
        if (rule->int_bak_flag == FSYNC_TURN_ON) {
            sync_info->is_bak = true;
            //在内网侧备份
            deal_path(rule->int_bak.scan_path, sync_info->src_file + strlen(rule->int_srv.scan_path),
                      sync_info->bak_file);

            PRINT_DBG_HEAD;
            print_dbg("make int back up  path = %s", sync_info->bak_file);
        } else {
            sync_info->is_bak = false;
        }
    } else {
        deal_path(rule->int_srv.scan_path, sync_info->src_file + strlen(rule->out_srv.scan_path),
                  sync_info->dst_file);
        PRINT_DBG_HEAD;
        print_dbg("make target path = %s", sync_info->dst_file);
        if (rule->out_bak_flag == FSYNC_TURN_ON) {
            sync_info->is_bak = true;
            //在外网侧备份
            deal_path(rule->out_bak.scan_path, sync_info->src_file + strlen(rule->out_srv.scan_path),
                      sync_info->bak_file);
            PRINT_DBG_HEAD;
            print_dbg("make out back up path = %s", sync_info->bak_file);
        } else {
            sync_info->is_bak = false;
        }

    }
    return sync_info->in_to_out;
}

/*******************************************************************************************
*功能:      目录同步
*参数:      send_msg           ----> 任务发送信息
*           sync_info          ----> 同步任务信息
*           log_info           ----> 日志信息
*           recorder           ----> 文件记录管理对象
*           web_log            ----> 日志对象
*
*           返回值              ----> -2 删除失败 -1 发送失败 0 不需发送  1发送成功 2删除成功
*
*注释:
*******************************************************************************************/
int sync_dir(fs_send_t *send_msg, fs_sync_t *sync_info, fs_log_t *log_info, recorder_t *recorder, CLOGMANAGE *web_log)
{

    int ret = 0;
    bool bret = true;
    int source_row = 0;
    fs_rule_t *rule = send_msg->rule;

    bool is_add_dir = false;
    if (rule->sync_area != FSYNC_BOTH_WAY) {  //单向模式
        if (sync_info->del_flag == FSYNC_TURN_OFF) {
            bret = check_dir_change(sync_info->src_type, recorder, sync_info->src_file, rule->task_name, &source_row);
        }
        if (!bret) {
            PRINT_DBG_HEAD;
            print_dbg("dir = %s no change ,not send", sync_info->src_file);
            return FSYNC_NOT_SEND;
        } else {
            ret = one_way_dir_sync(send_msg, sync_info, recorder);
            if (ret == 0) {   //此目录为扫描目录
                return ret;
            } else {          //判断目录增删
                is_add_dir = ret == 1 ? true : false;
            }
            if (!is_add_dir) {
                PRINT_DBG_HEAD;
                print_dbg("dir = %s not send", sync_info->src_file);
                return ret;
            }
        }
    } else {                                  //双向模式
        if (sync_info->dst_worker->check_access(sync_info->dst_worker->handle, sync_info->dst_file)) {
            add_dir_change(sync_info->src_worker, true, sync_info->in_to_out, sync_info->src_file,
                           send_msg->dir_hash_table, send_msg->dir_hash_mut, &(sync_info->src_stat));
            add_dir_change(sync_info->dst_worker, true, !sync_info->in_to_out, sync_info->dst_file,
                           send_msg->dir_hash_table, send_msg->dir_hash_mut, NULL);
            return FSYNC_NOT_SEND;
        } else {
            if ((ret = both_way_dir_sync(send_msg, sync_info, recorder)) > 0) {
                is_add_dir = ret == 1 ? true : false;   //判断目录增删
            } else {
                return ret;
            }
        }
    }

    if (is_add_dir) {
        if (rule->log_flag != FSYNC_TURN_OFF) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, "", S_SUCCESS, DIR_SYNC,
                                      !sync_info->in_to_out);
            if (sync_info->is_bak) {
                web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->bak_ip,
                                          log_info->log_src_path, log_info->log_bak_path, "", S_SUCCESS, DIR_SYNC,
                                          !sync_info->in_to_out);
            }
        }
    } else {
        if (rule->log_flag != FSYNC_TURN_OFF) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, "", S_SUCCESS, DIR_DELETE,
                                      !sync_info->in_to_out);
        }
    }
    return ret;
}

/*******************************************************************************************
*功能:      文件同步
*参数:      send_msg           ----> 任务发送信息
*           sync_info          ----> 同步任务信息
*           log_info           ----> 日志信息
*           recorder           ----> 记录管理对象
*           web_log            ----> 日志对象
*
*           返回值              ----> -2 删除失败 -1 发送失败 0 不需发送  1发送成功 2删除成功
*
*注释:
*******************************************************************************************/
int
sync_file(fs_send_t *send_msg, fs_sync_t *sync_info, fs_log_t *log_info, recorder_t *recorder, CLOGMANAGE *web_log)
{

    int ret = 0;
    bool bret = true;
    int source_row = 0;
    int target_row = 0;
    int keyword_row = 0;
    char tmp_dst_file[FSYNC_PATH_MAX_LEN] = {0};
    char tmp_bak_file[FSYNC_PATH_MAX_LEN] = {0};
    char remark[FSYNC_PATH_MAX_LEN] = {0};
    fs_rule_t *rule = send_msg->rule;

    if (strlen(rule->tmp_extname) > 0) {
        char extname_list[FSYNC_NAME_MAX_LEN] = {0};
        const char *p_start = strchr(rule->tmp_extname, '.');
        if (p_start != NULL) {
            p_start++;
            sprintf(extname_list, ",%s,", p_start);
            bret = suffix_check(2, sync_info->file_name, extname_list);
        }
        if (!bret) {
            PRINT_DBG_HEAD;
            print_dbg("suffix check not allow file = %s send", sync_info->src_file);
            return FSYNC_SEND_FAILED;
        }
    }

    if ((rule->sync_area != FSYNC_BOTH_WAY)) {    //单向文件增量检测
        if (sync_info->del_flag == FSYNC_TURN_OFF) {
            bret = check_file_change(sync_info->src_type, recorder, sync_info->src_file,
                                     sync_info->src_stat.st_size,
                                     sync_info->src_stat.st_mtime, rule->task_name, &source_row);
        }
    } else {                                //双向文件增量检测
        bret = check_file_change(sync_info->src_type, recorder, sync_info->src_file,
                                 sync_info->src_stat.st_size,
                                 sync_info->src_stat.st_mtime, rule->task_name, &source_row);
        //目标文件记录查询
        target_row = recorder->select_data(recorder, rule->task_name, sync_info->dst_type, sync_info->dst_file,
                                           NULL, NULL, NULL);

        //双向文件同步删除
        if (!bret) {    //文件未更新
            ret = both_way_check_file(send_msg, sync_info, recorder, target_row);
            if ((ret == FSYNC_DELETE_SUCCESS) || (ret == FSYNC_DELETE_FAILED)) {
                if (rule->log_flag != FSYNC_TURN_OFF) {    //文件删除
                    web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                              log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                              (ret == FSYNC_DELETE_SUCCESS) ? S_SUCCESS : S_FAILED,
                                              FILE_DELETE, !sync_info->in_to_out);
                }
                return ret;
            } else if (ret == 0) {           //无需操作
                PRINT_DBG_HEAD;
                print_dbg("both way source file = %s not need any operation ,will return", sync_info->src_file);
                return ret;
            } else {
                bret = true;                         //文件发送
            }
        } else {
            PRINT_DBG_HEAD;
            print_dbg("both way source file = %s is changed ,next step", sync_info->src_file);
        }
    }


    if (bret && (rule->filter_flag != FSYNC_TURN_OFF)) {                              //文件后缀检查
        bret = suffix_check(rule->filter_flag, sync_info->file_name, rule->filter_list);
        if (!bret) {
            PRINT_DBG_HEAD;
            print_dbg("suffix check not allow file = %s send", sync_info->src_file);
            if (rule->log_flag != FSYNC_TURN_OFF) {
                web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, FORBIDTYPE, FILE_SYNC_MOD,
                                        log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                        sync_info->in_to_out ? "I" : "O");
            }
            return FSYNC_SEND_FAILED;
        }
    }

    if ((bret) && (rule->keyword_flag == FSYNC_TURN_ON)) {                           //关键字记录检查
        keyword_row = 0;
        char keyword_info[FSYNC_NAME_MAX_LEN] = {0};
        bret = check_file_change(KEYWORD_FILE_TYPE, recorder, sync_info->src_file, sync_info->src_stat.st_size,
                                 sync_info->src_stat.st_mtime, rule->task_name, &keyword_row, keyword_info);
        if (!bret) {
            if (rule->log_flag != FSYNC_TURN_OFF) {
                sprintf(remark, "%s:%s", FORBIDWORD, keyword_info);
                web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, remark, FILE_SYNC_MOD,
                                        log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                        sync_info->in_to_out ? "I" : "O");
            }
            return FSYNC_NOT_SEND;
        }
    }

    if ((bret) && (rule->virus_flag == FSYNC_TURN_ON) &&
        ((sync_info->src_protocol & FSYNC_FILE_SYSTEM) != FSYNC_FTP_TYPE)) { //病毒检查
        int virus_result = 0;
        char virus_name[FSYNC_NAME_MAX_LEN] = {0};
        virus_result = check_virus_file(rule, recorder, sync_info->src_file, &(sync_info->src_stat), virus_name);
        if (virus_result == IS_VIRUS) {
            if (rule->log_flag != FSYNC_TURN_OFF) {
                sprintf(remark, "%s %s", VIRUSTYPE, virus_name);
                web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, remark, FILE_SYNC_MOD,
                                        log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                        sync_info->in_to_out ? "I" : "O");
            }
            return FSYNC_NOT_SEND;
        } else if (virus_result == VIRUS_FAIL) {
            if (rule->log_flag != FSYNC_TURN_OFF) {
                sprintf(remark, "%s %s", VIRUSFAIL, virus_name);
                web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, remark, FILE_SYNC_MOD,
                                        log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                        sync_info->in_to_out ? "I" : "O");
            }
            return FSYNC_NOT_SEND;
        }
    }

    if (bret) {                                                                //文件拷贝
        if (sync_info->dst_worker->check_access(sync_info->dst_worker->handle, sync_info->dst_file)) {
            if (sync_info->dst_worker->remove(sync_info->dst_worker->handle, sync_info->dst_file) != 0) {
                PRINT_ERR_HEAD
                print_err("remove dst file fail[%s]", sync_info->dst_file);
            }
        }
        memset(remark, 0, sizeof(remark));
        make_tmp_name(true, rule, sync_info, sync_info->dst_worker, tmp_dst_file, sync_info->bak_worker,
                      tmp_bak_file);
#ifdef FSYNC_USE_CURL
        bret = curl_copy_file(sync_info->in_to_out, send_msg, web_log, log_info, sync_info->src_worker,
                              sync_info->src_file, &sync_info->src_stat, sync_info->dst_worker, tmp_dst_file,
                              sync_info->bak_worker, tmp_bak_file);
#else
        bret = copy_file(sync_info->in_to_out, send_msg, web_log, log_info, sync_info->src_worker, sync_info->src_file,
                         &sync_info->src_stat, sync_info->dst_worker, tmp_dst_file, sync_info->bak_worker,
                         tmp_bak_file);
#endif
        if (bret) {
            make_tmp_name(false, rule, sync_info, sync_info->dst_worker, tmp_dst_file, sync_info->bak_worker,
                          tmp_bak_file);

            //完成重命名后,再次检测目的端文件
            if (sync_info->dst_worker->get_stat(sync_info->dst_worker->handle, sync_info->dst_file,
                                                &(sync_info->dst_stat)) != 0) {
                bret = false;
            }

            if (sync_info->dst_stat.st_size != sync_info->src_stat.st_size) {
                PRINT_ERR_HEAD;
                print_err("[TASK%d] source stat size = %zu ,target stat size = %zu", rule->task_id,
                          sync_info->src_stat.st_size, sync_info->dst_stat.st_size);
                bret = false;
                sync_info->dst_worker->remove(sync_info->dst_worker->handle, sync_info->dst_file);
            }
        }

        if (bret) {
            if (rule->log_flag != FSYNC_TURN_OFF) {
                web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                          log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                          S_SUCCESS, FILE_SYNC, !sync_info->in_to_out);
                if (sync_info->is_bak) {
                    web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->bak_ip,
                                              log_info->log_src_path, log_info->log_bak_path, log_info->file_name,
                                              S_SUCCESS, FILE_BACK, !sync_info->in_to_out);
                }
            }
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] send file = %s to %s success", rule->task_id, sync_info->src_file,
                      sync_info->dst_file);
        } else {
            if (rule->log_flag != FSYNC_TURN_OFF) {
                web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                          log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                          S_FAILED, FILE_SYNC, !sync_info->in_to_out);
            }
            PRINT_ERR_HEAD;
            print_err("[TASK%d] send file = %s to %s failed", rule->task_id, sync_info->src_file,
                      sync_info->dst_file);
        }
    }

    if (bret) {
        if (rule->sync_area != FSYNC_BOTH_WAY) {                            //单向结束处理
            one_way_file_over(send_msg, sync_info, recorder, source_row, log_info, web_log);
        } else {                                                            //双向结束处理
            both_way_file_over(send_msg, sync_info, recorder, source_row, target_row);
        }
    }

    return bret ? FSYNC_SEND_SUCCESS : FSYNC_SEND_FAILED;
}


/*******************************************************************************************
*功能:      生成日志信息
*参数:      rule                ----> 策略信息
*           sync_info          ----> 同步任务信息
*           path_offset        ----> 目录偏移量
*           log_info           ----> 日志信息
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool make_log_info(fs_rule_t *rule, fs_sync_t *sync_info, fs_log_t *log_info)
{

    bool log_area;
    log_info->log_src_path = sync_info->src_file + (sync_info->in_to_out ? strlen(rule->int_srv.mount_path) :
                             strlen(rule->out_srv.mount_path));
    log_info->log_dst_path = sync_info->dst_file + (sync_info->in_to_out ? strlen(rule->out_srv.mount_path) :
                             strlen(rule->int_srv.mount_path));
    if (sync_info->is_bak) {
        log_info->log_bak_path = sync_info->bak_file + (sync_info->in_to_out ? strlen(rule->int_bak.mount_path) :
                                 strlen(rule->out_bak.mount_path));
    }
    if (sync_info->in_to_out) {
        log_area = false;
        log_info->src_ip = rule->int_srv.real_ip;
        log_info->dst_ip = rule->out_srv.real_ip;
        sprintf(log_info->src_port, "%d", rule->int_srv.port);
        sprintf(log_info->dst_port, "%d", rule->out_srv.port);
        if (sync_info->is_bak) {
            log_info->bak_ip = rule->int_bak.real_ip;
            sprintf(log_info->bak_port, "%d", rule->int_bak.port);
        }
    } else {
        log_area = true;
        log_info->src_ip = rule->out_srv.real_ip;
        log_info->dst_ip = rule->int_srv.real_ip;
        sprintf(log_info->src_port, "%d", rule->out_srv.port);
        sprintf(log_info->dst_port, "%d", rule->int_srv.port);
        if (sync_info->is_bak) {
            log_info->bak_ip = rule->out_bak.real_ip;
            sprintf(log_info->bak_port, "%d", rule->out_bak.port);
        }
    }

    strcpy(log_info->file_name, sync_info->file_name);

    return log_area;
}

/*******************************************************************************************
*功能:      检测更新
*参数:      worker               ----> 服务器对象
*           tmp_task             ----> 任务结构
*           stat_buf             ----> 文件元数据
*           返回值                ----> true 未更新 , false 被更新
*
*注释:
*******************************************************************************************/
bool check_update(fs_work_t *worker, fs_task_t *tmp_task, struct stat *stat_buf)
{
    int ret = 0;
    bool bret = false;
    ret = worker->get_stat(worker->handle, tmp_task->path, stat_buf);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("file = %s get stat failed", tmp_task->path);
        return false;
    }

    if (stat_buf->st_mode != tmp_task->type) {
        PRINT_ERR_HEAD;
        print_err("file = %s type is change ,old type = %d ,new type = %d", tmp_task->path, tmp_task->type,
                  stat_buf->st_mode);
        return false;
    }

    if (tmp_task->type == FSYNC_IS_DIR) {
        if (tmp_task->modify != 0) {
            stat_buf->st_mtime = tmp_task->modify;
        }
        PRINT_DBG_HEAD;
        print_dbg("file = %s is a dir", tmp_task->path);
        bret = true;
    } else {
        if ((tmp_task->modify != stat_buf->st_mtime) || (tmp_task->size != stat_buf->st_size)) {
            PRINT_ERR_HEAD;
            print_err("file = %s modify time or size changed", tmp_task->path);
            bret = false;
        } else {
            PRINT_DBG_HEAD;
            print_dbg("get file = %s from ready_list to sending list", tmp_task->path);
            bret = true;
        }
    }
    return bret;
}

/*******************************************************************************************
*功能:       目录更新检测
*参数:      type                ----> 文件类型
*           recorder           ----> 记录管理器
*           path               ----> 路径名
*           dir_time           ----> 目录最后修改时间
*           user               ----> 策略名
*           row_num            ----> 获取的行数
*
*           返回值              ----> true 更新 false 未更新
*
*注释:
*******************************************************************************************/
bool check_dir_change(int file_type, recorder_t *recorder, const char *path_name, const char *user, int *row_num)
{

    unsigned long old_time = 0;
    bool bret = false;
    *row_num = recorder->select_data(recorder, user, file_type, path_name, &old_time, NULL, NULL);
    if (*row_num > 0) {
        bret = false;
        PRINT_DBG_HEAD;
        print_dbg("find dir = %s in record ", path_name);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("not find dir = %s in record", path_name);
        bret = true;
    }
    return bret;
}

/*******************************************************************************************
*功能:      文件更新检测
*参数:       type          ----> 文件类型
*           recorder           ----> 记录管理器
*           path          ----> 路径名
*           size          ----> 文件大小
*           file_time          ----> 文件最后修改时间
*           user               ----> 策略名
*           row_num            ----> 获取的行数
*           remark             ----> 备注信息
*
*           返回值              ----> true 更新 false 未更新
*
*注释:
*******************************************************************************************/
bool check_file_change(int file_type, recorder_t *recorder, const char *path_name, unsigned long file_size,
                       unsigned long file_time, const char *user, int *row_num, char *remark)
{

    unsigned long old_size = 0;
    unsigned long old_time = 0;
    bool bret = false;
    *row_num = recorder->select_data(recorder, user, file_type, path_name, &old_time, &old_size, remark);

    long time_diff = file_time > old_time ? (file_time - old_time) : (old_time - file_time);
    if (*row_num > 0) {
        if ((old_size == file_size) && (time_diff < 2)) {
            bret = false;
            PRINT_DBG_HEAD;
            print_dbg("find file = %s in record , file size and time not changed", path_name);
        } else {
            bret = true;
            PRINT_DBG_HEAD;
            print_dbg(
                "find file = %s in record , file size or time is changed,old size = %lu,new size = %lu ,old time = %lu,"
                "new time = %lu ,remark = %s", path_name, old_size, file_size, old_time, file_time,
                remark == NULL ? "" : remark);
        }
    } else {
        PRINT_DBG_HEAD;
        print_dbg("not find file = %s in record", path_name);
        bret = true;
    }
    return bret;
}

/*******************************************************************************************
*功能:      文件病毒检查
*参数:       rule               ----> 策略信息
*           recorder           ----> 记录管理器
*           file_name          ----> 文件名
*           source_stat        ----> 目录元数据
*           virus_name         ----> 病毒名称
*
*           返回值              ----> true 检查通过 false禁止通过
*
*注释:
*******************************************************************************************/
int check_virus_file(fs_rule_t *rule, recorder_t *recorder, const char *file_name, struct stat *file_stat,
                     char *virus_name)
{

    bool bret;
    int virus_row = 0;
    int virus_result = IS_VIRUS;

    bret = check_file_change(VIRUS_FILE_TYPE, recorder, file_name, file_stat->st_size, file_stat->st_mtime,
                             rule->task_name, &virus_row, virus_name);
    if (bret) {
        virus_result = check_virus((char *) file_name, virus_name);
        if (virus_result == NOT_VIRUS) {
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] file = %s is not virus ", rule->task_id, file_name);
        } else if (virus_result == VIRUS_FAIL) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d] file = %s check virus failed !", rule->task_id, file_name);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] file = %s is virus", rule->task_id, file_name);
            if (virus_row > 0) {
                recorder->update_data(recorder, rule->task_name, VIRUS_FILE_TYPE, file_name, file_stat->st_mtime,
                                      file_stat->st_size, virus_name);
            } else {
                recorder->insert_data(recorder, rule->task_name, VIRUS_FILE_TYPE, file_name, file_stat->st_mtime,
                                      file_stat->st_size, virus_name);
            }
        }
    }
    return virus_result;
}

/*******************************************************************************************
*功能:      单向目录同步
*参数:       send_msg           ----> 发送信息
*           sync_info          ----> 同步任务信息
*           recorder           ----> 记录管理器
*
*           返回值              ----> -2删除目录失败 -1创建目录失败 0不做操作 1创建目录成功  2删除目录成功
*
*注释:
*******************************************************************************************/
int one_way_dir_sync(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder)
{

    int ret = 1;
    bool is_del = true;
    //目的端处理
    const char *scan_path = sync_info->in_to_out ? send_msg->rule->int_srv.scan_path
                            : send_msg->rule->out_srv.scan_path;

    if (!sync_info->dst_worker->check_access(sync_info->dst_worker->handle, sync_info->dst_file)) {
        if (sync_info->dst_worker->mkdir_r(sync_info->dst_worker->handle, sync_info->dst_file) != 0) {
            ret = -1;
            is_del = false;
        } else {
            is_del = true;
        }
    } else {
        ret = -1;
        is_del = true;
    }
    if (sync_info->is_bak) {
        sync_info->bak_worker->mkdir_r(sync_info->bak_worker->handle, sync_info->bak_file);
    }

    //源端处理
    if (sync_info->del_flag == FSYNC_TURN_OFF) {
        add_dir_change(sync_info->src_worker, true, sync_info->in_to_out, sync_info->src_file,
                       send_msg->dir_hash_table, send_msg->dir_hash_mut, &(sync_info->src_stat));
    } else if ((sync_info->del_flag == FSYNC_RM_ALL) && (is_del)) {
        if (strcmp(scan_path, sync_info->src_file) != 0) {  //禁止删除扫描目录
            sync_info->src_worker->rmdir(sync_info->src_worker->handle, sync_info->src_file);
        } else {
            ret = 0;
        }
    }
    return ret;
}

/*******************************************************************************************
*功能:      双向目录同步
*参数:       send_msg           ----> 发送信息
*           sync_info          ----> 同步任务信息
*           recorder           ----> 记录管理器
*
*           返回值              ----> -2删除目录失败 -1创建目录失败 0不做操作 1创建目录成功  2删除目录成功
*
*注释:
*******************************************************************************************/
int both_way_dir_sync(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder)
{

    fs_rule_t *rule = send_msg->rule;
    int ret = 0;

    if (((fs_bothway_t *) rule->diff_info)->sync_del == 0) {
        //双向不同步删除
        if (sync_info->dst_worker->mkdir_r(sync_info->dst_worker->handle, sync_info->dst_file) != 0) {
            return -1;
        }
        if (sync_info->is_bak) {
            sync_info->bak_worker->mkdir_r(sync_info->bak_worker->handle, sync_info->bak_file);
        }

        add_dir_change(sync_info->src_worker, true, sync_info->in_to_out, sync_info->src_file,
                       send_msg->dir_hash_table, send_msg->dir_hash_mut, &(sync_info->src_stat));
        add_dir_change(sync_info->dst_worker, true, !sync_info->in_to_out, sync_info->dst_file,
                       send_msg->dir_hash_table, send_msg->dir_hash_mut, NULL);
        ret = 1;

    } else {
        //双向同步删除
        int row = 0;
        row = recorder->select_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file, NULL,
                                    NULL, NULL);
        if (row <= 0) {
            row = recorder->select_data(recorder, rule->task_name, sync_info->dst_type, sync_info->dst_file, NULL,
                                        NULL, NULL);
        }

        if (row > 0) {
            const char *scan_path = sync_info->in_to_out ? send_msg->rule->int_srv.scan_path
                                    : send_msg->rule->out_srv.scan_path;
            if (strcmp(scan_path, sync_info->src_file) == 0) {
                return 0;
            }

            if (!sync_info->src_worker->rmdir(sync_info->src_worker->handle, sync_info->src_file)) {
                PRINT_DBG_HEAD;
                print_dbg("rmdir = %s failed", sync_info->src_file);
                ret = -2;
            } else {
                PRINT_DBG_HEAD;
                print_dbg("[TASK%d] find target dir = %s not existed ,delete sync !", rule->task_id,
                          sync_info->dst_file);
                add_dir_change(sync_info->src_worker, false, sync_info->in_to_out, sync_info->src_file,
                               send_msg->dir_hash_table, send_msg->dir_hash_mut, &(sync_info->src_stat));
                add_dir_change(sync_info->dst_worker, false, !sync_info->in_to_out, sync_info->dst_file,
                               send_msg->dir_hash_table, send_msg->dir_hash_mut, NULL);
                ret = 2;
            }

        } else {
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] target = %s not in record ,will make", rule->task_id, sync_info->dst_file);
            if (sync_info->dst_worker->mkdir_r(sync_info->dst_worker->handle, sync_info->dst_file) != 0) {
                return -1;
            }
            if (sync_info->is_bak) {
                sync_info->bak_worker->mkdir_r(sync_info->bak_worker->handle, sync_info->bak_file);
            }
            add_dir_change(sync_info->src_worker, true, sync_info->in_to_out, sync_info->src_file,
                           send_msg->dir_hash_table, send_msg->dir_hash_mut, &(sync_info->src_stat));
            add_dir_change(sync_info->dst_worker, true, !sync_info->in_to_out, sync_info->dst_file,
                           send_msg->dir_hash_table, send_msg->dir_hash_mut, NULL);
            ret = 1;
        }
    }

    return ret;
}


/*******************************************************************************************
*功能:      双向文件同步增删检查
*参数:       send_msg           ----> 发送信息
*           sync_info          ----> 同步任务信息
*           recorder           ----> 记录管理器
*           target_row         ----> 目标文件记录数量
*
*           返回值              ----> -2 删除失败 -1 发送失败 0 不需发送  1发送成功 2删除成功
*
*注释:
*******************************************************************************************/
int both_way_check_file(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int target_row)
{
    fs_rule_t *rule = send_msg->rule;
    int ret = 0;

    if (((fs_bothway_t *) rule->diff_info)->sync_del == FSYNC_TURN_OFF) {
        //不存在,需要发送
        if (!sync_info->dst_worker->check_access(sync_info->dst_worker->handle, sync_info->dst_file)) {
            ret = 1;
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] target file  = %s not exited ,will send", rule->task_id, sync_info->dst_file);
        }
    } else {
        if (!sync_info->dst_worker->check_access(sync_info->dst_worker->handle, sync_info->dst_file)) {
            PRINT_DBG_HEAD;
            print_dbg("[TASK%d] find target file = %s not existed ,will check  !", rule->task_id,
                      sync_info->dst_file);
            if (target_row > 0) {
                //不存在,需要删除
                if (sync_info->src_worker->remove(sync_info->src_worker->handle, sync_info->src_file) != 0) {
                    PRINT_ERR_HEAD
                    print_err("remove src file[%s] fail", sync_info->src_file);
                    ret = -2;
                } else {
                    recorder->delete_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file);
                    recorder->delete_data(recorder, rule->task_name, sync_info->dst_type, sync_info->dst_file);

                    PRINT_DBG_HEAD;
                    print_dbg("[TASK%d] find target file = %s not existed ,delete sync !", rule->task_id,
                              sync_info->dst_file);
                    ret = 2;
                }
            }
        }
    }
    return ret;
}

/*******************************************************************************************
*功能:      双向文件同步结束处理
*参数:       send_msg           ----> 发送信息
*           sync_info          ----> 同步任务信息
*           recorder           ----> 记录管理器
*           source_row         ----> 源文件记录数量
*           target_row         ----> 目标文件记录数量
*
*           返回值              ----> true
*
*注释:
*******************************************************************************************/
bool
both_way_file_over(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int source_row, int target_row)
{

    fs_rule_t *rule = send_msg->rule;

    //源端文件记录增改
    if (source_row > 0) {
        recorder->update_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file,
                              sync_info->src_stat.st_mtime, sync_info->src_stat.st_size, NULL);
    } else {
        recorder->insert_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file,
                              sync_info->src_stat.st_mtime, sync_info->src_stat.st_size, NULL);
    }
    //目的端文件记录增改
    if (target_row > 0) {
        recorder->update_data(recorder, rule->task_name, sync_info->dst_type, sync_info->dst_file,
                              sync_info->dst_stat.st_mtime, sync_info->dst_stat.st_size, NULL);
    } else {
        recorder->insert_data(recorder, rule->task_name, sync_info->dst_type, sync_info->dst_file,
                              sync_info->dst_stat.st_mtime, sync_info->dst_stat.st_size, NULL);
    }
    return true;
}

/*******************************************************************************************
*功能:      单向文件同步结束处理
*参数:       send_msg           ----> 发送信息
*           sync_info          ----> 同步任务信息
*           recorder           ----> 记录管理器
*           source_row         ----> 源文件记录数量
*           log_info           ----> 日志信息
*           web_log            ----> 日志对象
*
*           返回值              ----> true
*
*注释:
*******************************************************************************************/
bool one_way_file_over(fs_send_t *send_msg, fs_sync_t *sync_info, recorder_t *recorder, int source_row,
                       fs_log_t *log_info, CLOGMANAGE *web_log)
{

    fs_rule_t *rule = send_msg->rule;

    if (sync_info->del_flag == FSYNC_TURN_OFF) {
        if (source_row > 0) {
            recorder->update_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file,
                                  sync_info->src_stat.st_mtime, sync_info->src_stat.st_size, NULL);
        } else {
            recorder->insert_data(recorder, rule->task_name, sync_info->src_type, sync_info->src_file,
                                  sync_info->src_stat.st_mtime, sync_info->src_stat.st_size, NULL);
        }
    } else {
        struct stat source_stat;
        memset(&source_stat, 0, sizeof(source_stat));
        sync_info->src_worker->get_stat(sync_info->src_worker->handle, sync_info->src_file, &source_stat);
        if (source_stat.st_size == sync_info->src_stat.st_size) {
            if (sync_info->src_worker->remove(sync_info->src_worker->handle, sync_info->src_file) != 0) {
                PRINT_ERR_HEAD
                print_err("remove src file fail[%s]", sync_info->src_file);

                if (rule->log_flag != FSYNC_TURN_OFF) {
                    web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                              log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                              S_FAILED, SRCFILE_DELETE_FAIL, !sync_info->in_to_out);
                }
            }
        } else {
            PRINT_DBG_HEAD;
            print_dbg("current file size = %lu ,old size = %lu,not remove", source_stat.st_size,
                      sync_info->src_stat.st_size);
        }
    }

    return true;
}

/*******************************************************************************************
*功能:      更新目录任务
*参数:      worker             ----> 服务器对象
*           is_add             ----> 增加或删除目录记录
*           in_to_out          ----> 同步方向
*           dir_path           ----> 目录路径
*           dir_hash_table     ----> 目录哈希表
*           dir_hash_nut       ----> 目录哈希锁
*           dir_stat           ----> 目录元数据
*
*           返回值              ----> true
*
*注释:
*******************************************************************************************/
bool add_dir_change(fs_work_t *worker, bool is_add, bool in_to_out, const char *dir_path, GHashTable *dir_hash_table,
                    pthread_mutex_t *dir_hash_mut, struct stat *dir_stat)
{

    fs_task_t tmp_task;
    struct stat tmp_stat;
    memset(&tmp_stat, 0, sizeof(tmp_stat));
    strcpy(tmp_task.path, dir_path);
    tmp_task.in_to_out = in_to_out;

    if (is_add) {
        if (dir_stat != NULL) {        //非空赋值
            tmp_task.size = dir_stat->st_size;
            tmp_task.modify = dir_stat->st_mtime;
        } else {                       //为空此时获取
            if (worker->get_stat(worker->handle, dir_path, &tmp_stat) != 0) {
                PRINT_DBG_HEAD;
                print_dbg("get dir_path = %s stat failed:%s", dir_path, strerror(errno));
                return false;
            }
            //tmp_task.size = tmp_stat.st_size;
            tmp_task.modify = tmp_stat.st_mtime;
        }
    }

    fs_task_t *task_value = (fs_task_t *) calloc(1, sizeof(fs_task_t));
    pthread_mutex_lock(dir_hash_mut);
    if (is_add) {
        tmp_task.type = FSYNC_IS_DIR;
        memcpy(task_value, &tmp_task, sizeof(fs_task_t));
        g_hash_table_insert(dir_hash_table, strdup(tmp_task.path), task_value);
        PRINT_DBG_HEAD;
        print_dbg("add dir = %s push in hash table", tmp_task.path);
    } else {
        tmp_task.type = -1;
        memcpy(task_value, &tmp_task, sizeof(fs_task_t));
        g_hash_table_insert(dir_hash_table, strdup(tmp_task.path), task_value);
        PRINT_DBG_HEAD;
        print_dbg("delete dir = %s push in hash table", tmp_task.path);
    }
    pthread_mutex_unlock(dir_hash_mut);

    return true;
}

gboolean add_allot(void *key, void *value, void *dir_list)
{

    fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
    memcpy(tmp_task, value, sizeof(fs_task_t));
    GList **add_list = (GList **) dir_list;

    if (tmp_task->type != -1) {
        *add_list = g_list_prepend(*add_list, tmp_task);
        return true;
    }

    return false;
}

gboolean del_allot(void *key, void *value, void *dir_list)
{

    fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
    memcpy(tmp_task, value, sizeof(fs_task_t));
    GList **del_list = (GList **) dir_list;

    if (tmp_task->type == -1) {
        *del_list = g_list_prepend(*del_list, tmp_task);
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:       增删改目录传输记录
*参数:       rule               ----> 策略信息
*           recorder           ----> 记录管理器
*           dir_hash_table     ----> 目录哈希表
*           dir_hash_mut       ----> 目录哈希表锁
*
*           返回值              ----> true 成功，false 失败
*
*注释:
*******************************************************************************************/
bool
change_dir_record(fs_rule_t *rule, recorder_t *recorder, GHashTable *dir_hash_table, pthread_mutex_t *dir_hash_mut)
{

    int dir_type = -1;
    int file_type = -1;
    fs_task_t *tmp_task = NULL;
    char dir_name[FSYNC_PATH_MAX_LEN] = {0};
    PRINT_DBG_HEAD;
    print_dbg("[TASK%d] dir over list start", rule->task_id);

    GList *add_list = NULL;
    GList *del_list = NULL;

    pthread_mutex_lock(dir_hash_mut);
    g_hash_table_foreach_remove(dir_hash_table, add_allot, &add_list);
    g_hash_table_foreach_remove(dir_hash_table, del_allot, &del_list);
    pthread_mutex_unlock(dir_hash_mut);

    //清除增改目录中是删除目录子集的元素
    for (GList *del_elem = del_list; del_elem != NULL; del_elem = del_elem->next) {
        sprintf(dir_name, "%s/", ((fs_task_t *) (del_elem->data))->path);
        for (GList *add_elem = add_list; add_elem != NULL; add_elem = add_elem->next) {
            if (strncmp(dir_name, ((fs_task_t *) (add_elem->data))->path, strlen(dir_name)) == 0) {
                free(add_elem->data);
                add_list = g_list_delete_link(add_list, add_elem);
                add_elem = add_list;
            }
        }
    }

    //增改操作
    for (GList *add_elem = add_list; add_elem != NULL; add_elem = add_list) {
        tmp_task = (fs_task_t *) (add_elem->data);
        unsigned long old_time = 0;
        dir_type = tmp_task->in_to_out ? INT_DIR_TYPE : OUT_DIR_TYPE;

        if (recorder->select_data(recorder, rule->task_name, dir_type, tmp_task->path, &old_time, NULL, NULL) > 0) {
            if (old_time != tmp_task->modify) {
                recorder->update_data(recorder, rule->task_name, dir_type, tmp_task->path, tmp_task->modify, 0, NULL);
            }
        } else {
            recorder->insert_data(recorder, rule->task_name, dir_type, tmp_task->path, tmp_task->modify, 0, NULL);
        }
        free(add_elem->data);
        add_list = g_list_delete_link(add_list, add_elem);
    }

    //删除操作
    for (GList *del_elem = del_list; del_elem != NULL; del_elem = del_list) {
        tmp_task = (fs_task_t *) (del_elem->data);
        dir_type = tmp_task->in_to_out ? INT_DIR_TYPE : OUT_DIR_TYPE;
        file_type = tmp_task->in_to_out ? INT_FILE_TYPE : OUT_FILE_TYPE;
        recorder->delete_data(recorder, rule->task_name, dir_type, tmp_task->path);
        recorder->delete_data(recorder, rule->task_name, file_type, tmp_task->path);
        sprintf(dir_name, "%s/", tmp_task->path);
        recorder->delete_like(recorder, rule->task_name, dir_type, dir_name);
        recorder->delete_like(recorder, rule->task_name, file_type, dir_name);
        free(del_elem->data);
        del_list = g_list_delete_link(del_list, del_elem);
    }

    g_list_free_full(add_list, free);
    g_list_free_full(del_list, free);
    return true;
}


/*******************************************************************************************
*功能:      删除传输记录表
*参数:      rule               ----> 策略信息
*
*           返回值              ----> true 允许删除，false 拒绝删除
*
*注释:
*******************************************************************************************/
bool is_clean_table(fs_rule_t *rule)
{

    bool is_drop = false;
    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
    char record_file_path[FSYNC_PATH_MAX_LEN] = {0};
    sprintf(record_file_path, "%s/%s.cf", FSYNC_CONF_RECORD_PATH, rule->task_name);
    int int_val = 0;
    char *str_val = NULL;
    const char *group = "SYS";
    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();

    if (rule->del_record != FSYNC_TURN_OFF) {
        is_drop = true;
        PRINT_INFO_HEAD;
        print_info("[TASK%d] del_recoed = %d ,will delete record", rule->task_id, rule->del_record);
    }

    //同步方向对比
    if (!is_drop) {
        g_key_file_load_from_file(keyfile, record_file_path, G_KEY_FILE_NONE, &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("load last record configure = %s failed:%s!", record_file_path, key_error->message);
            g_error_free(key_error);
            int_val = -1;
        } else {
            int_val = g_key_file_get_integer(keyfile, group, "Area", &key_error);
        }
        if ((int_val >= 0) && (int_val != rule->sync_area)) {
            is_drop = true;
            PRINT_INFO_HEAD;
            print_info("[TASK%d] old_area = %d ,new_area = %d ,will drop", rule->task_id, int_val, rule->sync_area);
        }
    }


    if (!is_drop) {  //内网服务器协议对比
        str_val = g_key_file_get_string(keyfile, group, "InFileSys", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read InFileSys failed will drop !");
        } else {
            if (protocol_str_to_int(str_val) != rule->int_srv.protocol) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("in srv protocol is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("InFileSys new = %s ,old = %s", protocol_int_to_str(rule->int_srv.protocol), str_val);
            g_free(str_val);
        }
    }


    if (!is_drop) {      //内网IP对比
        str_val = g_key_file_get_string(keyfile, group, "InIp", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read InIp failed !");
        } else {
            if (strcmp(str_val, rule->int_srv.real_ip) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("in srv ip is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("InIp new = %s ,old = %s", str_val, rule->int_srv.real_ip);
            g_free(str_val);
        }
    }

    if (!is_drop) {       //内网共享路径对比
        str_val = g_key_file_get_string(keyfile, group, "InSharePath", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read InSharePath failed");
        } else {
            if (strcmp(str_val, rule->int_srv.share_path) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("in srv share path is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("InSharePath new = %s ,old = %s", rule->int_srv.share_path, str_val);
            g_free(str_val);
        }
    }

    if (!is_drop) {        //内网子路径对比
        str_val = g_key_file_get_string(keyfile, group, "InSubPath", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read InSubPath failed");
        } else {
            if (strcmp(str_val, rule->int_srv.sub_path) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("in srv sub path is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("new InSubPath = %s ,old InSubPath = %s", rule->int_srv.sub_path, str_val);
            g_free(str_val);
        }
    }

    if (!is_drop) {  //外网服务器协议对比
        str_val = g_key_file_get_string(keyfile, group, "OutFileSys", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read OutFileSys failed !");
        } else {
            if (protocol_str_to_int(str_val) != rule->out_srv.protocol) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("out protocol path is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("OutFileSys new = %s ,old = %s", protocol_int_to_str(rule->out_srv.protocol), str_val);
            g_free(str_val);
        }
    }


    if (!is_drop) {      //外网IP对比
        str_val = g_key_file_get_string(keyfile, group, "OutIp", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read OutIp failed !");
        } else {
            if (strcmp(str_val, rule->out_srv.real_ip) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("out srv ip is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("OutIp new = %s ,old = %s", rule->out_srv.real_ip, str_val);
            g_free(str_val);
        }
    }

    if (!is_drop) {       //外网共享路径对比
        str_val = g_key_file_get_string(keyfile, group, "OutSharePath", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read OutSharePath failed !");
        } else {
            if (strcmp(str_val, rule->out_srv.share_path) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("out srv share path is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("OutSharePath new = %s ,old = %s", rule->out_srv.share_path, str_val);
            g_free(str_val);
        }
    }

    if (!is_drop) {        //外网子路径对比
        str_val = g_key_file_get_string(keyfile, group, "OutSubPath", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("read OutSubPath failed !");
        } else {
            if (strcmp(str_val, rule->out_srv.sub_path) != 0) {
                is_drop = true;
                PRINT_INFO_HEAD;
                print_info("out srv sub path is change ,will drop");
            }
            PRINT_INFO_HEAD;
            print_info("OutSubPath new = %s ,old = %s", rule->out_srv.sub_path, str_val);
            g_free(str_val);
        }
    }

    if (is_drop) {
        recorder->drop_table(recorder, rule->task_name, INT_DIR_TYPE);
        recorder->drop_table(recorder, rule->task_name, INT_FILE_TYPE);
        recorder->drop_table(recorder, rule->task_name, OUT_DIR_TYPE);
        recorder->drop_table(recorder, rule->task_name, OUT_FILE_TYPE);
        recorder->drop_table(recorder, rule->task_name, VIRUS_FILE_TYPE);
    }

    recorder->drop_table(recorder, rule->task_name, KEYWORD_FILE_TYPE);
    recorder->close_db(recorder);

    g_key_file_free(keyfile);
    return is_drop;
}

bool rewrite_record_file(fs_rule_t *rule)
{

    mkdir_r(FSYNC_CONF_RECORD_PATH, FSYNC_DIR_DEFAULT_MODE);
    char buf[FSYNC_PATH_MAX_LEN] = {0};
    char record_path[FSYNC_PATH_MAX_LEN] = {0};

    sprintf(record_path, "%s/%s.cf", FSYNC_CONF_RECORD_PATH, rule->task_name);

    FILE *record_file_fd = fopen(record_path, "wb");
    if (record_file_fd == NULL) {
        PRINT_ERR_HEAD;
        print_err("open %s failed:%s", record_path, strerror(errno));
        return false;
    }
    sprintf(buf, "[SYS]\n");
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "Area=%d\n\n", rule->sync_area);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "InFileSys=%s\n", protocol_int_to_str(rule->int_srv.protocol));
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "InIp=%s\n", rule->int_srv.real_ip);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "InSharePath=%s\n", rule->int_srv.share_path);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "InSubPath=%s\n", rule->int_srv.sub_path);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "\n");
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "OutFileSys=%s\n", protocol_int_to_str(rule->out_srv.protocol));
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "OutIp=%s\n", rule->out_srv.real_ip);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "OutSharePath=%s\n", rule->out_srv.share_path);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "OutSubPath=%s\n", rule->out_srv.sub_path);
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "\n");
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    sprintf(buf, "pid=%u\n", getpid());
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    time_t local_time = time(NULL);
    sprintf(buf, "start=%s\n", ctime(&local_time));
    fwrite(buf, sizeof(char), strlen(buf), record_file_fd);

    fclose(record_file_fd);

    return true;
}

/*******************************************************************************************
*功能:      初始化工作对象
*参数:       protocol           ----> 协议
*
*           返回值              ----> fs_work_t 成功 , NULL 失败
*
*注释:
*******************************************************************************************/
fs_work_t *create_worker_obj(int protocol)
{

    fs_work_t *worker = NULL;
    if (protocol == FSYNC_FTP_PROTOCOL) {
        worker = create_ftp_worker();
    } else if (protocol == FSYNC_SFTP_PROTOCOL) {
#ifdef FSYNC_USE_CURL
        worker = create_sftp_curl_worker();
#else
        worker = create_sftp_worker();
#endif
    } else if (protocol == FSYNC_FTPS_PROTOCOL) {
        worker = create_ftps_worker();
    } else if (protocol == FSYNC_CIFS_PROTOCOL) {
        worker = create_smb_worker();
    } else if (protocol == FSYNC_NFS_PROTOCOL) {
        worker = create_smb_worker();
    } else {
        PRINT_DBG_HEAD;
        print_dbg("protocol = %d ,not support !", protocol);
        return NULL;
    }

    if (worker == NULL) {
        PRINT_ERR_HEAD;
        print_err("create obj failed !");
        return NULL;
    }

    worker->protocol = protocol;
    return worker;
}

/*******************************************************************************************
*功能:      检测所有服务器连接
*参数:       rule               ----> 规则信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool connect_all_server(fs_rule_t *rule, fs_work_t *int_obj, fs_work_t *out_obj, fs_work_t *intbak_obj,
                        fs_work_t *outbak_obj)
{

    bool bret = false;
    CLOGMANAGE web_log;
    web_log.Init(rule->syslog_flag);
    char buf[FSYNC_NAME_MAX_LEN] = {0};

    for (int i = 0; i < 3; i++) {
        bret = int_obj->connect_server(int_obj->handle);
        if (bret) {
            break;
        } else {
            sleep(1);
        }
    }
    if (rule->log_flag == FSYNC_TURN_ON) {
        if (bret) {
            sprintf(buf, "%s%s", MOUNT_SUCCESS, INT_SRV);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip, "",
                                     rule->int_srv.share_path, "", "", S_SUCCESS, buf, false);
        } else {
            sprintf(buf, "%s%s", MOUNT_FAILED, INT_SRV);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip, "",
                                     rule->int_srv.share_path, "", "", S_FAILED, buf, false);
        }
    }
    if (bret) {
        for (int i = 0; i < 3; i++) {
            bret = out_obj->connect_server(out_obj->handle);
            if (bret) {
                break;
            } else {
                sleep(1);
            }
        }
        if (rule->log_flag == FSYNC_TURN_ON) {
            if (bret) {
                sprintf(buf, "%s%s", MOUNT_SUCCESS, OUT_SRV);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_srv.real_ip, "",
                                         rule->out_srv.share_path, "", "", S_SUCCESS, buf, true);
            } else {
                sprintf(buf, "%s%s", MOUNT_FAILED, OUT_SRV);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_srv.real_ip, "",
                                         rule->out_srv.share_path, "", "", S_FAILED, buf, true);
            }
        }
    }

    if (bret && (rule->int_bak_flag == FSYNC_TURN_ON)) {
        for (int i = 0; i < 3; i++) {
            bret = intbak_obj->connect_server(intbak_obj->handle);
            if (bret) {
                break;
            } else {
                sleep(1);
            }
        }
        if (rule->log_flag == FSYNC_TURN_ON) {
            if (bret) {
                sprintf(buf, "%s%s", MOUNT_SUCCESS, INT_BAK);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_bak.real_ip, "",
                                         rule->int_bak.share_path, "", "", S_SUCCESS, buf, false);
            } else {
                sprintf(buf, "%s%s", MOUNT_FAILED, INT_BAK);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_bak.real_ip, "",
                                         rule->int_bak.share_path, "", "", S_FAILED, buf, false);
            }
        }
    }

    if (bret && (rule->out_bak_flag == FSYNC_TURN_ON)) {
        for (int i = 0; i < 3; i++) {
            bret = outbak_obj->connect_server(outbak_obj->handle);
            if (bret) {
                break;
            } else {
                sleep(1);
            }
        }
        if (rule->log_flag == FSYNC_TURN_ON) {
            if (bret) {
                sprintf(buf, "%s%s", MOUNT_SUCCESS, OUT_BAK);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_bak.real_ip, "",
                                         rule->out_bak.share_path, "", "", S_SUCCESS, buf, true);
            } else {
                sprintf(buf, "%s%s", MOUNT_FAILED, OUT_BAK);
                web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_bak.real_ip, "",
                                         rule->out_bak.share_path, "", "", S_FAILED, buf, true);
            }
        }
    }

    return bret;

}

/*******************************************************************************************
*功能:      关闭所有服务器连接
*参数:       rule               ----> 规则信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> void
*
*注释:
*******************************************************************************************/
void close_all_server(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                      fs_work_t *outbak_worker)
{

    int_worker->destroy_worker_obj(int_worker);

    out_worker->destroy_worker_obj(out_worker);

    if (rule->int_bak_flag == FSYNC_TURN_ON) {
        intbak_worker->destroy_worker_obj(intbak_worker);
    }

    if (rule->out_bak_flag == FSYNC_TURN_ON) {
        outbak_worker->destroy_worker_obj(outbak_worker);
    }

    return;

}

/*******************************************************************************************
*功能:      创建所有发送任务连接
*参数:       rule               ----> 规则信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool create_all_data_connect(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                             fs_work_t *outbak_worker)
{

    bool bret = true;

    if ((int_worker->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE) {
        bret = int_worker->connect_server(int_worker->handle);
    }
    if (bret && ((out_worker->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE)) {
        bret = out_worker->connect_server(out_worker->handle);
    }

    if (bret && (rule->int_bak_flag == FSYNC_TURN_ON) &&
        ((intbak_worker->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE)) {
        bret = intbak_worker->connect_server(intbak_worker->handle);
    }

    if (bret && (rule->out_bak_flag == FSYNC_TURN_ON) &&
        ((outbak_worker->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE)) {
        bret = out_worker->connect_server(outbak_worker->handle);
    }

    return bret;

}

/*******************************************************************************************
*功能:      检测所有服务器连接
*参数:       rule               ----> 规则信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool check_all_server(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                      fs_work_t *outbak_worker)
{

    bool bret = true;

    bret = int_worker->check_server_connect(int_worker->handle);
    if (!bret) {
        PRINT_ERR_HEAD;
        print_info("check connect of intsrv failed! will reconnect");
        bret = int_worker->connect_server(int_worker->handle);
    }

    if (bret) {
        bret = out_worker->check_server_connect(out_worker->handle);
        if (!bret) {
            PRINT_ERR_HEAD;
            print_info("check connect of outsrv failed! will reconnect");
            bret = out_worker->connect_server(out_worker->handle);
        }
    }

    if (bret && (rule->int_bak_flag == FSYNC_TURN_ON)) {
        bret = intbak_worker->check_server_connect(intbak_worker->handle);
        if (!bret) {
            PRINT_ERR_HEAD;
            print_info("check connect of intbak failed! will reconnect");
            bret = intbak_worker->connect_server(intbak_worker->handle);
        }
    }

    if (bret && (rule->out_bak_flag == FSYNC_TURN_ON)) {
        bret = outbak_worker->check_server_connect(outbak_worker->handle);
        if (!bret) {
            PRINT_ERR_HEAD;
            print_info("check connect of outbak failed! will reconnect");
            bret = outbak_worker->connect_server(outbak_worker->handle);
        }
    }

    return bret;
}

/*******************************************************************************************
*功能:      检测所有扫描路径
*参数:       rule               ----> 规则信息
*           int_worker          ----> 内网服务器对象
*           out_worker          ----> 外网服务器对象
*           intbak_worker       ----> 内网备份服务器对象
*           outbak_worker       ----> 外网备份服务器对象
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool check_all_path(fs_rule_t *rule, fs_work_t *int_worker, fs_work_t *out_worker, fs_work_t *intbak_worker,
                    fs_work_t *outbak_worker)
{

    bool bret = true;
    char buf[FSYNC_NAME_MAX_LEN] = {0};
    CLOGMANAGE web_log;
    web_log.Init(rule->syslog_flag);

    bret = int_worker->check_scan_path(int_worker->handle);
    if (bret) {
        sprintf(buf, "%s%s", CAN_FIND_SUB_PATH, INT_SRV);
        web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip, "", rule->int_srv.sub_path, "",
                                 "", S_SUCCESS, buf, false);
    } else {
        sprintf(buf, "%s%s", NOT_FIND_SUB_PATH, INT_SRV);
        web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_srv.real_ip, "", rule->int_srv.sub_path, "",
                                 "", S_FAILED, buf, false);
        PRINT_ERR_HEAD;
        print_info("check intsrv path = %s failed!", rule->int_srv.scan_path);
        return false;
    }


    bret = out_worker->check_scan_path(out_worker->handle);
    if (bret) {
        sprintf(buf, "%s%s", CAN_FIND_SUB_PATH, OUT_SRV);
        web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_srv.real_ip, "", rule->out_srv.sub_path, "",
                                 "", S_SUCCESS, buf, true);
    } else {
        sprintf(buf, "%s%s", NOT_FIND_SUB_PATH, OUT_SRV);
        web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_srv.real_ip, "", rule->out_srv.sub_path, "",
                                 "", S_FAILED, buf, true);
        PRINT_ERR_HEAD;
        print_info("check outsrv path = %s failed!", rule->out_srv.scan_path);
        return false;
    }


    if (rule->int_bak_flag == FSYNC_TURN_ON) {
        bret = intbak_worker->check_scan_path(intbak_worker->handle);
        if (bret) {
            sprintf(buf, "%s%s", CAN_FIND_SUB_PATH, INT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_bak.real_ip, "", rule->int_bak.sub_path,
                                     "", "", S_SUCCESS, buf, false);
        } else {
            sprintf(buf, "%s%s", NOT_FIND_SUB_PATH, INT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->int_bak.real_ip, "", rule->int_bak.sub_path,
                                     "", "", S_FAILED, buf, false);
            PRINT_ERR_HEAD;
            print_info("check intbak path = %s failed!", rule->int_bak.scan_path);
            return false;
        }

    }

    if (bret && (rule->out_bak_flag == FSYNC_TURN_ON)) {
        bret = outbak_worker->check_scan_path(outbak_worker->handle);
        if (bret) {
            sprintf(buf, "%s%s", CAN_FIND_SUB_PATH, OUT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_bak.real_ip, "", rule->out_bak.sub_path,
                                     "", "", S_SUCCESS, buf, true);
        } else {
            sprintf(buf, "%s%s", NOT_FIND_SUB_PATH, OUT_BAK);
            web_log.WriteFileSyncLog(rule->task_id, rule->rule_name, rule->out_bak.real_ip, "", rule->out_bak.sub_path,
                                     "", "", S_FAILED, buf, true);
            PRINT_ERR_HEAD;
            print_info("check outbak path = %s failed!", rule->out_bak.scan_path);
            return false;
        }
    }

    return bret;
}

/*******************************************************************************************
*功能:       创建还原临时后缀
*参数:       is_make_tmp_file                   ----> 创建/还原临时后缀文件
*            rule                               ----> 策略信息
*            sync_info                          ----> 同步文件信息
*            tmp_target_file                    ----> 临时目的端文件路径
*            tmp_backup_file                    ----> 临时备份端文件路径
*            返回值                             ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool make_tmp_name(bool is_make_tmp_file, fs_rule_t *rule, fs_sync_t *sync_info, fs_work_t *dst_worker,
                   char *tmp_dst_file, fs_work_t *bak_worker, char *tmp_bak_file)
{

    bool bret = false;
    if (is_make_tmp_file) {
        if ((rule->delay_time == FSYNC_TURN_OFF) || (strlen(rule->tmp_extname) == 0)) {
            strcpy(tmp_dst_file, sync_info->dst_file);
        } else {
            sprintf(tmp_dst_file, "%s%s", sync_info->dst_file, rule->tmp_extname);
        }
        if (sync_info->is_bak) {
            if (rule->delay_time == FSYNC_TURN_OFF) {
                strcpy(tmp_bak_file, sync_info->bak_file);
            } else {
                sprintf(tmp_bak_file, "%s%s", sync_info->bak_file, rule->tmp_extname);
            }
        }
    } else {
        if ((rule->delay_time != FSYNC_TURN_OFF) && ((strlen(rule->tmp_extname) > 0))) {
            for (int i = 0; i < 3; i++) {
                if (dst_worker->rename(dst_worker->handle, tmp_dst_file, sync_info->dst_file)) {
                    bret = true;
                    break;
                }
                sleep(3);
            }
            if (!bret) {
                dst_worker->remove(dst_worker->handle, tmp_dst_file);
            }
        }
        if ((sync_info->is_bak) && (rule->delay_time != FSYNC_TURN_OFF) && (strlen(rule->tmp_extname) > 0)) {
            for (int i = 0; i < 3; i++) {
                if (bak_worker->rename(bak_worker->handle, tmp_bak_file, sync_info->bak_file)) {
                    bret = true;
                    break;
                }
                sleep(3);
            }
            if (!bret) {
                bak_worker->remove(bak_worker->handle, tmp_bak_file);
            }
        }
    }
    return true;
}

/*******************************************************************************************
*功能:       文件拷贝
*参数:       in_to_out                          ----> 同步方向
*            send_msg                           ----> 发送模块信息
*            web_log                            ----> 写日志对象
*            log_info                           ----> 日志信息
*            source_worker                      ----> 源端对象
*            source_file                        ----> 源端文件
*            source_stat                        ----> 源文件状态
*            target_worker                      ----> 目的端对象
*            target_file                        ----> 目的端文件
*            backup_worker                      ----> 备份端对象
*            backup_file                        ----> 备份文件
*            返回值                             ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool copy_file(bool in_to_out, fs_send_t *send_msg, CLOGMANAGE *web_log, fs_log_t *log_info, fs_work_t *src_worker,
               const char *src_file, struct stat *src_stat, fs_work_t *dst_worker, const char *dst_file,
               fs_work_t *bak_worker, const char *bak_file)
{

    bool bret = false;
    static unsigned int failed_times = 0;
    fs_rule_t *rule = send_msg->rule;
    char remark[FSYNC_NAME_MAX_LEN] = {0};
    char buf[8192] = {0};
    size_t r_len = 0;
    size_t w_len = 0;
    size_t rw_len = 0;
    unsigned long file_size = 0;

    bret = src_worker->open_source_file(src_worker->handle, src_file);
    if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
        web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                  log_info->log_src_path, log_info->log_dst_path, log_info->file_name, S_FAILED,
                                  OPEN_SOURCE_FAILED, !in_to_out);
    }

    if (bret) {
        bret = dst_worker->open_target_file(dst_worker->handle, dst_file);
        if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                      S_FAILED, OPEN_TARGET_FAILED, !in_to_out);
        }
    }

    if (bret && (bak_worker != NULL)) {
        bret = bak_worker->open_target_file(bak_worker->handle, bak_file);
        if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                      S_FAILED, OPEN_BACK_FAILED, !in_to_out);
        }
    }

    if (!bret) {
        failed_times++;
        if (failed_times > 100) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d] open file failed times > 100 ,will exit and restart", rule->task_id);
            exit(-1);
        }
    } else {
        failed_times = 0;
    }

    while ((bret) && ((r_len = src_worker->read(src_worker->handle, buf, sizeof(buf))) > 0)) {

        if (rule->keyword_flag == FSYNC_TURN_ON) {
            bret = check_keyword(send_msg, src_file, src_stat, buf, r_len, remark);
            if (!bret) {
                bret = false;
                break;
            }
        }

        w_len = 0;
        for (int i = 0; i < FSYNC_RETRY_TIME; i++) {
            int dst_len = dst_worker->write(dst_worker->handle, buf + w_len, r_len - w_len);
            if (dst_len < 0) {
                bret = false;
                break;
            } else if (dst_len < (r_len - w_len)) {
                w_len += dst_len;
            } else {
                break;
            }
        }

        if (bak_worker != NULL) {
            w_len = 0;
            for (int i = 0; i < FSYNC_RETRY_TIME; i++) {
                int dst_len = bak_worker->write(bak_worker->handle, buf + w_len, r_len - w_len);
                if (dst_len < 0) {
                    bret = false;
                    break;
                } else if (dst_len < (r_len - w_len)) {
                    w_len += dst_len;
                } else {
                    break;
                }
            }
        }

        file_size += r_len;
        rw_len++;
        if (rw_len > 10) {
            rw_len = 0;
            gettimeofday(send_msg->work_stat, NULL);
        }
    }


    if ((strlen(remark) > 0) && (rule->log_flag != FSYNC_TURN_OFF)) {
        char keyword_info[FSYNC_PATH_MAX_LEN] = {0};
        sprintf(keyword_info, "%s:%s", FORBIDWORD, remark);
        if (check_str_utf8(remark, strlen(remark))) {
            sprintf(keyword_info, "%s:%s", FORBIDWORD, remark);
        } else {
            char tmp_remark[FSYNC_PATH_MAX_LEN] = {0};
            code_convert("gb2312", "utf-8", remark, strlen(remark), tmp_remark, sizeof(tmp_remark));
            sprintf(keyword_info, "%s:%s", FORBIDWORD, tmp_remark);
        }
        web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, keyword_info, FILE_SYNC_MOD,
                                log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                in_to_out ? "I" : "O");
    }

    if (file_size != src_stat->st_size) {
        PRINT_ERR_HEAD;
        print_err("[TASK%d] src file %s size = %zu ,dst %s file size = %zu", rule->task_id, src_file, src_stat->st_size,
                  dst_file, file_size);
        bret = false;
    }

    src_worker->close_data_handle(src_worker->handle);
    dst_worker->close_data_handle(dst_worker->handle);

    if (bak_worker != NULL) {
        bak_worker->close_data_handle(bak_worker->handle);
        if (!bret) {
            bak_worker->remove(bak_worker->handle, bak_file);
        }
    }

    if (!bret) {
        dst_worker->remove(dst_worker->handle, dst_file);
    }

    return bret;
}

void umount_local_path(fs_rule_t *rule)
{

    if (rule->int_srv.protocol == FSYNC_CIFS_PROTOCOL || rule->int_srv.protocol == FSYNC_NFS_PROTOCOL) {
        umount2(rule->int_srv.mount_path, MNT_DETACH);
    }
    if (rule->out_srv.protocol == FSYNC_CIFS_PROTOCOL || rule->out_srv.protocol == FSYNC_NFS_PROTOCOL) {
        umount2(rule->out_srv.mount_path, MNT_DETACH);
    }
    if ((rule->int_bak_flag == FSYNC_TURN_ON) &&
        (rule->int_bak.protocol == FSYNC_CIFS_PROTOCOL || rule->int_bak.protocol == FSYNC_NFS_PROTOCOL)) {
        umount2(rule->int_bak.mount_path, MNT_DETACH);
    }
    if ((rule->out_bak_flag == FSYNC_TURN_ON) &&
        ((rule->out_bak.protocol == FSYNC_CIFS_PROTOCOL || rule->out_bak.protocol == FSYNC_NFS_PROTOCOL))) {
        umount2(rule->out_bak.mount_path, MNT_DETACH);
    }
    PRINT_INFO_HEAD;
    print_info("[TASK%d] umount local path over", rule->task_id);
}

/*********************************************curl copy***************************************************************/


void *read_data(void *pth_arg)
{

    int r_len = 0;
    char buf[FSYNC_BUF_MAX_LEN] = {0};
    rw_info_t *rw_info = (rw_info_t *) pth_arg;
    fs_work_t *src_worker = rw_info->worker;
    if (src_worker->protocol != FSYNC_SFTP_PROTOCOL) {
        while (1) {
            r_len = src_worker->read(src_worker->handle, buf, sizeof(buf));
            rw_data_t *r_data = (rw_data_t *) calloc(1, sizeof(rw_data_t));
            memcpy(r_data->buf, buf, r_len);
            r_data->len = r_len;
            if (g_async_queue_length(rw_info->data_queue) > 500) {
                sleep(1);
            }
            g_async_queue_push(rw_info->data_queue, r_data);
            //printf("rlen = %d\n", r_len);
            //sleep(1);
            if (r_len == 0) {
                break;
            }
        }
    } else {
        curl_handle_t *curl_handle = (curl_handle_t *) (rw_info->worker->handle);
        char cmd[FSYNC_CMD_MAX_LEN] = {0};
        CURLcode res;
        sprintf(cmd, "sftp://%s:%d/%s", curl_handle->remote_ip, curl_handle->port, rw_info->path);

        curl_easy_reset(curl_handle->curl);
        curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
        if (strlen(curl_handle->password) > 0) {
            curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
            curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
        }
        curl_easy_setopt(curl_handle->curl, CURLOPT_WRITEFUNCTION, curl_sftp_read_cb);
        curl_easy_setopt(curl_handle->curl, CURLOPT_WRITEDATA, rw_info->data_queue);

        curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
        curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

        res = curl_easy_perform(curl_handle->curl);

        rw_data_t *r_data = (rw_data_t *) calloc(1, sizeof(rw_data_t));
        r_data->len = 0;
        g_async_queue_push(rw_info->data_queue, r_data);

        if (CURLE_OK != res) {
            PRINT_ERR_HEAD;
            print_err("sftp read file = %s failed:%s", rw_info->path, curl_easy_strerror(res));
        } else {
            PRINT_DBG_HEAD;
            print_dbg("sftp read file = %s success", rw_info->path);
        }

    }
    return NULL;
}

void *write_data(void *pth_arg)
{

    int w_len = 0;
    rw_data_t *w_data = NULL;
    rw_info_t *rw_info = (rw_info_t *) pth_arg;
    fs_work_t *dst_worker = rw_info->worker;
    if (dst_worker->protocol != FSYNC_SFTP_PROTOCOL) {
        while (1) {
            w_data = (rw_data_t *) (g_async_queue_try_pop(rw_info->data_queue));
            if (w_data == NULL) {
                continue;
            }
            if (w_data->len == 0) {
                free(w_data);
                break;
            }
            w_len = dst_worker->write(dst_worker->handle, w_data->buf, w_data->len);
            //printf("wlen = %d\n", w_len);
            if (unlikely((w_len == -1) || (w_len != w_data->len))) {
                free(w_data);
                break;
            }
            free(w_data);
        }

    } else {
        curl_handle_t *curl_handle = (curl_handle_t *) (rw_info->worker->handle);
        char cmd[FSYNC_CMD_MAX_LEN] = {0};
        CURLcode res;
        sprintf(cmd, "sftp://%s:%d/%s", curl_handle->remote_ip, curl_handle->port, rw_info->path);
        curl_easy_reset(curl_handle->curl);
        curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
        if (strlen(curl_handle->password) > 0) {
            curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
            curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
        }
        curl_easy_setopt(curl_handle->curl, CURLOPT_READFUNCTION, curl_sftp_write_cb);
        curl_easy_setopt(curl_handle->curl, CURLOPT_READDATA, rw_info->data_queue);

        curl_easy_setopt(curl_handle->curl, CURLOPT_FTP_CREATE_MISSING_DIRS, 0);
        curl_easy_setopt(curl_handle->curl, CURLOPT_UPLOAD, 1);
        curl_easy_setopt(curl_handle->curl, CURLOPT_INFILESIZE, rw_info->size);

        curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
        curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

        res = curl_easy_perform(curl_handle->curl);

        if (CURLE_OK != res) {
            PRINT_ERR_HEAD;
            print_dbg("sftp write file = %s failed:%s", rw_info->path, curl_easy_strerror(res));
        } else {
            PRINT_DBG_HEAD;
            print_dbg("sftp write = %s success", rw_info->path);
        }

    }
    return NULL;
}

/*******************************************************************************************
*功能:       文件拷贝
*参数:       in_to_out                          ----> 同步方向
*            send_msg                           ----> 发送模块信息
*            web_log                            ----> 写日志对象
*            log_info                           ----> 日志信息
*            source_worker                      ----> 源端对象
*            source_file                        ----> 源端文件
*            source_stat                        ----> 源文件状态
*            target_worker                      ----> 目的端对象
*            target_file                        ----> 目的端文件
*            backup_worker                      ----> 备份端对象
*            backup_file                        ----> 备份文件
*            返回值                             ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool curl_copy_file(bool in_to_out, fs_send_t *send_msg, CLOGMANAGE *web_log, fs_log_t *log_info, fs_work_t *src_worker,
                    const char *src_file, struct stat *src_stat, fs_work_t *dst_worker, const char *dst_file,
                    fs_work_t *bak_worker, const char *bak_file)
{

    bool bret = false;
    int count = 0;
    static unsigned int failed_times = 0;
    fs_rule_t *rule = send_msg->rule;
    char remark[FSYNC_NAME_MAX_LEN] = {0};
    rw_info_t src_rw_info = {0, 0, NULL, NULL, {0}};
    src_rw_info.data_queue = g_async_queue_new_full(free);
    src_rw_info.worker = src_worker;
    src_rw_info.size = src_stat->st_size;
    strcpy(src_rw_info.path, src_file);

    rw_info_t dst_rw_info = {0, 0, NULL, NULL, {0}};
    dst_rw_info.data_queue = g_async_queue_new_full(free);
    dst_rw_info.worker = dst_worker;
    dst_rw_info.size = src_stat->st_size;
    strcpy(dst_rw_info.path, dst_file);

    rw_info_t bak_rw_info = {0, 0, NULL, NULL, {0}};
    if (bak_worker != NULL) {
        bak_rw_info.data_queue = g_async_queue_new_full(free);
        bak_rw_info.worker = bak_worker;
        bak_rw_info.size = src_stat->st_size;
        strcpy(bak_rw_info.path, bak_file);
    }

    bret = src_worker->open_source_file(src_worker->handle, src_file);
    if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
        web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                  log_info->log_src_path, log_info->log_dst_path, log_info->file_name, S_FAILED,
                                  OPEN_SOURCE_FAILED, !in_to_out);
    }

    if (bret) {
        bret = dst_worker->open_target_file(dst_worker->handle, dst_file);
        if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                      S_FAILED, OPEN_TARGET_FAILED, !in_to_out);
        }
    }

    if (bret && (bak_worker != NULL)) {
        bret = bak_worker->open_target_file(bak_worker->handle, bak_file);
        if ((!bret) && (rule->log_flag != FSYNC_TURN_OFF)) {
            web_log->WriteFileSyncLog(rule->task_id, rule->rule_name, log_info->src_ip, log_info->dst_ip,
                                      log_info->log_src_path, log_info->log_dst_path, log_info->file_name,
                                      S_FAILED, OPEN_BACK_FAILED, !in_to_out);
        }
    }

    if (!bret) {
        failed_times++;
        if (failed_times > 100) {
            PRINT_ERR_HEAD;
            print_err("[TASK%d] open file failed times > 100 ,will exit and restart", rule->task_id);
            exit(-1);
        }
    } else {
        failed_times = 0;
    }


    pthread_t src_tid, dst_tid, bak_tid;
    if (pthread_create(&src_tid, NULL, read_data, (void *) &src_rw_info) != 0) {
        PRINT_ERR_HEAD;
        print_err("create src pthread failed:%s", strerror(errno));
    }
    if (pthread_create(&dst_tid, NULL, write_data, (void *) &dst_rw_info)) {
        PRINT_ERR_HEAD;
        print_err("create dst pthread failed:%s", strerror(errno));
    }
    if (bak_worker != NULL) {
        pthread_create(&bak_tid, NULL, write_data, (void *) &bak_rw_info);
    }


    rw_data_t *rw_data = NULL;
    while (bret) {
        rw_data = (rw_data_t *) g_async_queue_try_pop(src_rw_info.data_queue);
        if (rw_data == NULL) {
            continue;
        }

        if (rule->keyword_flag == FSYNC_TURN_ON) {
            bret = check_keyword(send_msg, src_file, src_stat, rw_data->buf, rw_data->len, remark);
            if (!bret) {
                bret = false;
                break;
            }
        }

        if (rw_data->len == 0) {
            if (bak_worker != NULL) {
                rw_data_t *bak_data = (rw_data_t *) calloc(1, sizeof(rw_data_t));
                memcpy(bak_data, rw_data, sizeof(rw_data_t));
                g_async_queue_push(bak_rw_info.data_queue, bak_data);
            }
            g_async_queue_push(dst_rw_info.data_queue, rw_data);
            break;
        }

        if (bak_worker != NULL) {
            rw_data_t *bak_data = (rw_data_t *) calloc(1, sizeof(rw_data_t));
            memcpy(bak_data, rw_data, sizeof(rw_data_t));
            g_async_queue_push(bak_rw_info.data_queue, bak_data);
        }
        g_async_queue_push(dst_rw_info.data_queue, rw_data);
        count++;
        if (count > 100) {
            count = 0;
            gettimeofday(send_msg->work_stat, NULL);
        }

    }

    pthread_join(src_tid, NULL);
    pthread_join(dst_tid, NULL);
    if (bak_worker != NULL) {
        pthread_join(bak_tid, NULL);
    }


    if ((strlen(remark) > 0) && (rule->log_flag != FSYNC_TURN_OFF)) {
        char keyword_info[FSYNC_PATH_MAX_LEN] = {0};
        sprintf(keyword_info, "%s:%s", FORBIDWORD, remark);
        web_log->WriteFilterLog(rule->rule_name, log_info->log_src_path, keyword_info, FILE_SYNC_MOD,
                                log_info->src_ip, log_info->dst_ip, log_info->src_port, log_info->dst_port,
                                in_to_out ? "I" : "O");
    }

    g_async_queue_unref(src_rw_info.data_queue);
    src_worker->close_data_handle(src_worker->handle);

    g_async_queue_unref(dst_rw_info.data_queue);
    dst_worker->close_data_handle(dst_worker->handle);


    g_async_queue_unref(bak_rw_info.data_queue);
    if (bak_worker != NULL) {
        bak_worker->close_data_handle(bak_worker->handle);
        if (!bret) {
            bak_worker->remove(bak_worker->handle, bak_file);
        }
    }


    long bak_size = 0;
    if (bak_worker != NULL) {
        if (!bret) {
            bak_worker->remove(bak_worker->handle, bak_file);
        }
    }

    if (!bret) {
        dst_worker->remove(dst_worker->handle, dst_file);
    }

    return bret;

}
