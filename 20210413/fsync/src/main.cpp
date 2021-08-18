/*******************************************************************************************
*文件:    main.cpp
*描述:    文件同步模块
*
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------> 2019-11-10
*1.修改信号处理函数，由接收2号信号改为15号信号                 ------> 2020-03-01
*2.创建子进程前更改线程栈大小                                  ------> 2020-03-03
*3.加入版本号信息./msync -v                                    ------> 2020-03-18
*4.加入清除清除无用传输记录表功能                              ------> 2020-05-29
*******************************************************************************************/

#include "global_define.h"
#include "parse_conf.h"
#include "file_sync.h"
#include "task_manage.h"
#include "connect_manage.h"
#include "common_func.h"

static fs_rule_t rule[FSYNC_RULE_MAX_COUNT];
_log_preinit_(glog_p);

int clean_del_rules_record(GList **task_names_list) {
    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
    GList *table_list = NULL;

    recorder->show_tables(recorder, &table_list);
    for (GList *p_elem = table_list; p_elem != NULL; p_elem = p_elem->next) {

        bool is_del = true;
        char table_user[FSYNC_NAME_MAX_LEN] = {0};
        if (recorder->get_user_name((char *) p_elem->data, table_user) == NULL) {
            continue;
        }

        for (GList *task_elem = *task_names_list; task_elem != NULL; task_elem = task_elem->next) {
            if (strcmp(table_user, (char *) task_elem->data) == 0) {
                is_del = false;
                break;
            }
        }

        if (is_del) {
            recorder->drop_table_from_name(recorder, (char *) p_elem->data);
            PRINT_INFO_HEAD;
            print_info("table name = %s rule not exist,will delete!", p_elem->data);
        }
    }

    g_list_free_full(table_list, free);

    close_db(recorder);
    return 0;
}

int clean_del_record_file(GList **task_names_list) {

    const char *dir_name = FSYNC_CONF_RECORD_PATH;
    struct stat stat_buf;
    char path_name[FSYNC_PATH_MAX_LEN] = {0};
    struct dirent **name_list = NULL;

    if (access(FSYNC_CONF_RECORD_PATH, F_OK) != 0) {
        return -1;
    }

    int count = scandir(dir_name, &name_list, 0, alphasort);
    if (count < 0) {
        PRINT_ERR_HEAD;
        print_err("scandir = %s failed:%s", dir_name, strerror(errno));
        goto _exit;
    }

    for (int i = 0; i < count; i++) {
        bool is_del = true;
        if ((!strcmp(name_list[i]->d_name, ".")) || (!strcmp(name_list[i]->d_name, "..")) ||
            (!strcmp(name_list[i]->d_name, "/.."))) {
            continue;
        }

        sprintf(path_name, "%s/%s", dir_name, name_list[i]->d_name);

        memset(&stat_buf, 0, sizeof(stat_buf));
        stat(path_name, &stat_buf);
        if (name_list[i]->d_type == DT_DIR) {
            continue;
        } else {
            for (GList *p_elem = *task_names_list; p_elem != NULL; p_elem = p_elem->next) {
                char local_file[FSYNC_NAME_MAX_LEN] = {0};
                sprintf(local_file, "%s.cf", p_elem->data);
                if ((strcmp(name_list[i]->d_name, local_file) == 0) ||
                    (strcmp(name_list[i]->d_name, FSYNC_STACK_INFO_NAME) == 0)) {
                    is_del = false;
                    break;
                }
            }
            if (is_del) {
                remove(path_name);
                PRINT_INFO_HEAD;
                print_info("remove record file = %s", path_name);
            }
        }
    }

    _exit:
    if (name_list != NULL) {
        for (int i = 0; i < count; i++) {
            if (name_list[i] != NULL) {
                free(name_list[i]);
                name_list[i] = NULL;
            }
        }
        free(name_list);
        name_list = NULL;
    }

    return 0;
}

void recycle_proc(int signum) {

    pid_t over_pid = 0;
    int stat = 0;

    sleep(3);

    PRINT_INFO_HEAD;
    print_info("recv signal = %d ,task count = %d", signum, rule[0].task_count);
    sleep(1);
    for (int i = 0; i < rule[0].task_count; i++) {
        kill(rule[i].task_pid, SIGKILL);
        over_pid = waitpid(rule[i].task_pid, &stat, WNOHANG);
        PRINT_DBG_HEAD;
        print_dbg("pid = %u over", over_pid);
    }
    PRINT_INFO_HEAD;
    print_info("parent process pid = %u is over ", getpid());

    exit(1);
}


int record_mount_path_replace(const char *task_name, int record_type, const char *mount_path) {


    recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
    fs_task_t *tmp_task = NULL;
    GList *tmp_list = NULL;
    char tmp_name[FSYNC_NAME_MAX_LEN] = {0};
    int mount_path_len = strlen(mount_path);
    int off_set = mount_path_len + 1;
    int row = 1;
    char file_path[FSYNC_PATH_MAX_LEN] = {0};

    sprintf(tmp_name,"%s_tmp",task_name);
    recorder->create_table(recorder, tmp_name, record_type);

    while (row > 0) {
        row = recorder->select_all(recorder, task_name, record_type, 0, 10000, &tmp_list);

        for (GList *list_elem = tmp_list; tmp_list != NULL; list_elem = tmp_list) {
            tmp_task = (fs_task_t *) (list_elem->data);

            recorder->delete_data(recorder, task_name, record_type, tmp_task->path);
            if (strncmp(tmp_task->path, mount_path, mount_path_len) != 0) {
                char *p_start = tmp_task->path + off_set;
                strcpy(file_path, p_start);
                sprintf(tmp_task->path, "%s%s", mount_path, file_path);
            }
            recorder->insert_data(recorder, tmp_name, record_type, tmp_task->path, tmp_task->modify, tmp_task->size,
                                  NULL);
            free(tmp_task);
            tmp_list = g_list_delete_link(tmp_list, list_elem);
        }
    }

    recorder->drop_table(recorder, task_name, record_type);
    char task_table_name[FSYNC_NAME_MAX_LEN] = {0};
    char tmp_table_name[FSYNC_NAME_MAX_LEN] = {0};
    make_table_name(task_name,record_type,task_table_name);
    make_table_name(tmp_name,record_type,tmp_table_name);
    recorder->rename_table(recorder, tmp_table_name, task_table_name);
    recorder->close_db(recorder);
    recorder = NULL;

    return 0;
}

int reset_record_path(int rule_count) {

    for (int i = 0; i < rule_count; ++i) {
        if (rule[i].int_srv.protocol == FSYNC_CIFS_PROTOCOL || rule[i].int_srv.protocol == FSYNC_NFS_PROTOCOL) {
            record_mount_path_replace(rule[i].task_name, INT_DIR_TYPE, rule[i].int_srv.mount_path);
            record_mount_path_replace(rule[i].task_name, INT_FILE_TYPE, rule[i].int_srv.mount_path);
        }

        if (rule[i].out_srv.protocol == FSYNC_CIFS_PROTOCOL || rule[i].out_srv.protocol == FSYNC_NFS_PROTOCOL) {
            record_mount_path_replace(rule[i].task_name, OUT_DIR_TYPE, rule[i].out_srv.mount_path);
            record_mount_path_replace(rule[i].task_name, OUT_FILE_TYPE, rule[i].out_srv.mount_path);
        }
    }

    return 0;
}

int main(int argc, char **argv) {

    _log_init_(glog_p, msync);

    if ((argc == 2) && (strcasecmp(argv[1], "-v") == 0)) {
        printf("build time: %s %s\nVersion: %s\n", __DATE__, __TIME__, Version);
        return 0;
    }

    int all_num = get_all_rules_num(PREFILESYNC_CONF_PATH);
    if (all_num < 0) {
        return -1;
    }
    GList *rule_name_list = NULL;
    if (get_all_task_ID(PREFILESYNC_CONF_PATH, all_num, &rule_name_list) < 0) {
        return -1;
    }
    clean_del_rules_record(&rule_name_list);
    clean_del_record_file(&rule_name_list);
    g_list_free_full(rule_name_list, free);


    SYSINFO sys_info;
    memset(&sys_info, 0, sizeof(sys_info));
    get_sys_info(FSYNC_GLOBAL_CONFIG_PATH, &sys_info);

    if (!check_file_utf8(FSYNC_CONFIG_PATH)) {
        if (iconv_conf(FSYNC_CONFIG_PATH, FSYNC_CONFIG_PATH_UTF8) != 0) {
            PRINT_ERR_HEAD;
            print_err("iconv conf = %s to utf-8 conf = %s failed", FSYNC_CONFIG_PATH, FSYNC_CONFIG_PATH_UTF8);
            return -1;
        } else {
            if (rename(FSYNC_CONFIG_PATH_UTF8, FSYNC_CONFIG_PATH) != 0) {
                PRINT_ERR_HEAD;
                print_err("rename %s to  %s failed:%s", FSYNC_CONFIG_PATH_UTF8, FSYNC_CONFIG_PATH, strerror(errno));
                return -1;
            }
        }
    }
    int rule_num = get_rule_num(FSYNC_CONFIG_PATH);
    PRINT_INFO_HEAD;
    print_info("rule num = %d", rule_num);
    if (rule_num <= 0) {
        return -1;
    } else if (rule_num > FSYNC_RULE_MAX_COUNT) {
        PRINT_ERR_HEAD;
        print_err("max rule num = %d", FSYNC_RULE_MAX_COUNT);
        rule_num = FSYNC_RULE_MAX_COUNT;
    }

    memset(rule, 0, sizeof(fs_rule_t) * FSYNC_RULE_MAX_COUNT);
    if (get_rule_info(&sys_info, FSYNC_CONFIG_PATH, rule, rule_num) != 0) {
        PRINT_ERR_HEAD;
        print_err("get rule info failed !");
        return -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("get rule info success !");
    }

    set_rule_info(rule, rule_num);

    if (access(FSYNC_CONFIG_FLAG_PATH, F_OK) != 0) {
        PRINT_INFO_HEAD;
        print_info("start to init record data,wait...");
        char cmd_buf[FSYNC_PATH_MAX_LEN] = {0};
        reset_record_path(rule_num);
        sprintf(cmd_buf, "touch %s", FSYNC_CONFIG_FLAG_PATH);
        system(cmd_buf);
    }


    set_stack_size(FSYNC_STACK_MAX_SIZE);
#if ((SUOS_V == 8) || SUOS_V == 81)
    g_thread_init(NULL);
#endif
    pid_t tmp_pid = 0;

    for (int i = 0; i < rule_num; i++) {
        tmp_pid = fork();
        if (tmp_pid < 0) {
            PRINT_ERR_HEAD;
            print_err("create child process failed !");
            return -1;
        } else if (tmp_pid == 0) {
            create_task(&(rule[i]));
            exit(0);
        } else {
            rule[i].task_pid = tmp_pid;
            PRINT_INFO_HEAD;
            print_info("create group = [TASK%d] ,task name = %s success ,pid = %u", rule[i].task_id, rule[i].task_name,
                       rule[i].task_pid);
        }
    }
    signal(SIGTERM, recycle_proc);
    //create_task(&(rule[0]));

    while (1) {
        int status = 0;
        tmp_pid = wait(&status);
        if (WIFEXITED(status)) {
            PRINT_INFO_HEAD;
            print_info("normal termination, exit status = %d", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            PRINT_ERR_HEAD;
            print_err("abnormal termination, signal number = %d", WTERMSIG(status));
        }
        sleep(15);
        reload_over_task(rule, tmp_pid);
    }


    return 0;

}

