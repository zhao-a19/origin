/*******************************************************************************************
*文件:  record_manager.h
*描述:  数据库操作类
*作者:  宋宇
*日期:  2019-11-26
*
*修改:创建文件                                             ------>     2019-11-10
*1.修改传输记录表前缀为msync_                              ------>     2020-05-29      
*******************************************************************************************/
#ifndef __RECORD_MANAGER_H__
#define __RECORD_MANAGER_H__

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "global_define.h"
#include <mysql.h>

#define INT_FILE_TYPE     0
#define INT_DIR_TYPE      1
#define OUT_FILE_TYPE     2
#define OUT_DIR_TYPE      3
#define VIRUS_FILE_TYPE   4
#define KEYWORD_FILE_TYPE 5
#define MYSQL_NAME_LEN    256
#define MYSQL_PATH_LEN    1024
#define SQL_BUF_MAX_LEN   2048
#define MYSQL_MAX_TIMEOUT 3600

#define TABLE_NAME_PREFIX "msync_"
#define FSYNC_MYSQL_HOST "localhost"
#define FSYNC_MYSQL_USR  "susqlroot"
#define FSYNC_MYSQL_PWD  "suanmitsql"
#define FSYNC_MYSQL_DB   "sudb"

typedef struct recorder_t {
    MYSQL mysql_handle;
    time_t old_time;
    bool is_init;
    int failed_times;
    char in_host_name[MYSQL_NAME_LEN];


    bool (*connect_db)(recorder_t *recorder, const char *host_name);

    bool (*reconnect_db)(recorder_t *recorder, char *host_name);

    void (*disconnect_db)(recorder_t *recorder);

    int (*show_tables)(recorder_t *recorder, GList **table_list);

    const char *(*make_table_name)(const char *user, int record_type, char *table_name);

    bool (*rename_table)(recorder_t *recorder, const char *old_table, const char *new_table);

    bool (*create_table)(recorder_t *recorder, const char *user, int record_type);

    bool (*drop_table)(recorder_t *recorder, const char *user, int record_type);

    bool (*drop_table_from_name)(recorder_t *recorder, const char *table_name);

    bool (*insert_data)(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                        unsigned long modify_time, unsigned long file_size, const char *remark);

    int (*select_data)(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                       unsigned long *modify_time, unsigned long *file_size, char *remark);

    int (*select_like)(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                       GList **dir_list);

    int (*select_all)(recorder_t *recorder, const char *user, int record_type, int start_num, int line_count,
                      GList **data_list);

    bool (*update_data)(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                        unsigned long modify_time, unsigned long file_size, const char *remark);

    bool (*delete_data)(recorder_t *recorder, const char *user, int record_type, const char *file_name);

    bool (*delete_like)(recorder_t *recorder, const char *user, int record_type, const char *file_name);

    const char *(*get_user_name)(const char *table_name, char *user);

    void (*close_db)(recorder_t *recorder);
} recorder_t;

recorder_t *init_recorder(const char *host_name);

bool connect_db(recorder_t *recorder, const char *host_name);

bool reconnect_db(recorder_t *recorder, char *host_name);

void disconnect_db(recorder_t *recorder);

bool exec_sql(recorder_t *recorder, const char *sql_buf);

int show_tables(recorder_t *recorder, GList **table_list);

bool rename_table(recorder_t *recorder, const char *old_table, const char *new_table);

bool create_table(recorder_t *recorder, const char *user, int record_type);

bool drop_table(recorder_t *recorder, const char *user, int record_type);

bool drop_table_from_name(recorder_t *recorder, const char *table_name);

bool insert_data(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                 unsigned long modify_time, unsigned long file_size, const char *remark);

int select_data(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                unsigned long *modify_time, unsigned long *file_size, char *remark);

int select_like(recorder_t *recorder, const char *user, int record_type, const char *file_name, GList **dir_list);

int select_all(recorder_t *recorder, const char *user, int record_type, int start_num, int line_count,
               GList **data_list);

bool update_data(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                 unsigned long modify_time, unsigned long file_size, const char *remark);

bool delete_data(recorder_t *recorder, const char *user, int record_type, const char *file_name);

bool delete_like(recorder_t *recorder, const char *user, int record_type, const char *file_name);

const char *make_table_name(const char *user, int record_type, char *table_name);

const char *get_user_name(const char *table_name, char *user);

const char *trans_sql_char(const char *old_name, char *new_name, int name_len);

void close_db(recorder_t *recorder);

#endif  //__RECORD_MANAGER_H__
