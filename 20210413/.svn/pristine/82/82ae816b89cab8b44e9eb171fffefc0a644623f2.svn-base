/*******************************************************************************************
*文件:  record_manager.cpp
*描述:  数据库操作类
*作者:  宋宇
*日期:  2019-11-26
*
*修改:
*1.增加遍历所有表函数                                                ------> 2020-05-29
*******************************************************************************************/
#include "record_manager.h"
#include "common_func.h"

/*******************************************************************************************
*功能:        初始化
*参数:        host_name                     ---->主机名
*            返回值                         ---->true 成功,false 失败
*注释:
*******************************************************************************************/
recorder_t *init_recorder(const char *host_name) {

    recorder_t *recorder = (recorder_t *) calloc(1, sizeof(recorder_t));

    recorder->connect_db = connect_db;
    recorder->reconnect_db = reconnect_db;
    recorder->disconnect_db = disconnect_db;

    recorder->show_tables = show_tables;
    recorder->make_table_name = make_table_name;
    recorder->rename_table = rename_table;
    recorder->create_table = create_table;
    recorder->drop_table = drop_table;
    recorder->drop_table_from_name = drop_table_from_name;
    recorder->insert_data = insert_data;
    recorder->select_data = select_data;
    recorder->select_like = select_like;
    recorder->select_all = select_all;
    recorder->update_data = update_data;
    recorder->delete_data = delete_data;
    recorder->delete_like = delete_like;

    recorder->get_user_name = get_user_name;

    recorder->close_db = close_db;

    strcpy(recorder->in_host_name, host_name);
    if (recorder->connect_db(recorder, host_name)) {
        return recorder;
    } else {
        free(recorder);
        return NULL;
    }

}

/*******************************************************************************************
*功能:        连接数据库
*参数:       recorder                       ---->记录管理对象 
*            host_name                     ---->主机名
*            返回值                         ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool connect_db(recorder_t *recorder, const char *host_name) {
    if (!recorder->is_init) {
        //非线程mysql写连接
        if (mysql_init(&recorder->mysql_handle) == NULL) {
            return false;
        }

        if (mysql_options(&recorder->mysql_handle, MYSQL_READ_DEFAULT_GROUP, "client") != 0) {
            PRINT_ERR_HEAD
            print_err("mysql_options error");
            mysql_close(&recorder->mysql_handle);
            return false;
        }
        bool my_bool = true;
        mysql_options(&recorder->mysql_handle, MYSQL_OPT_RECONNECT, &my_bool);

        if (mysql_real_connect(&recorder->mysql_handle, host_name, FSYNC_MYSQL_USR, FSYNC_MYSQL_PWD, FSYNC_MYSQL_DB, 0,
                               NULL, 0) ==
            NULL) {
            PRINT_ERR_HEAD
            print_err("connect db error:%s", mysql_error(&recorder->mysql_handle));
            mysql_close(&recorder->mysql_handle);
            return false;
        } else {
            PRINT_DBG_HEAD;
            print_dbg("connect db success");
        }

        recorder->is_init = true;
    } else {
        PRINT_INFO_HEAD
        print_info("already connected");
    }

    return true;
}

/*******************************************************************************************
*功能:        重连数据库
*参数:       recorder                       ---->记录管理对象 
*            host_name                     ---->主机名
*            返回值                         ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool reconnect_db(recorder_t *recorder, char *host_name) {
    disconnect_db(recorder);
    return connect_db(recorder, host_name);
}

/*******************************************************************************************
*功能:        断开数据库连接
*参数:
*注释:
*******************************************************************************************/
void disconnect_db(recorder_t *recorder) {
    if (recorder->is_init) {
        mysql_close(&recorder->mysql_handle);
        recorder->is_init = false;
    } else {
        PRINT_ERR_HEAD;
        print_err("dis_connect:has not connected,cannot dis_connect!\n");
    }
}


/*******************************************************************************************
*功能:        执行sql
*参数:       recorder                       ---->记录管理对象 
*            sql_buf                       ---->sql语句
*            返回值                         ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool exec_sql(recorder_t *recorder, const char *sql_buf) {
    bool bret = true;
    time_t new_time = time(NULL);
    if (((new_time - recorder->old_time) > MYSQL_MAX_TIMEOUT) || (recorder->failed_times > 3)) {
        reconnect_db(recorder, recorder->in_host_name);
        recorder->failed_times = 0;
    }
    recorder->old_time = new_time;
    if (mysql_query(&recorder->mysql_handle, sql_buf) != 0) {
        char error_info[FSYNC_PATH_MAX_LEN] = {0};
        sprintf(error_info, "%s", mysql_error(&recorder->mysql_handle));

        PRINT_ERR_HEAD
        print_err("exec_sql [%s] error[%s]", sql_buf, error_info);
        bret = false;
    }

    return bret;
}

/*******************************************************************************************
*功能:       根据用户名获取表名
*参数:      user                 ----> 用户名 
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           table_name           ----> 表名
*
*           返回值                ---->  表名
*
*注释:
*******************************************************************************************/
const char *make_table_name(const char *user, int record_type, char *table_name) {

    switch (record_type) {
        case INT_FILE_TYPE:
            sprintf(table_name, "%s%s_INT_FILE_TYPE", TABLE_NAME_PREFIX, user);
            break;

        case INT_DIR_TYPE:
            sprintf(table_name, "%s%s_INT_DIR_TYPE", TABLE_NAME_PREFIX, user);
            break;

        case OUT_FILE_TYPE:
            sprintf(table_name, "%s%s_OUT_FILE_TYPE", TABLE_NAME_PREFIX, user);
            break;

        case OUT_DIR_TYPE:
            sprintf(table_name, "%s%s_OUT_DIR_TYPE", TABLE_NAME_PREFIX, user);
            break;

        case VIRUS_FILE_TYPE:
            sprintf(table_name, "%s%s_VIRUS_FILE_TYPE", TABLE_NAME_PREFIX, user);
            break;

        case KEYWORD_FILE_TYPE:
            sprintf(table_name, "%s%s_KEYWORD_FILE_TYPE", TABLE_NAME_PREFIX, user);
            break;

        default: PRINT_ERR_HEAD;
            print_err("not find this record type");
            return NULL;
    }

    return table_name;
}

const char *get_user_name(const char *table_name, char *user) {

    if (strstr(table_name, TABLE_NAME_PREFIX) == NULL) {
        PRINT_DBG_HEAD;
        print_dbg("table = %s not belong to msync table", table_name);
        return NULL;
    } else {
        const char *p_start = table_name + strlen(TABLE_NAME_PREFIX);
        const char *p_end = strchr(p_start, '_');
        if (p_end == NULL) {
            PRINT_ERR_HEAD;
            print_err("table = %s can not parse", table_name);
        }
        strncpy(user, p_start, p_end - p_start);
        PRINT_DBG_HEAD;
        print_dbg("get user = %s from table = %s", user, table_name);
        return user;
    }

}

/*******************************************************************************************
*功能:       特殊字符转换
*参数:       old_name             ---->需转换的字符串
*            new_name             ----> 转换后的字符串
*            name_len             ----> 长度
* 
*           返回值                ---->  表类型
*
*注释:
*******************************************************************************************/
const char *trans_sql_char(const char *old_name, char *new_name, int name_len) {

    char tmp_char[8] = {0};
    memset(new_name, 0, name_len);

    for (int i = 0; i < strlen(old_name); i++) {
        switch (old_name[i]) {
            case '\'':
                strcat(new_name, "\\'");
                break;
            case '\"':
                strcat(new_name, "\\\"");
                break;
            case '%':
                strcat(new_name, "\\%");
                break;
            default:
                tmp_char[0] = old_name[i];
                strcat(new_name, tmp_char);
        }
    }
    return new_name;
}

/*******************************************************************************************
*功能:       获取所有表名
*参数:       recorder                     ---->记录管理对象 
*           table_list                   ---->表名链表
*            
*           返回值                       ---->true 成功, false 失败
*注释:
*******************************************************************************************/
int show_tables(recorder_t *recorder, GList **table_list) {

    int i = 0;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};

    sprintf(sql_buf, "SHOW TABLES;");
    if (exec_sql(recorder, sql_buf)) {
        if ((res = mysql_store_result(&recorder->mysql_handle)) != NULL) {
            while (1) {
                row = mysql_fetch_row(res);
                if (row == NULL) {
                    break;
                }
                char *table_name = (char *) calloc(MYSQL_NAME_LEN, sizeof(char));
                strcpy(table_name, row[0]);
                *table_list = g_list_prepend(*table_list, table_name);
                i++;
                PRINT_DBG_HEAD;
                print_dbg("get table name = %s", table_name);
            }
            mysql_free_result(res);
        } else {
            PRINT_ERR_HEAD;
            print_err("get SHOW TABLES from mysql failed !");
            return -1;
        }

    } else {
        PRINT_ERR_HEAD;
        print_err("SHOW TABLES failed");
        return -1;
    }

    return i;
}

bool rename_table(recorder_t *recorder, const char *old_table, const char *new_table) {

    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};

    sprintf(sql_buf, "RENAME TABLE `%s` to `%s`", old_table, new_table);
    bret = exec_sql(recorder, sql_buf);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("rename tables %s to %s success", old_table, new_table);

    } else {
        PRINT_ERR_HEAD;
        print_err("rename tables %s to %s failed", old_table, new_table);
    }

    return bret;
}

/*******************************************************************************************
*功能:       创建表
*参数:       recorder                    ---->记录管理对象 
*           user                        ---->用户名
*           record_type                 ---->文件类型（不同类型文件记录在不同的表中）
*            
*           返回值                       ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool create_table(recorder_t *recorder, const char *user, int record_type) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};

    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "CREATE TABLE IF NOT EXISTS `%s`("
                     "id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                     "`path_name` TEXT NOT NULL,"
                     "`file_time` TIMESTAMP NOT NULL,"
                     "`file_size` BIGINT,"
                     "`remark` TEXT DEFAULT NULL,"
                     "KEY idx_path_name(path_name(128))"
                     ")", table_name);
    bret = exec_sql(recorder, sql_buf);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("create tables %s success", table_name);

    } else {
        PRINT_ERR_HEAD;
        print_err("create tables %s failed", table_name);
    }
    sprintf(sql_buf, "ALTER TABLE `%s` CHANGE path path_name TEXT NOT NULL", table_name);
    exec_sql(recorder, sql_buf);
    sprintf(sql_buf, "ALTER TABLE `%s` CHANGE size file_size BIGINT", table_name);
    exec_sql(recorder, sql_buf);
    return bret;
}

/*******************************************************************************************
*功能:       删除表
*参数:       recorder                     ---->记录管理对象 
*           user                         ---->用户名
*           record_type                  ---->文件类型（不同类型文件记录在不同的表中）
*            
*           返回值                       ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool drop_table(recorder_t *recorder, const char *user, int record_type) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};

    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "DROP TABLE IF EXISTS `%s`", table_name);
    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("DROP TABLE %s success ", table_name);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("DROP TABLE %s failed ", table_name);
    }
    return bret;
}

/*******************************************************************************************
*功能:       删除表
*参数:       recorder                     ---->记录管理对象
*           table_name                    ---->表名
*
*           返回值                       ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool drop_table_from_name(recorder_t *recorder, const char *table_name) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};

    sprintf(sql_buf, "DROP TABLE `%s`", table_name);
    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("DROP TABLE %s success ", table_name);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("DROP TABLE %s failed ", table_name);
    }
    return bret;
}

/*******************************************************************************************
*功能:        插入数据
*参数:        recorder                     ---->记录管理对象 
*            user                         ---->用户名
*            record_type                  ---->文件类型（不同类型文件记录在不同的表中）
*            file_name                    ---->路径+文件名
*            modify                  ---->文件最后修改时间
*            size                    ---->文件大小
*            remark                       ---->备注
*            
*            返回值                        ---->true 成功, false 失败
*注释:
*******************************************************************************************/
bool insert_data(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                 unsigned long modify_time, unsigned long file_size, const char *remark) {
    bool bret = false;
    char file_time[FSYNC_TIME_MAX_LEN] = {0};
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    time2str(modify_time, file_time, sizeof(file_time));                 //将时间转换为Timestamp
    if (remark == NULL) {
        sprintf(sql_buf, "INSERT INTO `%s`(path_name,file_size,file_time) VALUES('%s',%lu,'%s')",
                table_name, trans_name, file_size, file_time);
    } else {
        sprintf(sql_buf, "INSERT INTO `%s`(path_name,file_size,file_time,remark) VALUES('%s',%lu,'%s','%s')",
                table_name, trans_name, file_size, file_time, remark);
    }

    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("%s success", sql_buf);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("%s failed", sql_buf);
    }
    return bret;
}

/*******************************************************************************************
*功能:       查询数据
*参数:       recorder             ---->记录管理对象 
*           user                 ---->用户名
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           file_name            ---->路径+文件名
*           modify               ---->文件最后修改时间(值结果参数)
*           size                 ---->文件大小(值结果参数)
*           
*           返回值                ---->  查询到的行数
*
*注释:
*******************************************************************************************/
int select_data(recorder_t *recorder, const char *user, int record_type, const char *file_name,
                unsigned long *modify_time, unsigned long *file_size, char *remark) {
    int row_num = 0;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "SELECT * FROM `%s` WHERE path_name='%s'", table_name, trans_name);
    if (exec_sql(recorder, sql_buf)) {
        if ((res = mysql_store_result(&recorder->mysql_handle)) != NULL) {
            if ((row_num = mysql_num_rows(res)) >= 1) {
                row = mysql_fetch_row(res);
                if (modify_time != NULL) {
                    *modify_time = str2time(row[2]);
                }
                if (file_size != NULL) {
                    *file_size = strtoul(row[3], NULL, 10);
                }
                if (remark != NULL) {
                    strcpy(remark, row[4]);
                }
                PRINT_DBG_HEAD;
                print_dbg("get path = %s info from mysql file_time = %s file_size = %s remark = %s",
                          file_name, row[2], row[3], remark == NULL ? "" : row[4]);
            } else {
                PRINT_DBG_HEAD;
                print_dbg("not get path = %s info from table %s !", file_name, table_name);
            }
            mysql_free_result(res);
        } else {
            PRINT_ERR_HEAD;
            print_err("get path = %s result from mysql failed !", file_name);
            return -1;
        }

    } else {
        PRINT_DBG_HEAD;
        print_dbg("SELECT * FROM %s WHERE  path='%s' not find", table_name, file_name);
        return -1;
    }
    return row_num;
}

/*******************************************************************************************
*功能:       查询类似数据
*参数:       recorder             ---->记录管理对象 
*           user                 ---->用户名
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           file_name            ---->路径+文件名
*           modify          ---->文件最后修改时间(值结果参数)
*           size            ---->文件大小(值结果参数)
*
*           返回值                ---->  查询到的行数
*
*注释:
*******************************************************************************************/
int select_like(recorder_t *recorder, const char *user, int record_type, const char *file_name, GList **dir_list) {
    int row_num = 0;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "SELECT * FROM `%s` WHERE path_name LIKE '%s%%'", table_name, trans_name);
    if (exec_sql(recorder, sql_buf)) {
        if ((res = mysql_store_result(&recorder->mysql_handle)) != NULL) {
            while (1) {
                row = mysql_fetch_row(res);
                if (row == NULL) {
                    break;
                }
                fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
                strcpy(tmp_task->path, row[1]);
                tmp_task->modify = str2time(row[2]);
                tmp_task->size = strtoul(row[3], NULL, 10);
                *dir_list = g_list_prepend(*dir_list, tmp_task);
                row_num++;
                PRINT_DBG_HEAD;
                print_dbg("select like = %s from table %s ,get path = %s", file_name, table_name, tmp_task->path);
            }
            mysql_free_result(res);
        } else {
            PRINT_ERR_HEAD;
            print_err("get path like = %s result from mysql failed !", file_name);
            return -1;
        }

    } else {
        PRINT_DBG_HEAD;
        print_dbg("SELECT * FROM %s WHERE  path='%s' not find", file_name, file_name);
        return -1;
    }
    return row_num;
}

int select_all(recorder_t *recorder, const char *user, int record_type, int start_num, int line_count,
               GList **data_list) {

    int row_num = 0;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};

    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "SELECT * FROM `%s` LIMIT %d,%d", table_name, start_num, line_count);
    if (exec_sql(recorder, sql_buf)) {

        if ((res = mysql_store_result(&recorder->mysql_handle)) != NULL) {
            while (1) {
                row = mysql_fetch_row(res);
                if (row == NULL) {
                    break;
                }
                fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
                strcpy(tmp_task->path, row[1]);
                tmp_task->modify = str2time(row[2]);
                tmp_task->size = strtoul(row[3], NULL, 10);
                *data_list = g_list_prepend(*data_list, tmp_task);
                row_num++;
                PRINT_DBG_HEAD;
                print_dbg("select * from table %s ,get path = %s", table_name, tmp_task->path);
            }
            mysql_free_result(res);
        } else {
            PRINT_ERR_HEAD;
            print_err("SELECT * from tables = %s result  failed !", table_name);
            return -1;
        }

    } else {
        PRINT_DBG_HEAD;
        print_dbg("SELECT * FROM %s failed", table_name);
        return -1;
    }
    return row_num;
}

/*******************************************************************************************
*功能:       修改数据
*参数:      recorder              ---->记录管理对象 
*           user                 ---->用户名
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           file_name            ---->路径+文件名
*           modify          ---->文件最后修改时间
*           size            ---->文件大小
*           remark               ---->备注           
*
*           返回值                ---->  true 成功 false 失败
*
*注释:
*******************************************************************************************/
bool
update_data(recorder_t *recorder, const char *user, int record_type, const char *file_name, unsigned long modify_time,
            unsigned long file_size, const char *remark) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char file_time[FSYNC_TIME_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    //将时间转换为Timestamp
    time2str(modify_time, file_time, sizeof(file_time));
    if (remark == NULL) {
        sprintf(sql_buf, "UPDATE `%s` SET file_time='%s' , file_size=%lu WHERE path_name='%s'",
                table_name, file_time, file_size, trans_name);
    } else {
        sprintf(sql_buf, "UPDATE `%s` SET file_time='%s' , file_size=%lu ,remark = %s WHERE path_name='%s'",
                table_name, file_time, file_size, remark, trans_name);
    }
    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("%s success", sql_buf);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("%s failed", sql_buf);
    }
    return bret;
}

/*******************************************************************************************
*功能:       删除数据
*参数:      recorder              ---->记录管理对象 
*           user                 ---->用户名 
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           file_name            ---->路径+文件名
*           
*           返回值                ---->  true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool delete_data(recorder_t *recorder, const char *user, int record_type, const char *file_name) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "DELETE FROM `%s` WHERE path_name='%s'", table_name, trans_name);
    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("%s success", sql_buf);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("%s failed", sql_buf);
    }
    return bret;
}

/*******************************************************************************************
*功能:       删除类似数据
*参数:       recorder            ---->记录管理对象 
*           user                 ---->用户名
*           record_type          ---->文件类型（不同类型文件记录在不同的表中）
*           file_name            ---->路径+文件名
*
*           返回值                ---->  true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool delete_like(recorder_t *recorder, const char *user, int record_type, const char *file_name) {
    bool bret = false;
    char sql_buf[SQL_BUF_MAX_LEN] = {0};
    char table_name[MYSQL_NAME_LEN] = {0};
    char trans_name[MYSQL_NAME_LEN * 2] = {0};

    trans_sql_char(file_name, trans_name, sizeof(trans_name));
    make_table_name(user, record_type, table_name);
    sprintf(sql_buf, "DELETE FROM `%s` WHERE path_name LIKE '%s%%'", table_name, trans_name);
    if (exec_sql(recorder, sql_buf)) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("%s success", sql_buf);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("%s failed", sql_buf);
    }
    return bret;
}


/*******************************************************************************************
*功能:       关闭数据连接并释放对象
*参数:       recorder            ---->记录管理对象 
*
*           返回值                ----> 
*
*注释:
*******************************************************************************************/
void close_db(recorder_t *recorder) {

    if (recorder->is_init) {
        mysql_close(&recorder->mysql_handle);
        recorder->is_init = false;
    }

    if (recorder != NULL) {
        free(recorder);
    }

    return;
}

