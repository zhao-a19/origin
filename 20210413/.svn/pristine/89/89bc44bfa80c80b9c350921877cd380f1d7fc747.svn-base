#include "curl_sftp_sync.h"

/*******************************************************************************************
*功能:      初始化sftp对象
*参数:
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
fs_work_t *create_sftp_curl_worker(void) {

    fs_work_t *sftp_worker = (fs_work_t *) calloc(1, sizeof(fs_work_t));
    if (sftp_worker == NULL) {
        return NULL;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_hanlde_t *handle = (curl_hanlde_t *) calloc(1, sizeof(curl_hanlde_t));
    handle->curl = curl_easy_init();
    sftp_worker->handle = handle;

    sftp_worker->init_worker_obj = curl_sftp_init_worker_obj;
    sftp_worker->connect_server = curl_sftp_connect_server;
    sftp_worker->check_server_connect = curl_sftp_check_connect;
    sftp_worker->check_scan_path = curl_sftp_check_path;

    sftp_worker->first_scan = curl_sftp_first_scan;
    sftp_worker->second_scan = curl_sftp_second_scan;

    sftp_worker->get_stat = curl_sftp_stat;
    sftp_worker->check_access = curl_sftp_check_access;

    sftp_worker->mkdir_r = curl_sftp_mkdir_r;
    sftp_worker->rmdir = curl_sftp_rmdir;

    sftp_worker->remove = curl_sftp_remove;
    sftp_worker->rename = curl_sftp_rename;

    sftp_worker->open_source_file = curl_sftp_open_source_file;
    sftp_worker->open_target_file = curl_sftp_open_target_file;
    //sftp_worker->read = ftp_read;
    //sftp_worker->write = ftp_write;

    sftp_worker->disconnect = curl_sftp_disconnect;
    sftp_worker->close_data_handle = curl_sftp_close_data_handle;
    sftp_worker->destroy_worker_obj = curl_sftp_destroy_worker;

    return sftp_worker;
}

int curl_sftp_init_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) (worker_obj->handle);
    curl_handle->protocol = srv_info->protocol;
    strcpy(curl_handle->user, srv_info->user);
    strcpy(curl_handle->password, srv_info->pwd);
    if (strchr(srv_info->use_ip, ':') != NULL) {
        curl_handle->ip_type = CURLSFTP_IPV6;
        sprintf(curl_handle->remote_ip, "[%s]", srv_info->use_ip);
    } else {
        curl_handle->ip_type = CURLSFTP_IPV4;
        strcpy(curl_handle->remote_ip, srv_info->use_ip);
    }

    curl_handle->port = srv_info->port;
    strcpy(curl_handle->scan_path, srv_info->scan_path);

    return 0;
}

long curl_sftp_size(void *handle, const char *path) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    curl_off_t size = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d/%s", curl_handle->remote_ip, curl_handle->port, path);

    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    res = curl_easy_perform(curl_handle->curl);

    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp get file = %s size failed err = %s", path, curl_easy_strerror(res));
    } else {
        res = curl_easy_getinfo(curl_handle->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &size);
        if (res != CURLE_OK) {
            PRINT_ERR_HEAD;
            print_err("sftp get file = %s size failed err = %s", path, curl_easy_strerror(res));
            size = -1;
        } else {
            if (size == -1) {
                size = 0;
            }
            PRINT_DBG_HEAD;
            print_dbg("sftp get file = %s size = %ld", path, size);
        }
    }

    return size;
}

long curl_sftp_get_modify(curl_hanlde_t *curl_handle, const char *path) {

    CURLcode res;
    long modify = -1;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d/%s", curl_handle->remote_ip, curl_handle->port, path);

    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    res = curl_easy_perform(curl_handle->curl);

    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp get file = %s modify failed err = %s", path, curl_easy_strerror(res));
    } else {
        res = curl_easy_getinfo(curl_handle->curl, CURLINFO_FILETIME, &modify);
        if (res != CURLE_OK) {
            PRINT_ERR_HEAD;
            print_err("sftp get file = %s modify failed err = %s", path, curl_easy_strerror(res));
        } else {
            PRINT_DBG_HEAD;
            print_dbg("sftp get file = %s modify = %ld ", path, modify);
        }
    }

    return modify;

}


/*******************************************************************************************
*功能:      连接服务器
*参数:      handle               ----> 对象句柄
 *          rule                 ----> 策略信息
*           srv_info             ----> 服务器信息
*
*           返回值                ----> ture 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_connect_server(void *handle) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) (handle);
    bool bret = true;
    CURLcode res;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};


    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d", curl_handle->remote_ip, curl_handle->port);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);

    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);
    res = curl_easy_perform(curl_handle->curl);


    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp login failed err = %s", curl_easy_strerror(res));
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp login success");
    }

    return bret;
}

/*******************************************************************************************
*功能:      连接状态检查
*参数:      handle              ----> 对象句柄
*           rule                ----> 规则信息
*           srv_info            ----> 服务器信息
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_check_connect(void *handle) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    bool bret = true;
    CURLcode res;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d", curl_handle->remote_ip, curl_handle->port);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);

    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);
    res = curl_easy_perform(curl_handle->curl);


    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp login failed err = %s", curl_easy_strerror(res));
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp login success");
    }

    return bret;

}

bool curl_sftp_check_path(void *handle) {

    curl_hanlde_t *sftp_handle = (curl_hanlde_t *) handle;

    return curl_sftp_check_access(handle, sftp_handle->scan_path);
}

/*******************************************************************************************
*功能:      检查文件/目录是否存在
*参数:      handle               ----> 对象句柄
*           path           ----> 文件路径名
*
*           返回值              ----> true 存在, false 不存在
*
*注释:
*******************************************************************************************/
bool curl_sftp_check_access(void *handle, const char *path_name) {

    bool bret = true;
    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "sftp://%s:%d/%s", curl_handle->remote_ip, curl_handle->port, path_name);

    curl_easy_reset(curl_handle->curl);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);

    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);
    res = curl_easy_perform(curl_handle->curl);


    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp check file = %s access failed err = %s", path_name, curl_easy_strerror(res));
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp check file = %s access success", path_name);
    }

    return bret;
}

/*******************************************************************************************
*功能:      路径检查
*参数:     handle              ----> 对象句柄
*          rule                ----> 策略信息
*          srv_info            ----> 服务器信息
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_check_path(void *handle, fs_rule_t *rule, fs_server_t *srv_info) {

    bool bret = true;
    if (strlen(srv_info->scan_path) == 0) {
        PRINT_ERR_HEAD;
        print_err("[TASK%d] check server path = (null)", rule->task_id);
        return false;
    }

    if (curl_sftp_check_access(handle, srv_info->scan_path)) {
        PRINT_DBG_HEAD;
        print_dbg("[TASK%d] check server path = %s success", rule->task_id, srv_info->scan_path);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("[TASK%d] check server path = %s failed", rule->task_id, srv_info->scan_path);
    }


    return bret;
}

/*******************************************************************************************
*功能:      获取文件/目录状态
*参数:      handle               ----> 对象句柄
*           path           ----> 文件路径名
*           file_stat           ----> 文件状态
*
*           返回值              ----> 0 成功, -1 失败
*
*注释:
*******************************************************************************************/
int curl_sftp_stat(void *handle, const char *path_name, struct stat *file_stat) {

    long size = -1;
    long modify = -1;

    if (curl_sftp_check_access(handle, path_name)) {
        PRINT_DBG_HEAD;
        print_dbg("check path = %s exist", path_name);
    } else {
        PRINT_ERR_HEAD;
        print_err("check path = %s not exist", path_name);
        return -1;
    }

    size = curl_sftp_size(handle, path_name);
    if (size >= 0) {
        file_stat->st_size = size;
        PRINT_DBG_HEAD;
        print_dbg("path name = %s size = %lu", path_name, file_stat->st_size);
    } else {
        PRINT_ERR_HEAD;
        print_err("path name = %s get size failed", path_name);
        return -1;
    }

    modify = curl_sftp_get_modify((curl_hanlde_t *) handle, path_name);
    if (modify > 0) {
        file_stat->st_mtime = modify;
        PRINT_DBG_HEAD;
        print_dbg("file modify time = %ld", file_stat->st_mtime);
    } else {
        PRINT_ERR_HEAD;
        print_err("get file modify time failed");
        return -1;
    }

    return 0;
}

typedef struct recv_mem_t {
    char *buf;
    unsigned int len;
    unsigned int offset;

} recv_mem_t;

int curl_sftp_parse_path(const char *parent_path, char *buf, GList **path_list) {

    char *p = buf;
    char *key_point;
    const char *parse_name = NULL;
    char tmp_name[FSYNC_NAME_MAX_LEN] = {0};
    while ((key_point = strsep(&p, "\r\n")) != NULL) {    //关键字为空格
        if (*key_point == 0) {
            continue;
        } else {
            //printf("key_point = %s\n",key_point);
            parse_name = strrchr(key_point, ' ');
            if (parse_name == NULL) {
                continue;
            } else {
                strcpy(tmp_name, ++parse_name);
            }

            if ((strcmp(".", basename(tmp_name)) == 0) || (strcmp("..", basename(tmp_name)) == 0)) {
                continue;
            }
            fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
            tmp_task->type = key_point[0] == 'd' ? FSYNC_IS_DIR : FSYNC_IS_FILE;

            if (strchr(tmp_name, '/') != NULL) {
                strcpy(tmp_task->path, tmp_name);
            } else {
                if (parent_path[strlen(parent_path) - 1] == '/') {
                    sprintf(tmp_task->path, "%s%s", parent_path, tmp_name);
                } else {
                    sprintf(tmp_task->path, "%s/%s", parent_path, tmp_name);
                }
            }
            //printf("type = %s ,path = %s\n", tmp_task->type == FSYNC_IS_FILE ? "FILE" : "DIR", tmp_task->path);
            *path_list = g_list_prepend(*path_list, tmp_task); //分割出一个正常的字符串
        }
    }

    return 0;
}

static size_t read_dir_list_cb(void *buffer, size_t size, size_t nmemb, void *arg) {

    recv_mem_t *recv_mem = (recv_mem_t *) arg;
    unsigned int len = size * nmemb;
    if (len < (recv_mem->len - recv_mem->offset)) {
        memcpy(recv_mem->buf + recv_mem->offset, buffer, len);
        recv_mem->offset += len;
    } else {
        recv_mem->len += SFTPLIB_BUFSIZ;
        recv_mem->buf = (char *) realloc(recv_mem->buf, recv_mem->len);
        memcpy(recv_mem->buf + recv_mem->offset, buffer, len);
        recv_mem->offset += len;
    }

    return nmemb;
}

/*******************************************************************************************
*功能:      首次扫描
*参数:      handle                    ----> 对象句柄
*           in_to_out                ----> 同步方向
*           rule                     ----> 策略信息
*           dir_name                 ----> 扫描目录
*           dir_list                 ----> 目录列表
*           file_list                ----> 文件列表
*           ready_queue              ----> 准备列表
*           recorder                 ----> 文件记录管理对象
*
*           返回值                    ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list,
                          GList **file_list, GAsyncQueue *ready_queue, int delay_time) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    bool bover = false;
    CURLcode res;
    GList *tmp_list = NULL;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    char scan_dir[FSYNC_PATH_MAX_LEN] = {0};
    recv_mem_t recv_mem;
    recv_mem.buf = (char *) calloc(1, SFTPLIB_BUFSIZ);
    recv_mem.len = SFTPLIB_BUFSIZ;
    recv_mem.offset = 0;
    strcpy(scan_dir, dir_name);

    while (1) {
        curl_easy_reset(curl_handle->curl);
        sprintf(cmd, "sftp://%s:%d/%s/", curl_handle->remote_ip, curl_handle->port, scan_dir);
        memset(recv_mem.buf, 0, recv_mem.len);
        recv_mem.offset = 0;
        curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
        if (strlen(curl_handle->password) > 0) {
            curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
            curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
        }
        curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
        curl_easy_setopt(curl_handle->curl, CURLOPT_CUSTOMREQUEST, "NLST -a");
        //curl_easy_setopt(sftp_handle->curl, CURLOPT_DIRLISTONLY, 1L);
        curl_easy_setopt(curl_handle->curl, CURLOPT_WRITEFUNCTION, read_dir_list_cb);
        curl_easy_setopt(curl_handle->curl, CURLOPT_WRITEDATA, &recv_mem);  //此函数可能会扩大接收缓冲区大小
        curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

        res = curl_easy_perform(curl_handle->curl);

        if (CURLE_OK != res) {
            PRINT_ERR_HEAD;
            print_err("scan dir = %s failed:%s", scan_dir, curl_easy_strerror(res));
        } else {
            PRINT_DBG_HEAD;
            print_dbg("scan dir = %s success", scan_dir);
            curl_sftp_parse_path(scan_dir, recv_mem.buf, &tmp_list);
        }

        //扫描目录加入目录列表
        fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
        tmp_task->in_to_out = in_to_out;
        tmp_task->type = FSYNC_IS_DIR;
        strcpy(tmp_task->path, scan_dir);
        tmp_task->size = 0;
        tmp_task->modify = CURL_DIR_DEFAULT_TIME;
        *dir_list = g_list_prepend(*dir_list, tmp_task);

        while (1) {
            //取出扫描信息
            GList *p_elem = g_list_first(tmp_list);
            if (p_elem == NULL) {
                bover = true;
                break;
            }
            tmp_task = (fs_task_t *) p_elem->data;
            tmp_list = g_list_delete_link(tmp_list, p_elem);

            if (tmp_task->type == FSYNC_IS_FILE) {
                tmp_task->in_to_out = in_to_out;
                tmp_task->modify = curl_sftp_get_modify(curl_handle, tmp_task->path);
                tmp_task->size = curl_sftp_size(handle, tmp_task->path);
                *file_list = g_list_prepend(*file_list, tmp_task);
            } else {
                strcpy(scan_dir, tmp_task->path);
                free(tmp_task);
                break;
            }
        }

        if (bover) {
            break;
        }
    }


    free(recv_mem.buf);
    PRINT_DBG_HEAD;
    print_dbg("ftp first scan over,dir = %d ,file = %d", g_list_length(*dir_list), g_list_length(*file_list));

    return true;
}

/*******************************************************************************************
*功能:      二次扫描
*参数:       handle                   ----> 对象句柄
*           file_list                ----> 源目录
*           ready_queue              ----> 源准备队列
*
*           返回值                    ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue) {

    struct stat stat_buf;
    fs_task_t *tmp_task = NULL;
    for (GList *p_elem = *file_list; p_elem != NULL; p_elem = *file_list) {
        tmp_task = (fs_task_t *) (p_elem->data);
        memset(&stat_buf, 0, sizeof(stat_buf));
        if (curl_sftp_stat(handle, tmp_task->path, &stat_buf) != 0) {      //文件不存在
            PRINT_ERR_HEAD;
            print_err("sftp get file = %s stat failed:%s", tmp_task->path, strerror(errno));
            free(p_elem->data);
            *file_list = g_list_delete_link(*file_list, p_elem);
        } else {
            if ((tmp_task->modify == stat_buf.st_mtime) && (tmp_task->size == stat_buf.st_size)) {
                g_async_queue_push(ready_queue, tmp_task);
                *file_list = g_list_delete_link(*file_list, p_elem);                  //文件未修改
            } else {
                PRINT_DBG_HEAD;
                print_dbg("path = %s ,old size = %ld ,new size = %ld ,old time = %ld ,new time = %ld",
                          tmp_task->path,tmp_task->size, stat_buf.st_size, tmp_task->modify, stat_buf.st_mtime);
                free(p_elem->data);
                p_elem->data = NULL;
                *file_list = g_list_delete_link(*file_list, p_elem);                  //文件被修改
            }
        }
    }
    PRINT_DBG_HEAD;
    print_dbg("sftp second scan over,file = %d", g_async_queue_length(ready_queue));

    return true;

}

int curl_sftp_mkdir(void *handle, const char *dir_path) {

    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    char cmd[FSYNC_PATH_MAX_LEN] = {0};

    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d", curl_handle->remote_ip, curl_handle->port);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    sprintf(cmd, "mkdir %s", dir_path);
    struct curl_slist *curl_list = NULL;
    curl_list = curl_slist_append(curl_list, cmd);
    curl_easy_setopt(curl_handle->curl, CURLOPT_POSTQUOTE, curl_list);

    res = curl_easy_perform(curl_handle->curl);
    curl_slist_free_all(curl_list);

    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp mkdir = %s failed err = %s", dir_path, curl_easy_strerror(res));
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp mkdir = %s success", dir_path);
    }


    return 0;

}

/*******************************************************************************************
*功能:      递归创建目录
*参数:      handle               ----> 对象句柄
*           dir_path             ----> 目录路径
*
*           返回值                ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int curl_sftp_mkdir_r(void *handle, const char *dir_path) {

    int ret = 0;
    int i = 0;
    if (curl_sftp_check_access(handle, dir_path)) {
        return 0;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    while (1) {
        i++;
        if (dir_path[i] == '\0') {
            strncpy(dir_bak, dir_path, i);
            curl_sftp_mkdir(handle, dir_bak);
            break;
        } else if (dir_path[i] == '/') {
            strncpy(dir_bak, dir_path, i);
            curl_sftp_mkdir(handle, dir_bak);
        }
    }


    if (curl_sftp_check_access(handle, dir_path)) {
        PRINT_DBG_HEAD;
        print_dbg("mkdir_r = %s success!", dir_path);
        ret = 0;
    } else {
        PRINT_ERR_HEAD;
        print_err("mkdir_r = %s failed!", dir_path);
        ret = -1;
    }

    return ret;
}

/*******************************************************************************************
*功能:      删除目录
*参数:      handle              ----> 对象句柄
*           path           ----> 文件名
*
*           返回值              ----> 0 成功, -1 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_rmdir(void *handle, const char *dir_path) {
    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    char cmd[FSYNC_PATH_MAX_LEN] = {0};

    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s:%d", curl_handle->remote_ip, curl_handle->port);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    sprintf(cmd, "rmdir %s", dir_path);
    struct curl_slist *curl_list = NULL;
    curl_list = curl_slist_append(curl_list, cmd);
    curl_easy_setopt(curl_handle->curl, CURLOPT_POSTQUOTE, curl_list);

    res = curl_easy_perform(curl_handle->curl);
    curl_slist_free_all(curl_list);

    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp rmdir = %s failed err = %s", dir_path, curl_easy_strerror(res));
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp rmdir = %s success", dir_path);
    }

    return true;
}


bool curl_sftp_rename(void *handle, const char *old_name, const char *new_name) {

    if (curl_sftp_check_access(handle, new_name)) {
        curl_sftp_remove(handle, new_name);
    }

    bool bret = true;
    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s", curl_handle->remote_ip);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    struct curl_slist *curl_list = NULL;
    sprintf(cmd, "rename %s %s", old_name, new_name);
    curl_list = curl_slist_append(curl_list, cmd);
    curl_easy_setopt(curl_handle->curl, CURLOPT_POSTQUOTE, curl_list);

    res = curl_easy_perform(curl_handle->curl);
    curl_slist_free_all(curl_list);


    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("sftp rename file = %s to %s failed:%s", old_name, new_name, curl_easy_strerror(res));
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("sftp rename file = %s to %s success", old_name, new_name);
        bret = true;
    }

    return bret;
}

int curl_sftp_remove(void *handle, const char *path_name) {

    bool ret = -1;
    curl_hanlde_t *curl_handle = (curl_hanlde_t *) handle;
    CURLcode res;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    curl_easy_reset(curl_handle->curl);
    sprintf(cmd, "sftp://%s", curl_handle->remote_ip);
    curl_easy_setopt(curl_handle->curl, CURLOPT_URL, cmd);
    if (strlen(curl_handle->password) > 0) {
        curl_easy_setopt(curl_handle->curl, CURLOPT_USERNAME, curl_handle->user);
        curl_easy_setopt(curl_handle->curl, CURLOPT_PASSWORD, curl_handle->password);
    }
    curl_easy_setopt(curl_handle->curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD);
    curl_easy_setopt(curl_handle->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl_handle->curl, CURLOPT_VERBOSE, 0L);

    struct curl_slist *curl_list = NULL;
    sprintf(cmd, "rm %s", path_name);
    curl_list = curl_slist_append(curl_list, cmd);
    curl_easy_setopt(curl_handle->curl, CURLOPT_POSTQUOTE, curl_list);

    res = curl_easy_perform(curl_handle->curl);
    curl_slist_free_all(curl_list);


    if (res != CURLE_OK) {
        PRINT_ERR_HEAD;
        print_err("remove file = %s failed:%s", path_name, curl_easy_strerror(res));
        ret = -1;
    } else {
        PRINT_DBG_HEAD;
        print_err("remove file = %s success", path_name);
        ret = 0;
    }

    return ret;
}

/*******************************************************************************************
*功能:      打开源文件
*参数:      handle                ----> 对象句柄
*           data_handle          ----> 数据连接句柄
*           source_file          ----> 源文件
*           返回值                ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_open_source_file(void *handle, const char *source_file) {

    return true;
}

/*******************************************************************************************
*功能:      打开目标文件
*参数:      handle                ----> 对象句柄
*           target_file          ----> 源文件
*
*           返回值                ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool curl_sftp_open_target_file(void *handle, const char *target_file) {

     char file_dir[FSYNC_PATH_MAX_LEN] = {0};
     strcpy(file_dir, target_file);
     dirname(file_dir);
     if (curl_sftp_mkdir_r(handle, file_dir) != 0) {
         return false;
     }

    return true;

}

size_t curl_sftp_read_cb(void *buf, size_t size, size_t count, void *arg_cb) {

    GAsyncQueue *data_queue = (GAsyncQueue *) arg_cb;
    rw_data_t *r_data = (rw_data_t *) calloc(1, sizeof(rw_data_t));
    size_t len = size * count;
    memcpy(r_data->buf, buf, len);
    r_data->len = len;
    if (g_async_queue_length(data_queue) > 500) {
        sleep(1);
    }
    g_async_queue_push(data_queue, r_data);
    //printf("rlen = %lu\n", len);

    return count;
}

size_t curl_sftp_write_cb(void *buf, size_t size, size_t count, void *arg_cb) {

    curl_off_t nwrite;
    GAsyncQueue *data_queue = (GAsyncQueue *) arg_cb;
    rw_data_t *w_data = (rw_data_t *) (g_async_queue_pop(data_queue));
    
    nwrite = w_data->len;
    memcpy(buf, w_data->buf, w_data->len);


    return nwrite;
}

void curl_sftp_close_data_handle(void *handle) {


    return;
}

void curl_sftp_disconnect(void *handle) {

    return;
}

/*******************************************************************************************
*功能:      销毁sftp对象
*参数:      worker                ----> 数据连接句柄
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void curl_sftp_destroy_worker(fs_work_t *worker) {

    curl_hanlde_t *curl_hanlde = (curl_hanlde_t *) (worker->handle);

    if (curl_hanlde != NULL) {
        if (curl_hanlde->curl != NULL) {
            curl_easy_cleanup(curl_hanlde->curl);
            curl_hanlde->curl = NULL;
        }
        free(curl_hanlde);

    }
    if (worker != NULL) {
        free(worker);
    }
    return;;
}
