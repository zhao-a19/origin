#include "sftp_sync.h"

/*******************************************************************************************
*功能:      初始化sftp对象
*参数:
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
fs_work_t *create_sftp_worker(void) {

    fs_work_t *sftp_worker = (fs_work_t *) calloc(1, sizeof(fs_work_t));
    if (sftp_worker == NULL) {
        return NULL;
    }

    sftp_hanlde_t *handle = (sftp_hanlde_t *) calloc(1, sizeof(sftp_hanlde_t));
    sftp_worker->handle = handle;

    sftp_worker->init_worker_obj = sftp_init_worker_obj;
    sftp_worker->connect_server = sftp_connect_server;
    sftp_worker->check_server_connect = sftp_check_connect;
    sftp_worker->check_scan_path = sftp_check_path;

    sftp_worker->first_scan = sftp_first_scan;
    sftp_worker->second_scan = sftp_second_scan;

    sftp_worker->get_stat = sftp_stat;
    sftp_worker->check_access = sftp_check_access;

    sftp_worker->mkdir_r = sftp_mkdir_r;
    sftp_worker->rmdir = sftp_rmdir_r;

    sftp_worker->remove = sftp_remove;
    sftp_worker->rename = sftp_rename;

    sftp_worker->open_source_file = sftp_open_source_file;
    sftp_worker->open_target_file = sftp_open_target_file;
    sftp_worker->read = sftp_read;
    sftp_worker->write = sftp_write;

    sftp_worker->disconnect = sftp_disconnect;
    sftp_worker->close_data_handle = sftp_close_data_handle;
    sftp_worker->destroy_worker_obj = sftp_destroy_worker;

    PRINT_DBG_HEAD;
    print_dbg("libssh2 version = %s", libssh2_version(0));

    return sftp_worker;
}

int sftp_init_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info) {

    sftp_hanlde_t *sftp_handle = (sftp_handle_t *) (worker_obj->handle);
    int ret = 0;
    ret = libssh2_init(0);
    if (ret != 0) {
        PRINT_ERR_HEAD;
        print_err("libssh2 initialization failed (%d)", ret);
        return -1;
    }

    if ((worker_obj == NULL) || srv_info == NULL) {
        PRINT_ERR_HEAD;
        print_err("worker or srv info = NULL");
        return -1;
    }

    sftp_handle->protocol = srv_info->protocol;
    strcpy(sftp_handle->user, srv_info->user);
    strcpy(sftp_handle->password, srv_info->pwd);
    if (strchr(srv_info->use_ip, ':') != NULL) {
        sftp_handle->ip_type = FSYNC_IPV6;
    } else {
        sftp_handle->ip_type = FSYNC_IPV4;
    }
    strcpy(sftp_handle->remote_ip, srv_info->use_ip);
    sftp_handle->port = srv_info->port;
    strcpy(sftp_handle->scan_path, srv_info->scan_path);

    return 0;

}

int sftp_connect_ipv4(sftp_hanlde_t *sftp_handle) {

    unsigned long hostaddr = 0;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    hostaddr = inet_addr(sftp_handle->remote_ip);
    sftp_handle->sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(sftp_handle->port);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sftp_handle->sock, (struct sockaddr *) (&sin), sizeof(struct sockaddr_in)) != 0) {
        PRINT_ERR_HEAD;
        print_err("failed to connect %s :%s!", sftp_handle->remote_ip, strerror(errno));
        return -1;
    }
    return 0;
}

int sftp_connect_ipv6(sftp_hanlde_t *sftp_handle) {

    struct sockaddr_in6 sin;
    memset(&sin, 0, sizeof(sin));
    sftp_handle->sock = socket(AF_INET6, SOCK_STREAM, 0);
    sin.sin6_family = AF_INET6;
    sin.sin6_port = htons(sftp_handle->port);
    if (inet_pton(AF_INET6, sftp_handle->remote_ip, &sin.sin6_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton ip = %s failed:%s", sftp_handle->remote_ip, strerror(errno));
        return -1;
    }
    if (connect(sftp_handle->sock, (struct sockaddr *) (&sin), sizeof(sin)) != 0) {
        PRINT_ERR_HEAD;
        print_err("failed to connect %s :%s!", sftp_handle->remote_ip, strerror(errno));
        return -1;
    }
    return 0;
}

/*******************************************************************************************
*功能:      连接服务器
*参数:      handle               ----> 对象句柄
*
*           返回值                ----> ture 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_connect_server(void *handle) {

    int ret = 0;
    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;

    if (sftp_handle->session != NULL) {
        libssh2_session_disconnect(sftp_handle->session, "Normal Shutdown");
        if (sftp_handle->sftp_session != NULL) {
            libssh2_sftp_shutdown(sftp_handle->sftp_session);
            sftp_handle->sftp_session = NULL;
        }
        libssh2_session_free(sftp_handle->session);
        sftp_handle->session = NULL;
        if (sftp_handle->sock > 0) {
            close(sftp_handle->sock);
            sftp_handle->sock = -1;
        }
    }

    if (sftp_handle->ip_type == FSYNC_IPV4) {
        ret = sftp_connect_ipv4(sftp_handle);
    } else {
        ret = sftp_connect_ipv6(sftp_handle);
    }

    if (ret != 0) {
        return false;
    }
    sftp_handle->session = libssh2_session_init();
    if (sftp_handle->session == NULL) {
        PRINT_ERR_HEAD;
        print_err("libssh2 initialization session failed");
        return false;
    }

    libssh2_session_set_blocking(sftp_handle->session, 1);

    ret = libssh2_session_handshake(sftp_handle->session, sftp_handle->sock);
    if (ret) {
        char *errmsg = NULL;
        int errlen = 1024;
        libssh2_session_last_error(sftp_handle->session, &errmsg, &errlen, 1);
        PRINT_ERR_HEAD;
        print_err("Failure establishing SSH session:%s,ip = %s ,port = %d", errmsg, sftp_handle->remote_ip,
                  sftp_handle->port);
        free(errmsg);
        return false;
    }

    if (libssh2_userauth_password(sftp_handle->session, sftp_handle->user, sftp_handle->password) != 0) {
        PRINT_ERR_HEAD;
        print_err("Authentication by password failed:user = %s ,pwd = %s", sftp_handle->user, sftp_handle->password);
        return false;
    }

    sftp_handle->sftp_session = libssh2_sftp_init(sftp_handle->session);
    if (sftp_handle->sftp_session == NULL) {
        PRINT_ERR_HEAD;
        print_err("Unable to init SFTP session");
        return false;
    }

    PRINT_DBG_HEAD;
    print_dbg("connect sftp success,ip = %s ,port = %d", sftp_handle->remote_ip, sftp_handle->port);
    return true;
}


/*******************************************************************************************
*功能:      连接状态检查
*参数:      handle              ----> 对象句柄
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_check_connect(void *handle) {

    sftp_handle_t *sftp_handle = (sftp_hanlde_t *) handle;
    LIBSSH2_SFTP_ATTRIBUTES file_stat;

    if (libssh2_sftp_stat(sftp_handle->sftp_session, sftp_handle->scan_path, &file_stat) != 0) {
        PRINT_ERR_HEAD;
        print_err("check server = %s connect failed!", sftp_handle->remote_ip);
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("check server = %s connect success!", sftp_handle->remote_ip);
        return true;
    }


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
bool sftp_check_access(void *handle, const char *path_name) {

    if ((strcmp(path_name, "./") == 0) || (strcmp(path_name, "/") == 0)) {
        return true;
    }

    sftp_handle_t *sftp_handle = (sftp_hanlde_t *) handle;
    LIBSSH2_SFTP_ATTRIBUTES file_stat;

    if (libssh2_sftp_stat(sftp_handle->sftp_session, path_name, &file_stat) != 0) {
        PRINT_DBG_HEAD;
        print_dbg("check file = %s access failed!", path_name);
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("check file = %s access success", path_name);
        return true;
    }

}

/*******************************************************************************************
*功能:      路径检查
*参数:     handle              ----> 对象句柄
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_check_path(void *handle) {


    sftp_handle_t *sftp_handle = (sftp_hanlde_t *) handle;
    LIBSSH2_SFTP_ATTRIBUTES file_stat;

    if (libssh2_sftp_stat(sftp_handle->sftp_session, sftp_handle->scan_path, &file_stat) != 0) {
        PRINT_ERR_HEAD;
        print_err("check file = %s access failed!", sftp_handle->scan_path);
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("check file = %s access success", sftp_handle->scan_path);
        return true;
    }

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
int sftp_stat(void *handle, const char *path_name, struct stat *file_stat) {

    sftp_handle_t *sftp_handle = (sftp_hanlde_t *) handle;
    LIBSSH2_SFTP_ATTRIBUTES sftp_file_stat;
    if (libssh2_sftp_stat_ex(sftp_handle->sftp_session, path_name,strlen(path_name),LIBSSH2_SFTP_LSTAT, &sftp_file_stat) != 0) {
        PRINT_ERR_HEAD;
        print_err("get file = %s stat failed!", path_name);
        return -1;
    } else {
        if (LIBSSH2_SFTP_S_ISDIR(sftp_file_stat.permissions)) {
            file_stat->st_mode = FSYNC_IS_DIR;
            file_stat->st_size = 0;
            file_stat->st_mtime = FSYNC_DIR_DEFAULT_TIME;
        } else {
            file_stat->st_mode = FSYNC_IS_FILE;
            file_stat->st_size = sftp_file_stat.filesize;
            file_stat->st_mtime = sftp_file_stat.mtime;
        }
        PRINT_DBG_HEAD;
        print_dbg("get file =%s ,size = %lu , modify = %lu", path_name, file_stat->st_size, file_stat->st_mtime);
        return 0;
    }

}


int sftp_scan_dir(sftp_handle_t *sftp_handle, const char *path, GList **path_list) {

    char buf[FSYNC_CMD_MAX_LEN] = {0};
    char mem[FSYNC_CMD_MAX_LEN] = {0};
    LIBSSH2_SFTP_ATTRIBUTES attrs;

    sftp_handle->data_session = libssh2_sftp_opendir(sftp_handle->sftp_session, path);
    if (sftp_handle->data_session == NULL) {
        PRINT_ERR_HEAD;
        print_err("open sftp dir = %s failed !", path);
        return -1;
    }

    while (libssh2_sftp_readdir_ex(sftp_handle->data_session, mem, sizeof(mem), buf, sizeof(buf), &attrs) > 0) {
        if ((strcmp(".", basename(mem)) == 0) || (strcmp("..", basename(mem)) == 0)) {
            continue;
        }
        fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
        tmp_task->type = buf[0] == 'd' ? FSYNC_IS_DIR : FSYNC_IS_FILE;
        if (path[strlen(path) - 1] != '/') {
            sprintf(tmp_task->path, "%s/%s", path, mem);
        } else {
            sprintf(tmp_task->path, "%s%s", path, mem);
        }

        //printf("type = %s ,path = %s\n", tmp_task->type == FSYNC_IS_FILE ? "FILE" : "DIR", tmp_task->path);
        *path_list = g_list_prepend(*path_list, tmp_task);
    }
    libssh2_sftp_closedir(sftp_handle->data_session);

    for (GList *p_elem = *path_list; p_elem != NULL; p_elem = p_elem->next) {
        fs_task_t *tmp_task = (fs_task_t *) (p_elem->data);
        if (tmp_task->type == FSYNC_IS_FILE) {
            struct stat file_stat;
            if (sftp_stat(sftp_handle, tmp_task->path, &file_stat) == 0) {
                tmp_task->size = file_stat.st_size;
                tmp_task->modify = file_stat.st_mtime;
            }
        } else {
            tmp_task->size = 0;
            tmp_task->modify = FSYNC_DIR_DEFAULT_TIME;
        }
    }


    return 0;
}

/*******************************************************************************************
*功能:      首次扫描
*参数:      handle                    ----> 对象句柄
*           in_to_out                ----> 同步方向
*           dir_name                 ----> 扫描目录
*           dir_list                 ----> 目录列表
*           file_list                ----> 文件列表
*           ready_queue              ----> 准备列表
*           delay_time               ----> 延迟发送时间
*
*           返回值                    ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list,
                     GList **file_list, GAsyncQueue *ready_queue, int delay_time) {

    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;
    bool bover = false;
    GList *tmp_list = NULL;
    char scan_dir[FSYNC_PATH_MAX_LEN] = {0};
    struct stat file_stat;
    strcpy(scan_dir, dir_name);

    while (1) {
        sftp_scan_dir(sftp_handle, scan_dir, &tmp_list);
        while (1) {
            //取出扫描信息
            GList *p_elem = g_list_first(tmp_list);
            if (p_elem == NULL) {
                bover = true;
                break;
            }
            fs_task_t *tmp_task = (fs_task_t *) p_elem->data;
            tmp_list = g_list_delete_link(tmp_list, p_elem);

            tmp_task->in_to_out = in_to_out;
            if (tmp_task->type == FSYNC_IS_FILE) {
                if (delay_time > 0) {
                    if (g_list_length(*file_list) < FSYNC_LIST_MAX_SIZE) {
                        *file_list = g_list_prepend(*file_list, tmp_task);
                    } else {
                        sleep(delay_time);
                        for (GList *tmp_elem = *file_list; tmp_elem != NULL; tmp_elem = *file_list) {
                            g_async_queue_push(ready_queue, tmp_elem->data);
                            *file_list = g_list_delete_link(*file_list, tmp_elem);
                        }
                        g_async_queue_push(ready_queue, tmp_task);
                    }
                } else {
                    g_async_queue_push(ready_queue, tmp_task);
                }
            } else {
                *dir_list = g_list_prepend(*dir_list, tmp_task);
                strcpy(scan_dir, tmp_task->path);
                break;
            }
        }

        if (bover) {
            break;
        }
    }

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
bool sftp_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue) {
    struct stat stat_buf;
    fs_task_t *tmp_task = NULL;
    for (GList *p_elem = *file_list; p_elem != NULL; p_elem = *file_list) {
        tmp_task = (fs_task_t *) (p_elem->data);
        memset(&stat_buf, 0, sizeof(stat_buf));
        if (sftp_stat(handle, tmp_task->path, &stat_buf) != 0) {         //文件不存在
            PRINT_ERR_HEAD;
            print_err("get file = %s stat failed:%s", tmp_task->path, strerror(errno));
            free(p_elem->data);
            *file_list = g_list_delete_link(*file_list, p_elem);
        } else {
            if ((tmp_task->type == stat_buf.st_mode) &&
                ((tmp_task->modify == stat_buf.st_mtime) || (stat_buf.st_mode == FSYNC_IS_DIR))) {
                g_async_queue_push(ready_queue, tmp_task);
                *file_list = g_list_delete_link(*file_list, p_elem);                  //文件未修改
            } else {
                free(p_elem->data);
                p_elem->data = NULL;
                *file_list = g_list_delete_link(*file_list, p_elem);                  //文件被修改
            }
        }
    }
    PRINT_DBG_HEAD;
    print_dbg("sftp second scan over ,file = %d", g_async_queue_length(ready_queue));

    return true;

}

int sftp_mkdir(void *handle, const char *dir_path) {

    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;
    int ret = libssh2_sftp_mkdir(sftp_handle->sftp_session, dir_path, 0755);
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("mkdir = %s failed", dir_path);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("mkdir = %s success", dir_path);
        return 0;
    }

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
int sftp_mkdir_r(void *handle, const char *dir_path) {

    int ret = 0;
    int i = 0;
    if (sftp_check_access(handle, dir_path)) {
        return 0;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    while (1) {
        i++;
        if (dir_path[i] == '\0') {
            strncpy(dir_bak, dir_path, i);
            if (!sftp_check_access(handle, dir_bak)) {
                sftp_mkdir(handle, dir_bak);
            }
            break;
        } else if (dir_path[i] == '/') {
            strncpy(dir_bak, dir_path, i);
            if (!sftp_check_access(handle, dir_bak)) {
                sftp_mkdir(handle, dir_bak);
            }
        }
    }


    if (sftp_check_access(handle, dir_path)) {
        PRINT_DBG_HEAD;
        print_dbg("mkdir = %s success!", dir_path);
        ret = 0;
    } else {
        PRINT_ERR_HEAD;
        print_err("mkdir = %s failed!", dir_path);
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
int sftp_rmdir(void *handle, const char *dir_path) {

    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;
    if (libssh2_sftp_rmdir(sftp_handle->sftp_session, dir_path) != 0) {
        PRINT_ERR_HEAD;
        print_err("rmdir = %s failed", dir_path);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("rmdir = %s success", dir_path);
        return 0;
    }

}

/*******************************************************************************************
*功能:      递归删除目录
*参数:      handle              ----> 对象句柄
*           path               ----> 路径
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool sftp_rmdir_r(void *handle, const char *dir_path) {

    bool bret = true;
    if (!sftp_check_access(handle, dir_path)) {
        return true;
    }

    for (int i = 0; i < 3; i++) {
        if (sftp_rmdir(handle, dir_path) == 0) {
            break;
        } else {
            usleep(10000);
        }
    }

    if (sftp_check_access(handle, dir_path)) {
        bret = false;
    } else {
        bret = true;
    }

    return bret;
}

/*******************************************************************************************
*功能:      重命名文件
*参数:      handle              ----> 对象句柄
*           old_name           ----> 旧文件名
*           new_name           ----> 新文件名
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool sftp_rename(void *handle, const char *old_name, const char *new_name) {

    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;
    if (libssh2_sftp_rename(sftp_handle->sftp_session, old_name, new_name) != 0) {
        PRINT_ERR_HEAD;
        print_err("rename %s to %s failed !", old_name, new_name);
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("rename %s to %s sucess !", old_name, new_name);
        return true;
    }

}

/*******************************************************************************************
*功能:      删除文件
*参数:      handle               ----> 对象句柄
*           path                 ----> 文件路径名
*
*           返回值              ----> 0 成功, -1 失败
*
*注释:
*******************************************************************************************/
int sftp_remove(void *handle, const char *path_name) {

    sftp_handle_t *sftp_handle = (sftp_handle_t *) handle;
    if (libssh2_sftp_unlink(sftp_handle->sftp_session, path_name) != 0) {
        PRINT_ERR_HEAD;
        print_err("remove = %s failed", path_name);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("remove = %s success", path_name);
        return 0;
    }

}

/*******************************************************************************************
*功能:      打开源文件
*参数:      handle                ----> 对象句柄
*           source_file          ----> 源文件
*           返回值                ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_open_source_file(void *handle, const char *source_file) {

    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;

    sftp_handle->data_session = libssh2_sftp_open(sftp_handle->sftp_session, source_file, LIBSSH2_FXF_READ,
                                                  LIBSSH2_SFTP_S_IRUSR);

    if (sftp_handle->data_session == NULL) {
        PRINT_ERR_HEAD;
        print_err("open file = %s failed", source_file);
        return false;
    }

    return true;
}

/*******************************************************************************************
*功能:      打开目标文件
*参数:      handle                ----> 对象句柄
*           target_file          ----> 文件
*
*           返回值                ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool sftp_open_target_file(void *handle, const char *target_file) {

    char file_dir[FSYNC_PATH_MAX_LEN] = {0};

    strcpy(file_dir, target_file);
    dirname(file_dir);
    sftp_mkdir_r(handle, file_dir);

    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;
    sftp_handle->data_session = libssh2_sftp_open(sftp_handle->sftp_session, target_file,
                                                  LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                                                  LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP |
                                                  LIBSSH2_SFTP_S_IROTH);

    if (sftp_handle->data_session == NULL) {
        PRINT_ERR_HEAD;
        print_err("open file = %s failed", target_file);
        return false;
    }

    return true;

}

/*******************************************************************************************
*功能:      读取文件
*参数:      handle                ----> 数据连接句柄
*           buf                  ----> 缓冲区
*           buf_len              ----> 缓冲区长度
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int sftp_read(void *handle, void *buf, unsigned int buf_len) {

    int len = 0;
    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        len = libssh2_sftp_read(sftp_handle->data_session, (char *) buf, buf_len);
        if (len < 0) {
            if (len == LIBSSH2_ERROR_EAGAIN) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("read failed,errno = %d", len);
                break;
            }
        } else {
            break;
        }
    }

    return len;
}

/*******************************************************************************************
*功能:      写文件
*参数:      handle                ----> 数据连接句柄
*           buf                  ----> 缓冲区
*           buf_len              ----> 缓冲区长度
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int sftp_write(void *handle, void *buf, unsigned int data_len) {

    int len = 0;
    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        len = libssh2_sftp_write(sftp_handle->data_session, (const char *) buf, data_len);
        if (len < 0) {
            if (len == LIBSSH2_ERROR_EAGAIN) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("write failed,errno = %d", len);
                break;
            }
        } else {
            break;
        }
    }

    return len;
}

/*******************************************************************************************
*功能:      关闭句柄
*参数:      handle                ----> 数据连接句柄
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void sftp_close_data_handle(void *handle) {

    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;
    if (sftp_handle->data_session != NULL) {
        libssh2_sftp_close(sftp_handle->data_session);
        sftp_handle->data_session = NULL;
    }
    return;
}

void sftp_disconnect(void *handle) {

    sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) handle;
    if (sftp_handle->session != NULL) {
        libssh2_session_disconnect(sftp_handle->session, "Normal Shutdown");
    }
    if (sftp_handle->sock > 0) {
        close(sftp_handle->sock);
        sftp_handle->sock = -1;
    }
    return;
}

/*******************************************************************************************
*功能:      销毁sftp对象
*参数:      worker                ----> 数据连接句柄
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void sftp_destroy_worker(fs_work_t *worker) {

    if (worker->handle != NULL) {
        sftp_hanlde_t *sftp_handle = (sftp_hanlde_t *) (worker->handle);
        if (sftp_handle != NULL) {
            if (sftp_handle->sftp_session != NULL) {
                libssh2_sftp_shutdown(sftp_handle->sftp_session);
                sftp_handle->sftp_session = NULL;
            }
            if (sftp_handle->session != NULL) {
                libssh2_session_free(sftp_handle->session);
                sftp_handle->session = NULL;
            }
        }
        free(worker->handle);
        worker->handle = NULL;
    }

    if (worker != NULL) {
        free(worker);
    }

    return;;
}