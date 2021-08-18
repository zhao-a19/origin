#include "smb_sync.h"

/*******************************************************************************************
*功能:      初始化samba对象     
*参数:                           
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
fs_work_t *create_smb_worker(void) {

    fs_work_t *smb_worker = (fs_work_t *) (calloc(1, sizeof(fs_work_t)));
    if (smb_worker == NULL) {
        return NULL;
    }
    smb_worker->handle = calloc(1, sizeof(smb_handle_t));

    smb_worker->init_worker_obj = init_smb_worker_obj;
    smb_worker->connect_server = smb_mount_server;
    smb_worker->check_server_connect = smb_check_mount_stat;
    smb_worker->check_scan_path = smb_check_path;

    smb_worker->first_scan = smb_first_scan;
    smb_worker->second_scan = smb_second_scan;

    smb_worker->get_stat = smb_stat;
    smb_worker->check_access = smb_access;

    smb_worker->mkdir_r = smb_mkdir;
    smb_worker->rmdir = smb_rmdir;

    smb_worker->remove = smb_remove;
    smb_worker->rename = smb_rename;

    smb_worker->open_source_file = smb_open_source_file;
    smb_worker->open_target_file = smb_open_target_file;
    smb_worker->read = smb_read;
    smb_worker->write = smb_write;

    smb_worker->disconnect = smb_disconnect;
    smb_worker->close_data_handle = smb_close_data_handle;
    smb_worker->destroy_worker_obj = destroy_smb_worker_obj;

    return smb_worker;
}

int init_smb_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info) {

    if ((worker_obj == NULL) || srv_info == NULL) {
        PRINT_ERR_HEAD;
        print_err("worker or srv info = NULL");
        return -1;
    }

    smb_handle_t *smb_handle = (smb_handle_t *) worker_obj->handle;
    smb_handle->protocol = srv_info->protocol;
    strcpy(smb_handle->user, srv_info->user);
    strcpy(smb_handle->password, srv_info->pwd);
    if (strchr(srv_info->use_ip, ':') != NULL) {
        smb_handle->ip_type = FSYNC_IPV6;
    } else {
        smb_handle->ip_type = FSYNC_IPV4;
    }
    strcpy(smb_handle->remote_ip, srv_info->use_ip);
    smb_handle->port = srv_info->port;
    strcpy(smb_handle->share_path, srv_info->share_path);
    strcpy(smb_handle->local_path, srv_info->mount_path);
    strcpy(smb_handle->scan_path, srv_info->scan_path);


    return 0;
}

/*******************************************************************************************
*功能:      销毁samba对象
*参数:      worker                ----> 数据连接句柄
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void destroy_smb_worker_obj(fs_work_t *worker) {

    if (worker->handle != NULL) {
        free(worker->handle);
        worker->handle = NULL;
    }
    if (worker != NULL) {
        free(worker);
    }
    return;
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
bool smb_access(void *handle, const char *path_name) {

    if ((strcmp(path_name, "./") == 0) || (strcmp(path_name, "/") == 0)) {
        return true;
    }

    if (access(path_name, F_OK) != 0) {
        return false;
    } else {
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
int smb_stat(void *handle, const char *path_name, struct stat *file_stat) {

    if (stat(path_name, file_stat) != 0) {
        return -1;
    } else {
        if (file_stat->st_mode & S_IFDIR) {
            file_stat->st_mode = FSYNC_IS_DIR;
            file_stat->st_size = 0;
            file_stat->st_mtime = FSYNC_DIR_DEFAULT_TIME;
        } else {
            file_stat->st_mode = FSYNC_IS_FILE;
        }
    }
    return 0;
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
int smb_remove(void *handle, const char *path_name) {
    return remove(path_name);
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
bool smb_rename(void *handle, const char *old_name, const char *new_name) {

    bool bret = false;
    if (rename(old_name, new_name) == 0) {
        bret = true;
    }

    return bret;
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
bool smb_rmdir(void *handle, const char *path) {

    for (int i = 0; i < 3; i++) {
        if (rmdir(path) == 0) {
            break;
        } else {
            usleep(10000);
        }
    }
    if (access(path, F_OK) != 0) {
        PRINT_DBG_HEAD;
        print_dbg("remove dir = %s success", path);
        return true;
    } else {
        PRINT_ERR_HEAD;
        print_err("remove dir = %s failed", path);
        return false;
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
bool smb_rmdir_r(void *handle, const char *path) {

    if (access(path, F_OK) != 0) {
        return true;
    }

    if (rmdir(path) != 0) {
        char cmd[FSYNC_PATH_MAX_LEN] = {0};
        sprintf(cmd, "rm -rf \"%s\"", path);
        system(cmd);
    }
    if (access(path, F_OK) != 0) {
        PRINT_DBG_HEAD;
        print_dbg("remove dir = %s success", path);
        return true;
    } else {
        PRINT_ERR_HEAD;
        print_err("remove dir = %s failed", path);
        return false;
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
int smb_mkdir(void *handle, const char *dir_path) {

    int ret = 0;
    int i = 0;
    if (access(dir_path, F_OK) == 0) {
        return 0;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    while (1) {
        i++;
        if (dir_path[i] == '\0') {
            strncpy(dir_bak, dir_path, i);
            if (access(dir_bak, F_OK) != 0) {
                mkdir(dir_bak, 0777);
            }
            break;
        } else if (dir_path[i] == '/') {
            strncpy(dir_bak, dir_path, i);
            if (access(dir_bak, F_OK) != 0) {
                mkdir(dir_bak, 0777);
            }
        }
    }


    if (access(dir_path, F_OK) != 0) {
        PRINT_ERR_HEAD;
        print_err("mkdir = %s failed!", dir_path);
        ret = -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("mkdir = %s success!", dir_path);
        ret = 0;
    }

    return ret;
}


/*******************************************************************************************
*功能:      路径检查
*参数:     handle              ----> 对象句柄
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool smb_check_path(void *handle) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    if (strlen(smb_handle->scan_path) == 0) {
        PRINT_ERR_HEAD;
        print_err("check server path = (null)");
        return false;
    }

    bool bret = true;

    if (access(smb_handle->scan_path, F_OK) != 0) {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("scan path = %s not existed !", smb_handle->scan_path);
    } else {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("scan path = %s check ok !", smb_handle->scan_path);
    }
    return bret;
}


/*******************************************************************************************
*功能:      挂载状态检查
*参数:      handle              ----> 对象句柄
*
*           返回值              ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool smb_check_mount_stat(void *handle) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    bool bret = true;
    struct statvfs mount_stat;
    struct stat dir_stat;

    if (access(smb_handle->local_path, F_OK) != 0) {
        PRINT_ERR_HEAD;
        print_err("mount path = %s not exist", smb_handle->local_path);
        return false;
    }

    if (stat(smb_handle->scan_path, &dir_stat) != 0) {
        PRINT_ERR_HEAD;
        print_err("get scan dir = %s stat failed:%s", smb_handle->scan_path, strerror(errno));
        bret = false;
    }

    if (statvfs(smb_handle->local_path, &mount_stat) != 0) {
        PRINT_ERR_HEAD;
        print_err("get mount path = %s stat failed:%s", smb_handle->local_path, strerror(errno));
        bret = false;
    }

    if ((mount_stat.f_flag & ST_NOEXEC) == 0) {
        PRINT_ERR_HEAD;
        print_err("mount path = %s is umount stat", smb_handle->local_path);
        bret = false;
    }

    return bret;
}

/*******************************************************************************************
*功能:      挂载服务器
*参数:      handle               ----> 对象句柄
 *          rule                 ----> 策略信息
*           srv_info             ----> 服务器信息
*
*           返回值                ----> ture 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool smb_mount_server(void *handle) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    bool bret = false;
    static pthread_mutex_t mount_mut = PTHREAD_MUTEX_INITIALIZER;


    pthread_mutex_lock(&mount_mut);
    if (smb_handle->protocol == FSYNC_CIFS_PROTOCOL) {
        bret = mount_cifs(smb_handle->remote_ip, smb_handle->port, smb_handle->share_path, smb_handle->local_path,
                          smb_handle->user, smb_handle->password);
    } else {
        bret = mount_nfs(smb_handle->remote_ip, smb_handle->port, smb_handle->share_path, smb_handle->local_path);
    }
    pthread_mutex_unlock(&mount_mut);
    if (bret) {
        PRINT_DBG_HEAD;
        print_dbg("mount %s success !", smb_handle->share_path);
    } else {
        PRINT_ERR_HEAD;
        print_err("mount %s failed !", smb_handle->share_path);
    }

    return bret;
}

/*******************************************************************************************
*功能:      挂载cifs主机
*参数:      source_ip             ----> 源IP
*           port                  ----> 端口 
*           share_path            ----> 共享路径
*           local_path            ----> 本地挂载路径
*           user                  ----> 用户名
*           pwd              ----> 密码
*           返回值                 ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool mount_cifs(const char *source_ip, int port, const char *share_path, const char *local_path, const char *user,
                const char *password) {

    bool bret = false;
    int ret = 0;
    if (smb_mkdir(NULL, local_path) != 0) {
        PRINT_ERR_HEAD;
        print_err("make local dir = %s failed !", local_path);
        return false;
    }

    char source_path[FSYNC_PATH_MAX_LEN] = {0};
    const char *tmp_start = strrchr(share_path, '/');
    if (tmp_start == NULL) {
        sprintf(source_path, "//%s/%s", source_ip, share_path);
    } else {
        sprintf(source_path, "//%s%s", source_ip, tmp_start);
    }

    char data[FSYNC_CMD_MAX_LEN] = {0};
    char safe_opt[][FSYNC_NAME_MAX_LEN] = {"vers=1.0", "vers=2.0", "vers=3.0", "sec=none", "sec=krb5", "sec=krb5i",
                                           "sec=ntlm", "sec=ntlmi", "sec=ntlmv2", "sec=ntlmv2i"};

    mkdir(local_path, FSYNC_DIR_DEFAULT_MODE);
    umount(local_path);
    sprintf(data, "username=%s,password=%s,port=%d,noserverino,iocharset=utf8,actimeo=1", user, password, port);
    ret = mount(source_path, local_path, "cifs", MS_NOEXEC, data);
    if (ret != 0) {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("mount cifs (%s:%s), local = %s, errno = %d failed: %s!", source_path, data, local_path, errno,
                  strerror(errno));
    } else {
        bret = true;
        PRINT_INFO_HEAD;
        print_info("mount cifs (%s:%s), local = %s, success!", source_path, data, local_path);
    }

    if (!bret) {
        for (int i = 0; i < sizeof(safe_opt) / sizeof(safe_opt[0]); ++i) {
            sprintf(data, "username=%s,pwd=%s,port=%d,noserverino,iocharset=utf8,actimeo=1,%s",
                    user, password, port, safe_opt[i]);
            ret = mount(source_path, local_path, "cifs", MS_NOEXEC, data);
            if (ret != 0) {
                PRINT_ERR_HEAD;
                print_err("mount cifs (%s:%s), local = %s, errno = %d failed:%s!", source_path, data, local_path, errno,
                          strerror(errno));
            } else {
                bret = true;
                PRINT_INFO_HEAD;
                print_info("mount cifs (%s:%s), local = %s, success!", source_path, data, local_path);
                break;
            }
        }
    }

    return bret;
}

/*******************************************************************************************
*功能:      挂载nfs主机
*参数:      source_ip             ----> 源IP
*           port                  ----> 端口 
*           share_path            ----> 共享路径
*           local_path            ----> 本地挂载路径
*           返回值                 ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool mount_nfs(const char *source_ip, int port, const char *share_path, const char *local_path) {
//mount(":/home/songyu/work/nfs_source", "/tmp/MQ00/intsrv/", "nfs", MS_NOEXEC, "nolock,actimeo=5,retry=3,hard,timeo=300,intr,tcp,addr=192.168.2.206,port=2049");

    bool bret = false;
    int ret = 0;
    char data[FSYNC_PATH_MAX_LEN] = {0};
    char tmp_source_path[FSYNC_PATH_MAX_LEN] = {0};

    if (smb_mkdir(NULL, local_path) != 0) {
        PRINT_ERR_HEAD;
        print_err("make local dir = %s failed !", local_path);
        return false;
    }

    umount(local_path);
    sprintf(tmp_source_path, ":%s", share_path);
    sprintf(data, "nolock,retry=3,hard,timeo=300,intr,tcp,addr=%s,port=%d", source_ip, port);
    ret = mount(tmp_source_path, local_path, "nfs", MS_NOEXEC, data);
    if (ret != 0) {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("mount nfs (%s:%s), local = %s, errno = %d failed:%s!", share_path, data, local_path, errno,
                  strerror(errno));
    } else {
        bret = true;
        PRINT_INFO_HEAD;
        print_info("mount nfs (%s:%s), local = %s, success!", share_path, data, local_path);
    }


    return bret;
}

/*******************************************************************************************
*功能:       设置传输任务
*参数:       tmp_task                           ----> 临时任务结构指针
*            in_to_out                          ----> 同步方向
*            path                          ----> 路径名
*            size                          ----> 文件大小
*            modify                        ----> 最后修改时间
*            type                          ----> 文件类型(0目录，1文件)
*            返回值                             ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool set_task_value(fs_task_t *tmp_task, bool in_to_out, const char *path_name, off_t file_size, time_t modify_time,
                    int file_type) {

    tmp_task->in_to_out = in_to_out;
    if (path_name != NULL) {
        strcpy(tmp_task->path, path_name);
    }
    tmp_task->size = file_size;
    tmp_task->modify = modify_time;
    tmp_task->type = file_type;

    return true;
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
bool smb_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                    GAsyncQueue *ready_queue, int delay_time) {

    struct stat stat_buf;
    static unsigned int list_count = 0;
    char path_name[FSYNC_PATH_MAX_LEN] = {0};
    struct dirent **name_list = NULL;

    if (access(dir_name, F_OK) != 0) {
        PRINT_ERR_HEAD;
        print_err("scan dir = %s not exit ,return.", dir_name);
        return false;
    }
    int count = scandir(dir_name, &name_list, 0, alphasort);
    if (count < 0) {
        PRINT_ERR_HEAD;
        print_err("scandir = %s failed:%s", dir_name, strerror(errno));
        goto _exit;
    }

    for (int i = 0; i < count; i++) {
        if ((!strcmp(name_list[i]->d_name, ".")) || (!strcmp(name_list[i]->d_name, "..")) ||
            (!strcmp(name_list[i]->d_name, "/.."))) {
            continue;
        }

        sprintf(path_name, "%s/%s", dir_name, name_list[i]->d_name);

        memset(&stat_buf, 0, sizeof(stat_buf));
        if (smb_stat(handle, path_name, &stat_buf) != 0) {
            continue;
        }

        fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));

        if (name_list[i]->d_type == DT_DIR) {
            set_task_value(tmp_task, in_to_out, path_name, stat_buf.st_size, stat_buf.st_mtime, FSYNC_IS_DIR);
            *dir_list = g_list_prepend(*dir_list, tmp_task);

            smb_first_scan(handle, in_to_out, path_name, dir_list, file_list, ready_queue, delay_time);

        } else {
            set_task_value(tmp_task, in_to_out, path_name, stat_buf.st_size, stat_buf.st_mtime, FSYNC_IS_FILE);
            if (delay_time > 0) {
                *file_list = g_list_prepend(*file_list, tmp_task);
                list_count++;
                if (list_count > FSYNC_LIST_MAX_SIZE) {
                    sleep(delay_time);
                    for (GList *tmp_elem = *file_list; tmp_elem != NULL; tmp_elem = *file_list) {
                        g_async_queue_push(ready_queue, tmp_elem->data);
                        *file_list = g_list_delete_link(*file_list, tmp_elem);
                    }

                    list_count = 0;
                    while (g_async_queue_length(ready_queue) > 0) {
                        sleep(1);
                    }
                }
            } else {
                g_async_queue_push(ready_queue, tmp_task);
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
bool smb_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue) {

    struct stat stat_buf;
    fs_task_t *tmp_task = NULL;
    for (GList *p_elem = *file_list; p_elem != NULL; p_elem = *file_list) {
        tmp_task = (fs_task_t *) (p_elem->data);
        memset(&stat_buf, 0, sizeof(stat_buf));
        if (smb_stat(handle, tmp_task->path, &stat_buf) != 0) {      //文件不存在
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

    return true;
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
bool smb_open_source_file(void *handle, const char *source_file) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    bool bret = false;
    smb_handle->data_fd = open(source_file, O_RDONLY | O_NONBLOCK);
    if (smb_handle->data_fd == -1) {
        PRINT_ERR_HEAD
        print_err("open source file = %s failed:%s !", source_file, strerror(errno));
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("open source file = %s success !", source_file);
        bret = true;
    }

    return bret;
}

/*******************************************************************************************
*功能:      打开目标文件
*参数:      handle                ----> 对象句柄 
*           data_handle          ----> 数据连接句柄
*           target_file          ----> 源文件
*
*           返回值                ----> true 成功 , false 失败
*
*注释:
*******************************************************************************************/
bool smb_open_target_file(void *handle, const char *target_file) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    bool bret = false;
    char file_dir[FSYNC_PATH_MAX_LEN] = {0};
    strcpy(file_dir, target_file);
    dirname(file_dir);

    for (int i = 0; i < 3; i++) {
        smb_mkdir(NULL, file_dir);
        smb_handle->data_fd = open(target_file, O_CREAT | O_WRONLY | O_NONBLOCK, 0666);
        if (smb_handle->data_fd == -1) {
            PRINT_ERR_HEAD
            print_err("open target file = %s failed:%s !", target_file, strerror(errno));
            bret = false;
        } else {
            PRINT_DBG_HEAD;
            print_dbg("open target file = %s success !", target_file);
            bret = true;
            break;
        }
        sleep(1);
    }

    return bret;
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
int smb_read(void *handle, void *buf, unsigned int buf_len) {
    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    int read_len = 0;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        read_len = read(smb_handle->data_fd, buf, buf_len);;
        if (read_len < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("read error:%s", strerror(errno));
                break;
            }
        } else {
            break;
        }
    }

    return read_len;
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
int smb_write(void *handle, void *buf, unsigned int buf_len) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;
    int write_len = 0;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        write_len = write(smb_handle->data_fd, buf, buf_len);
        if (write_len < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("write error:%s", strerror(errno));
                break;
            }
        } else {
            break;
        }
    }
    return write_len;
}

/*******************************************************************************************
*功能:      关闭句柄
*参数:      handle                ----> 数据连接句柄 
*           返回值                ----> 大于0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void smb_close_data_handle(void *handle) {

    smb_handle_t *smb_handle = (smb_handle_t *) handle;

    close(smb_handle->data_fd);

    return;
}

void smb_disconnect(void *handle) {
    //umount((char *)handle);
    return;
}

