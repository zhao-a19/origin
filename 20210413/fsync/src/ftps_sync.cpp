#include "ftps_sync.h"

/*******************************************************************************************
*功能:      初始化ftps对象     
*参数:                           
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
fs_work_t *create_ftps_worker(void) {

    fs_work_t *ftps_worker = (fs_work_t *) calloc(1, sizeof(fs_work_t));
    if (ftps_worker == NULL) {
        return NULL;
    }
    ftps_worker->handle = calloc(1, sizeof(ftps_handle_t));

    ftps_worker->init_worker_obj = init_ftps_worker_obj;
    ftps_worker->connect_server = ftps_connect_server;
    ftps_worker->check_server_connect = ftps_check_server_connect;
    ftps_worker->check_scan_path = ftps_check_scan_path;

    ftps_worker->first_scan = ftps_first_scan;
    ftps_worker->second_scan = ftps_second_scan;

    ftps_worker->get_stat = ftps_get_stat;
    ftps_worker->check_access = ftps_check_access;

    ftps_worker->mkdir_r = ftps_mkdir_r;
    ftps_worker->rmdir = ftps_rmdir_r;

    ftps_worker->remove = ftps_remove;
    ftps_worker->rename = ftps_rename;

    ftps_worker->open_source_file = ftps_open_source_file;
    ftps_worker->open_target_file = ftps_open_target_file;
    ftps_worker->read = ftps_read;
    ftps_worker->write = ftps_write;

    ftps_worker->disconnect = ftps_disconnect;
    ftps_worker->close_data_handle = ftps_close_data_handle;
    ftps_worker->destroy_worker_obj = destroy_ftps_worker_obj;


    return ftps_worker;
}

int init_ftps_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info) {

    if ((worker_obj == NULL) || srv_info == NULL) {
        PRINT_ERR_HEAD;
        print_err("worker or srv info = NULL");
        return -1;
    }

    ftps_handle_t *ftps_handle = (ftps_handle_t *) worker_obj->handle;
    ftps_handle->protocol = srv_info->protocol;
    strcpy(ftps_handle->user, srv_info->user);
    strcpy(ftps_handle->password, srv_info->pwd);
    if (strchr(srv_info->use_ip, ':') != NULL) {
        ftps_handle->ip_type = FSYNC_IPV6;
    } else {
        ftps_handle->ip_type = FSYNC_IPV4;
    }
    strcpy(ftps_handle->remote_ip, srv_info->use_ip);
    ftps_handle->port = srv_info->port;
    strcpy(ftps_handle->scan_path, srv_info->scan_path);

    static pthread_mutex_t ftps_ssl_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&ftps_ssl_mutex);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
    pthread_mutex_unlock(&ftps_ssl_mutex);

    ftps_handle->ctx = SSL_CTX_new(SSLv23_client_method());
    if (ftps_handle->ctx == NULL) {
        PRINT_ERR_HEAD;
        print_err("create ctx failed:%s", ERR_error_string(ERR_get_error(), NULL));
    }

    return 0;
}

void destroy_ftps_worker_obj(fs_work_t *worker) {

    if ((worker == NULL) || (worker->handle == NULL)) {
        return;
    }

    ftps_handle_t *ftps_obj = (ftps_handle_t *) (worker->handle);
    if (ftps_obj->cmd_ssl != NULL) {
        SSL_free(ftps_obj->cmd_ssl);
    }
    if (ftps_obj->ctx != NULL) {
        SSL_CTX_free(ftps_obj->ctx);
    }

    free(worker->handle);
    worker->handle = NULL;
    free(worker);

}

/**
 * ftps同步读取命令行
 * @param ftps_obj ftps对象
 * @return 读取到命令行长度
 */
int ftps_read_line_fd(ftps_handle_t *ftps_obj) {

    int read_len = 0;
    char *end = NULL;
    char tran_buf[FSYNC_CMD_MAX_LEN] = {0};

    memset(ftps_obj->resp_buf, 0, FSYNC_CMD_MAX_LEN);
    for (int i = 0; i < 3; i++) {
        if ((end = strstr(ftps_obj->cmd_buf, "\r\n")) == NULL) {
            read_len = read(ftps_obj->cmd_fd, tran_buf, FSYNC_CMD_MAX_LEN);
            if (read_len < 0) {
                if ((errno == EAGAIN) || (errno == EINTR)) {
                    usleep(10000);
                    continue;
                } else {
                    PRINT_ERR_HEAD;
                    print_err("read cmd fd = %d is failed !", ftps_obj->cmd_fd);
                    read_len = -1;
                    break;
                }
            } else if (read_len == 0) {
                PRINT_ERR_HEAD;
                print_err("remote is disconnect,fd = %d", ftps_obj->cmd_fd);
                read_len = -1;
                break;
            }
            strcat(ftps_obj->cmd_buf, tran_buf);
        } else {
            end += 2;
            strncpy(ftps_obj->resp_buf, ftps_obj->cmd_buf, end - (ftps_obj->cmd_buf));
            strcpy(tran_buf, end);
            strcpy(ftps_obj->cmd_buf, tran_buf);
            read_len = strlen(ftps_obj->resp_buf);
            PRINT_DBG_HEAD;
            print_dbg("resp buf = %s", ftps_obj->resp_buf);
            break;
        }

    }

    return read_len;
}

/**
 * ftps同步读取返回值
 * @param ftps_obj ftps对象
 * @param exp_char 期望的返回值首字符
 * @return 成功 0 失败 -1
 */
int ftps_read_resp_fd(ftps_handle_t *ftps_obj, char exp_char) {

    int ret = 0;
    if (ftps_read_line_fd(ftps_obj) <= 0) {
        PRINT_ERR_HEAD;
        print_err("read failed!");
        return -1;
    }

    if (ftps_obj->resp_buf[0] == exp_char) {
        ret = 0;
    } else {
        PRINT_ERR_HEAD;
        print_err("expect = %c ,err resp = %s", exp_char, ftps_obj->resp_buf);
        ret = -1;
    }

    return ret;
}


/**
 * 发送命令并判断返回值
 * @param ftps_obj ftps对象
 * @param cmd 需发送的命令
 * @param exp_resp 期望返回值首字符
 * @return 成功 0 失败 -1
 */
int ftps_send_cmd_fd(ftps_handle_t *ftps_obj, const char *cmd, char exp_resp) {

    int ret = 0;
    memset(ftps_obj->cmd_buf, 0, FSYNC_CMD_MAX_LEN);
    if (write(ftps_obj->cmd_fd, cmd, strlen(cmd)) != strlen(cmd)) {
        PRINT_ERR_HEAD;
        print_err("cmd fd = %d ,send cmd = %s failed:%s !", ftps_obj->cmd_fd, cmd, strerror(errno));
        return -1;
    }

    ret = ftps_read_resp_fd(ftps_obj, exp_resp);
    PRINT_DBG_HEAD;
    print_dbg("cmd fd = %d ,send cmd = %s resp = %s", ftps_obj->cmd_fd, cmd, ftps_obj->resp_buf);

    return ret;
}

/**
 * ftps同步读取命令行
 * @param ftps_obj ftps对象
 * @return 读取到命令行长度
 */
int ftps_read_line_ssl(ftps_handle_t *ftps_obj) {

    int read_len = 0;
    char *end = NULL;
    char tran_buf[FSYNC_CMD_MAX_LEN] = {0};

    memset(ftps_obj->resp_buf, 0, FSYNC_CMD_MAX_LEN);
    for (int i = 0; i < 3; i++) {
        if ((end = strstr(ftps_obj->cmd_buf, "\r\n")) == NULL) {
            read_len = SSL_read(ftps_obj->cmd_ssl, tran_buf, sizeof(tran_buf));
            if (read_len < 0) {
                if ((errno == EAGAIN) || (errno == EINTR)) {
                    usleep(10000);
                    continue;
                } else {
                    PRINT_ERR_HEAD;
                    print_err("read cmd fd = %d is failed !", ftps_obj->cmd_fd);
                    read_len = -1;
                    break;
                }
            } else if (read_len == 0) {
                PRINT_ERR_HEAD;
                print_err("remote is disconnect,fd = %d", ftps_obj->cmd_fd);
                read_len = -1;
                break;
            }
            strcat(ftps_obj->cmd_buf, tran_buf);
        } else {
            end += 2;
            strncpy(ftps_obj->resp_buf, ftps_obj->cmd_buf, end - (ftps_obj->cmd_buf));
            strcpy(tran_buf, end);
            strcpy(ftps_obj->cmd_buf, tran_buf);
            read_len = strlen(ftps_obj->resp_buf);
            PRINT_DBG_HEAD;
            print_dbg("resp buf = %s", ftps_obj->resp_buf);
            break;
        }

    }

    return read_len;
}

/**
 * ftps同步读取返回值
 * @param ftps_obj ftps对象
 * @param exp_char 期望的返回值首字符
 * @return 成功 0 失败 -1
 */
int ftps_read_resp_ssl(ftps_handle_t *ftps_obj, char exp_char) {

    int ret = 0;
    if (ftps_read_line_ssl(ftps_obj) <= 0) {
        PRINT_ERR_HEAD;
        print_err("read failed!");
        return -1;
    }

    if (ftps_obj->resp_buf[0] == exp_char) {
        ret = 0;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("expect = %c ", exp_char);
        ret = -1;
    }

    return ret;
}


/**
 * 发送命令并判断返回值
 * @param ftps_obj ftps对象
 * @param cmd 需发送的命令
 * @param exp_resp 期望返回值首字符
 * @return 成功 0 失败 -1
 */
int ftps_send_cmd_ssl(ftps_handle_t *ftps_obj, const char *cmd, char exp_resp) {

    if (ftps_obj->cmd_ssl == NULL) {
        PRINT_ERR_HEAD;
        print_err("cmd ssl is NULL !");
        return -1;
    }
    int ret = 0;
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = 0;
    int i = ftps_obj->cmd_fd + 1;

    fd_set mask;
    FD_ZERO(&mask);
    FD_SET(ftps_obj->cmd_fd, &mask);
    i = select(i + 1, &mask, NULL, NULL, &tv);
    if (i >= 1) {
        SSL_read(ftps_obj->cmd_ssl, ftps_obj->cmd_buf, FSYNC_CMD_MAX_LEN);
    }
    memset(ftps_obj->cmd_buf, 0, FSYNC_CMD_MAX_LEN);
    if (SSL_write(ftps_obj->cmd_ssl, cmd, strlen(cmd)) != strlen(cmd)) {
        PRINT_ERR_HEAD;
        print_err("cmd fd = %d ,send cmd = %s failed:%s !", ftps_obj->cmd_fd, cmd, strerror(errno));
        return -1;
    }

    ret = ftps_read_resp_ssl(ftps_obj, exp_resp);
    PRINT_DBG_HEAD;
    print_dbg("cmd fd = %d ,send cmd = %s resp = %s", ftps_obj->cmd_fd, cmd, ftps_obj->resp_buf);

    return ret;
}

/**
 * 创建ipv4命令连接(显式连接)
 * @param ftps_obj ftps对象
 * @return 成功 0 失败 -1
 */
int ftps_cmd_connect_ipv4_explicit(ftps_handle_t *ftps_obj) {

    int fd = -1;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(ftps_obj->port);
    if (inet_pton(AF_INET, ftps_obj->remote_ip, &sin.sin_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {            //端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};                                  //设置连接超时
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    ftps_obj->cmd_fd = fd;

    if (ftps_read_resp_fd(ftps_obj, '2') == -1) {                                    //等待连接成功消息
        close(fd);
        return -1;
    }

    if (ftps_send_cmd_fd(ftps_obj, "AUTH SSL\r\n", '2') == -1) {               //请求开启SSL连接
        close(fd);
        return -1;
    }

    ftps_obj->cmd_ssl = SSL_new(ftps_obj->ctx);
    if (ftps_obj->cmd_ssl == NULL) {
        PRINT_ERR_HEAD;
        print_err("create cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    } else {
        SSL_set_fd(ftps_obj->cmd_ssl, ftps_obj->cmd_fd);
    }

    if (SSL_connect(ftps_obj->cmd_ssl) == -1) {
        PRINT_ERR_HEAD;
        print_err("connect cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        close(fd);
        return -1;
    } else {
        X509 *cert;
        cert = SSL_get_peer_certificate(ftps_obj->cmd_ssl);
        if (cert == NULL) {
            PRINT_ERR_HEAD;
            print_err("get ssl crt failed:%s", ERR_error_string(ERR_get_error(), NULL));
            close(fd);
            return -1;
        } else {
            X509_free(cert);
        }
    }

    if (getsockname(ftps_obj->cmd_fd, (struct sockaddr *) &sin, &len) == -1) {                 //获取命令连接信息
        PRINT_ERR_HEAD;
        print_err("get cmd fd info failed:%s", strerror(errno));
    } else {                                                                                  //获取本地IP
        inet_ntop(AF_INET, (struct sockaddr *) &sin.sin_addr, ftps_obj->local_ip, FSYNC_IP_MAX_LEN);
        PRINT_DBG_HEAD;
        print_dbg("local remote_ip = %s", ftps_obj->local_ip);
    }

    return fd;
}

/**
 * 创建ipv4命令连接(隐式连接)
 * @param ftps_obj ftps对象
 * @return 成功 fd 失败 -1
 */
int ftps_cmd_connect_ipv4_implicit(ftps_handle_t *ftps_obj) {

    int fd = -1;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(ftps_obj->port);
    if (inet_pton(AF_INET, ftps_obj->remote_ip, &sin.sin_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {            //端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};                                  //设置连接超时
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    ftps_obj->cmd_fd = fd;

    ftps_obj->cmd_ssl = SSL_new(ftps_obj->ctx);
    if (ftps_obj->cmd_ssl == NULL) {
        PRINT_ERR_HEAD;
        print_err("create cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    } else {
        SSL_set_fd(ftps_obj->cmd_ssl, ftps_obj->cmd_fd);
    }

    if (SSL_connect(ftps_obj->cmd_ssl) == -1) {
        PRINT_DBG_HEAD;
        print_dbg("connect cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        close(fd);
        return -1;
    } else {
        X509 *cert;
        cert = SSL_get_peer_certificate(ftps_obj->cmd_ssl);
        if (cert == NULL) {
            PRINT_ERR_HEAD;
            print_err("get ssl crt failed:%s", ERR_error_string(ERR_get_error(), NULL));
            close(fd);
            return -1;
        } else {
            X509_free(cert);
        }
    }

    if (ftps_read_resp_ssl(ftps_obj, '2') == -1) {                                    //等待连接成功消息
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        close(fd);
        return -1;
    }

    if (getsockname(ftps_obj->cmd_fd, (struct sockaddr *) &sin, &len) == -1) {                 //获取命令连接信息
        PRINT_ERR_HEAD;
        print_err("get cmd fd info failed:%s", strerror(errno));
    } else {                                                                                  //获取本地IP
        inet_ntop(AF_INET, (struct sockaddr *) &sin.sin_addr, ftps_obj->local_ip, FSYNC_IP_MAX_LEN);
        PRINT_DBG_HEAD;
        print_dbg("local remote_ip = %s", ftps_obj->local_ip);
    }

    return fd;
}

/**
 * 创建ipv6命令连接(隐式连接)
 * @param ftps_obj ftps对象
 * @return 成功 fd 失败 -1
 */
int ftps_cmd_connect_ipv6_implicit(ftps_handle_t *ftps_obj) {

    int fd = -1;
    struct sockaddr_in6 sin;
    socklen_t len = sizeof(sin);
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_port = htons(ftps_obj->port);
    if (inet_pton(AF_INET6, ftps_obj->remote_ip, &sin.sin6_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {
        PRINT_ERR_HEAD;
        print_err("setsockopt failed:%s", strerror(errno));
        close(fd);
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }

    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    ftps_obj->cmd_fd = fd;

    ftps_obj->cmd_ssl = SSL_new(ftps_obj->ctx);
    if (ftps_obj->cmd_ssl == NULL) {
        PRINT_ERR_HEAD;
        print_err("create cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    } else {
        SSL_set_fd(ftps_obj->cmd_ssl, ftps_obj->cmd_fd);
    }

    if (SSL_connect(ftps_obj->cmd_ssl) == -1) {
        PRINT_ERR_HEAD;
        print_err("connect cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        close(fd);
        return -1;
    } else {
        X509 *cert;
        cert = SSL_get_peer_certificate(ftps_obj->cmd_ssl);
        if (cert == NULL) {
            PRINT_ERR_HEAD;
            print_err("get ssl crt failed:%s", ERR_error_string(ERR_get_error(), NULL));
            close(fd);
            return -1;
        } else {
            X509_free(cert);
        }
    }

    if (ftps_read_resp_ssl(ftps_obj, '2') == -1) {
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        return -1;
    }

    if (getsockname(ftps_obj->cmd_fd, (struct sockaddr *) &sin, &len) == -1) {
        PRINT_ERR_HEAD;
        print_err("get cmd fd info failed:%s", strerror(errno));
    } else {
        inet_ntop(AF_INET6, (struct sockaddr *) &sin.sin6_addr, ftps_obj->local_ip, FSYNC_IP_MAX_LEN);
        PRINT_DBG_HEAD;
        print_dbg("local remote_ip = %s", ftps_obj->local_ip);
    }

    return fd;
}

/**
 * 创建ipv6命令连接(显式连接)
 * @param ftps_obj ftps对象
 * @return 成功 fd 失败 -1
 */
int ftps_cmd_connect_ipv6_explicit(ftps_handle_t *ftps_obj) {

    int fd = -1;
    struct sockaddr_in6 sin;
    socklen_t len = sizeof(sin);
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_port = htons(ftps_obj->port);
    if (inet_pton(AF_INET6, ftps_obj->remote_ip, &sin.sin6_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {
        PRINT_ERR_HEAD;
        print_err("setsockopt failed:%s", strerror(errno));
        close(fd);
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }

    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(fd);
        return -1;
    }
    ftps_obj->cmd_fd = fd;

    if (ftps_read_resp_fd(ftps_obj, '2') == -1) {                                    //等待连接成功消息
        close(fd);
        return -1;
    }

    if (ftps_send_cmd_fd(ftps_obj, "AUTH SSL\r\n", '2') == -1) {               //请求开启SSL连接
        close(fd);
        return -1;
    }

    ftps_obj->cmd_ssl = SSL_new(ftps_obj->ctx);
    if (ftps_obj->cmd_ssl == NULL) {
        PRINT_ERR_HEAD;
        print_err("create cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    } else {
        SSL_set_fd(ftps_obj->cmd_ssl, ftps_obj->cmd_fd);
    }

    if (SSL_connect(ftps_obj->cmd_ssl) == -1) {
        PRINT_ERR_HEAD;
        print_err("connect cmd ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
        close(fd);
        return -1;
    } else {
        X509 *cert;
        cert = SSL_get_peer_certificate(ftps_obj->cmd_ssl);
        if (cert == NULL) {
            PRINT_ERR_HEAD;
            print_err("get ssl crt failed:%s", ERR_error_string(ERR_get_error(), NULL));
            close(fd);
            return -1;
        } else {
            X509_free(cert);
        }
    }

    if (getsockname(ftps_obj->cmd_fd, (struct sockaddr *) &sin, &len) == -1) {
        PRINT_ERR_HEAD;
        print_err("get cmd fd info failed:%s", strerror(errno));
    } else {
        inet_ntop(AF_INET6, (struct sockaddr *) &sin.sin6_addr, ftps_obj->local_ip, FSYNC_IP_MAX_LEN);
        PRINT_DBG_HEAD;
        print_dbg("local remote_ip = %s", ftps_obj->local_ip);
    }

    return fd;
}

/**
 * 创建ftps命令连接
 * @param ftps_obj ftps对象
 * @return 成功 0 失败 -1
 */
int ftps_cmd_connect(ftps_handle_t *ftps_obj) {

    if (ftps_obj->cmd_ssl != NULL) {
        SSL_shutdown(ftps_obj->cmd_ssl);
        SSL_free(ftps_obj->cmd_ssl);
        ftps_obj->cmd_ssl = NULL;
    }
    if (ftps_obj->cmd_fd > 0) {
        close(ftps_obj->cmd_fd);
    }

    if (ftps_obj->ip_type == FSYNC_IPV4) {
        ftps_obj->cmd_fd = ftps_cmd_connect_ipv4_implicit(ftps_obj);
        if (ftps_obj->cmd_fd < 0) {
            ftps_obj->cmd_fd = ftps_cmd_connect_ipv4_explicit(ftps_obj);
        }
    } else {
        ftps_obj->cmd_fd = ftps_cmd_connect_ipv6_implicit(ftps_obj);
        if (ftps_obj->cmd_fd < 0) {
            ftps_obj->cmd_fd = ftps_cmd_connect_ipv6_explicit(ftps_obj);
        }
    }

    if (ftps_obj->cmd_fd < 0) {
        PRINT_ERR_HEAD;
        print_err("cmd_connect cmd link failed ,fd = %d", ftps_obj->cmd_fd);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("cmd_connect cmd link success ,fd = %d", ftps_obj->cmd_fd);
    }

    return 0;
}


/**
 * ftps登录
 * @param ftps_obj ftps对象
 * @return 成工 0 失败 -1
 */
int ftps_login(ftps_handle_t *ftps_obj) {

    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    if (((strlen(ftps_obj->user) + 7) > sizeof(cmd)) || ((strlen(ftps_obj->password) + 7) > sizeof(cmd))) {
        PRINT_ERR_HEAD;
        print_err("user name or pass is too long !");
        return -1;
    }

    sprintf(cmd, "USER %s\r\n", ftps_obj->user);
    ret = ftps_send_cmd_ssl(ftps_obj, cmd, '3');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send USER info failed");
        return -1;
    }

    sprintf(cmd, "PASS %s\r\n", ftps_obj->password);
    ret = ftps_send_cmd_ssl(ftps_obj, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send PASS info failed");
        return -1;
    }

    sprintf(cmd, "PBSZ 0\r\n");
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return -1;
    }

    sprintf(cmd, "PROT P\r\n");
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return -1;
    }
    ret = ftps_send_cmd_ssl(ftps_obj, "SYST\r\n", '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send SYST info failed");
    } else {
        if (strcasestr(ftps_obj->resp_buf, "UNIX") == NULL) {
            ftps_obj->is_windows = true;
            PRINT_DBG_HEAD;
            print_dbg("System type is windows");
        } else {
            ftps_obj->is_windows = false;
            PRINT_DBG_HEAD;
            print_dbg("System type is UNIX");
        }
    }

    return 0;

}

bool ftps_connect_server(void *handle) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;

    if (ftps_cmd_connect(ftps_handle) != 0) {
        return false;
    }

    if (ftps_login(ftps_handle) != 0) {
        return false;
    }

    return true;
}

bool ftps_check_scan_path(void *handle) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    if ((strcmp(ftps_handle->scan_path, "./") == 0) || (strcmp(ftps_handle->scan_path, "/") == 0)) {
        return true;
    }
    if (ftps_check_access(handle, ftps_handle->scan_path)) {
        return true;
    } else {
        return false;
    }

}

bool ftps_check_server_connect(void *handle) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "TYPE I\r\n");
    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("check server = %s connect failed", ftps_handle->remote_ip);
        return false;
    } else {
        return true;
    }
}

/**
 * ftps获取当前路径
 * @param ftps_obj ftps对象
 * @param path 路径缓冲区
 * @param buf_len 缓冲区长度
 * @return 成功 0 失败 -1
 */
int ftps_pwd(ftps_handle_t *ftps_obj, char *path, int buf_len) {

    int ret = 0;
    int len = buf_len;
    char *tmp_path = path;
    char *head;

    ret = ftps_send_cmd_ssl(ftps_obj, "PWD\r\n", '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send cmd = PWD failed !");
        return -1;
    }
    head = strchr(ftps_obj->resp_buf, '"');
    if (head == NULL) {
        PRINT_ERR_HEAD;
        print_err("can not get pwd failed !");
        return -1;
    }
    head++;
    while ((--len) && (*head) && (*head != '"')) {
        *tmp_path++ = *head++;
    }
    *tmp_path++ = '\0';
    return 0;
}

/**
 * ftps判断文件、目录是否存在
 * @param ftps_obj ftps对象
 * @param path 路径
 * @return 成功/存在 0 失败/不存在 -1
 */
bool ftps_check_access(void *handle, const char *path_name) {

    if ((strcmp(path_name, ".") == 0) || (strcmp(path_name, "..") == 0) || (strcmp(path_name, "./") == 0) ||
        (strcmp(path_name, "/") == 0)) {
        return true;
    }

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    bool bret = true;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "RNFR %s\r\n", path_name);

    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '3');
    if (ret == -1) {
        PRINT_DBG_HEAD;
        print_dbg("path/file = %s not existed", path_name);
        bret = false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("path/file = %s existed", path_name);
    }


    return bret;
}

/**
 * ftps获取文件大小
 * @param ftps_obj ftps对象
 * @param path 路径
 * @return 成功 文件大小 失败 -1
 */
long ftps_get_size(void *handle, const char *path_name) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    long size = 0;
    int resp = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "TYPE I\r\n");
    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return -1;
    }

    sprintf(cmd, "SIZE %s\r\n", path_name);
    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_DBG_HEAD;
        print_dbg("send %s failed:%s", cmd, ftps_handle->resp_buf);
        return -1;
    } else {
        if (sscanf(ftps_handle->resp_buf, "%d %ld", &resp, &size) == 2) {
            PRINT_DBG_HEAD;
            print_dbg("file = %s size = %lu", path_name, size);
        } else {
            PRINT_ERR_HEAD;
            print_err("read file = %s size failed !", path_name);
            return -1;
        }
    }

    return size;
}

/**
 * ftps获取文件最后修改时间
 * @param ftps_obj ftps对象
 * @param path 文件路径
 * @return 成功 文件时间 失败 0
 */
time_t ftps_modify(ftps_handle_t *ftps_obj, const char *path) {

    if ((strcmp(path, ".") == 0) || (strcmp(path, "..") == 0) || (strcmp(path, "./") == 0) ||
        (strcmp(path, "/") == 0)) {
        return 0;
    }

    int ret = 0;
    int num = 0;
    char time[FSYNC_NAME_MAX_LEN] = {0};
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    if ((strlen(path) + 7) > sizeof(cmd)) {
        PRINT_ERR_HEAD;
        print_err("path is too long");
        return 0;
    }

    sprintf(cmd, "MDTM %s\r\n", path);
    ret = ftps_send_cmd_ssl(ftps_obj, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return 0;
    }

    sscanf(ftps_obj->resp_buf, "%d %s", &num, time);
    char *p = strstr(time, "\r\n");
    if (p != NULL) {
        *p = '\0';
    }

    int year, month, day, hour, minute, second;
    sscanf(time, "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &minute, &second);

    struct tm sec_time;
    memset(&sec_time, 0, sizeof(sec_time));
    sec_time.tm_year = year - 1900;
    sec_time.tm_mon = month - 1;
    sec_time.tm_mday = day;
    sec_time.tm_hour = hour;
    sec_time.tm_min = minute;
    sec_time.tm_sec = second;

    return mktime(&sec_time);
}

/**
 * ftps创建目录
 * @param ftps_obj ftps对象
 * @param path 路径
 * @return 成功 0 失败 -1
 */
int ftps_mkdir(void *handle, const char *dir_path) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "MKD %s\r\n", dir_path);

    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("mkdir = %s failed:%s", dir_path, ftps_handle->resp_buf);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("mkdir = %s success", dir_path);
        return 0;
    }

}

int ftps_mkdir_r(void *handle, const char *dir_path) {

    int ret = 0;
    int i = 0;
    if (ftps_check_access(handle, dir_path)) {
        return 0;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    while (1) {
        i++;
        if (dir_path[i] == '\0') {
            strncpy(dir_bak, dir_path, i);
            if (!ftps_check_access(handle, dir_bak)) {
                ftps_mkdir(handle, dir_bak);
            }
            break;
        } else if (dir_path[i] == '/') {
            strncpy(dir_bak, dir_path, i);
            if (!ftps_check_access(handle, dir_bak)) {
                ftps_mkdir(handle, dir_bak);
            }
        }
    }


    if (ftps_check_access(handle, dir_path)) {
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

/**
 * ftps删除目录
 * @param ftps_obj ftps对象
 * @param path 路径
 * @return 成功 0 失败 -1
 */
int ftps_rmdir(void *handle, const char *path) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "RMD %s\r\n", path);

    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("rmdir = %s failed", path);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("rmdir = %s success", path);
        return 0;
    }
}

bool ftps_rmdir_r(void *handle, const char *path_name) {

    bool bret = true;
    if (!ftps_check_access(handle, path_name)) {
        return true;
    }

    for (int i = 0; i < 3; i++) {
        if (ftps_rmdir(handle, path_name) == 0) {
            break;
        } else {
            usleep(10000);
        }
    }

    if (ftps_check_access(handle, path_name)) {
        bret = false;
    } else {
        bret = true;
    }

    return bret;
}

/**
 * ftps重命名
 * @param ftps_obj ftps对象
 * @param src_path 源路径
 * @param dst_path 目的路径
 * @return 成功 0 失败 -1
 */
bool ftps_rename(void *handle, const char *old_name, const char *new_name) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;

    if (ftps_check_access(handle, new_name)) {
        ftps_remove(handle, new_name);
    }

    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "RNFR %s\r\n", old_name);
    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '3');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("rename %s to %s failed:%s", old_name, new_name, ftps_handle->resp_buf);
        return false;
    }

    sprintf(cmd, "RNTO %s\r\n", new_name);
    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("rename %s to = %s failed:%s", old_name, new_name, ftps_handle->resp_buf);
        return false;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("move %s to %s success !", old_name, new_name);
    }
    return true;
}

/**
 * ftps删除
 * @param ftps_obj ftps对象
 * @param path 路径
 * @return 成功 0 失败 -1
 */
int ftps_remove(void *handle, const char *path_name) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "DELE %s\r\n", path_name);

    ret = ftps_send_cmd_ssl(ftps_handle, cmd, '2');
    if (ret == -1) {
        PRINT_ERR_HEAD;
        print_err("delete = %s failed:%s", path_name, ftps_handle->resp_buf);
        return -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("delete = %s success", path_name);
        return 0;
    }
}

/**
 * ftps创建ipv4被动模式数据连接
 * @param ftps_obj ftps对象
 * @param action_cmd 读/写命令
 * @param is_read_connect 是否为读连接
 * @return 成功 fd 失败 -1
 */
int ftps_data_connect_ipv4_pasv(ftps_handle_t *ftps_obj, const char *action_cmd, bool is_read_connect) {

    char data_ip[FSYNC_NAME_MAX_LEN] = {0};
    const char *tmp_head = NULL;
    int ftps_ip[4] = {0};
    int port = 0;
    int ftps_port[2] = {0};
    struct linger lng = {1, 5};
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "PASV\r\n");                                                            //被动模式
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return -1;
    }

    tmp_head = strchr(ftps_obj->resp_buf, '(');                                               //寻找服务器回复的IP端口
    if (tmp_head == NULL) {
        PRINT_ERR_HEAD;
        print_err("can not find char '(' ,buf = %s", ftps_obj->resp_buf);
        return -1;
    }
    sscanf(tmp_head, "(%d,%d,%d,%d,%d,%d)", &ftps_ip[0], &ftps_ip[1], &ftps_ip[2], &ftps_ip[3], &ftps_port[0],
           &ftps_port[1]);

    strcpy(data_ip, ftps_obj->remote_ip);
    port = ftps_port[0] * 256 + ftps_port[1];
    PRINT_DBG_HEAD;
    print_dbg("recv = %s ,remote_ip = %s,port = %d", ftps_obj->resp_buf, data_ip, port);

    struct sockaddr_in sin;
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, data_ip, &sin.sin_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    ftps_obj->data_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ftps_obj->data_fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {  //关闭端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_REUSEADDR failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;

    }
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_LINGER, (void *) &lng, sizeof(lng)) == -1) {   //延时关闭待数据发送完成
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_LINGER failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) { //设置超时
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }

    if ((connect(ftps_obj->data_fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)) {                        //连接数据端口
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;
    }

    if (is_read_connect) {
        //设置读超时
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;
            print_err("set read time out failed:%s", strerror(errno));
            return -1;
        }
    }

    if (ftps_send_cmd_ssl(ftps_obj, action_cmd, '1') == -1) {                            //发送读/写命令
        close(ftps_obj->data_fd);
        PRINT_ERR_HEAD;
        print_err("send %s failed:%s", action_cmd, ftps_obj->resp_buf);
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("create ftps(pasv) data cmd_connect success,fd = %d", ftps_obj->data_fd);

    return ftps_obj->data_fd;

}

/**
 * ftps创建ipv4主动模式数据连接
 * @param ftps_obj ftps对象
 * @param action_cmd 读/写命令
 * @param is_read_connect 是否为读连接
 * @return 成功 fd 失败 -1
 */
int ftps_data_connect_ipv4_port(ftps_handle_t *ftps_obj, const char *action_cmd, bool is_read_connect) {

    int ip[4] = {0};
    int port[2] = {0};
    int local_port = 0;
    int lfd = 0;
    int on = 1;
    struct sockaddr_in cli;
    struct sockaddr_in srv;
    struct linger lng = {1, 5};
    socklen_t srv_len = sizeof(srv);
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    memset(&srv, 0, sizeof(srv));
    memset(&cli, 0, sizeof(cli));

    lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    srv.sin_family = AF_INET;
    inet_pton(AF_INET, ftps_obj->local_ip, &srv.sin_addr);
    srv.sin_port = htons(0);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {  //关闭端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_REUSEADDR failed:%s", strerror(errno));
        close(lfd);
        return -1;

    }
    if (setsockopt(lfd, SOL_SOCKET, SO_LINGER, (void *) &lng, sizeof(lng)) == -1) {   //延时关闭待数据发送完成
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_LINGER failed:%s", strerror(errno));
        close(lfd);
        return -1;
    }

    if (bind(lfd, (struct sockaddr *) &srv, sizeof(srv)) == -1) {                     //绑定IP端口
        PRINT_ERR_HEAD;
        print_err("bind data fd = %d failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }

    if (listen(lfd, 1) == -1) {                                                    //监听本地任意端口,队列长度1
        PRINT_ERR_HEAD;
        print_err("listen fd = %d failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }

    if (getsockname(lfd, (struct sockaddr *) &srv, &srv_len) < 0) {                   //获取监听fd信息
        PRINT_ERR_HEAD;
        print_err("get fd = %d sock name failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    } else {
        local_port = ntohs(srv.sin_port);                                             //获取本地监听端口
    }

    sscanf(ftps_obj->local_ip, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
    port[0] = local_port / 256;
    port[1] = local_port % 256;
    sprintf(cmd, "PORT %d,%d,%d,%d,%d,%d\r\n", ip[0], ip[1], ip[2], ip[3], port[0], port[1]);
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {                       //告知服务器本地IP及端口
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        close(lfd);
        return -1;
    }

    if (ftps_send_cmd_ssl(ftps_obj, action_cmd, '1') == -1) {                //向服务器发送读/写命令
        PRINT_ERR_HEAD;
        print_err("send %s failed", action_cmd);
        close(lfd);
        return -1;
    }

    int flags = fcntl(lfd, F_GETFL, 0);
    if (fcntl(lfd, F_SETFL, flags | O_NONBLOCK) < 0) {                                //设置非阻塞
        PRINT_ERR_HEAD;
        print_err("set lfd = %d error:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        if ((ftps_obj->data_fd = accept(lfd, NULL, 0)) == -1) {          //等待建立连接
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            } else if (i == 2) {
                close(lfd);
                PRINT_ERR_HEAD;
                print_err("lfd = %d ,accept failed:%s", lfd, strerror(errno));
                return -1;
            }
        } else {
            close(lfd);
            PRINT_DBG_HEAD;
            print_dbg("data fd = %d,accept success", ftps_obj->data_fd);
            break;
        }
    }

    if (ftps_obj->data_fd == -1) {
        close(lfd);
        PRINT_ERR_HEAD;
        print_err("lfd = %d ,accept failed:%s", lfd, strerror(errno));
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (is_read_connect) {                                                          //设置读超时
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;
            print_err("set read time out failed:%s", strerror(errno));
            return -1;
        }
    } else {
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;                                                         //设置写超时
            print_err("set write time out failed:%s", strerror(errno));
            return -1;
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("create ftps(port) data cmd_connect success ,data fd = %d,data port = %d", ftps_obj->data_fd, local_port);
    return ftps_obj->data_fd;
}

/**
 * ftps创建ipv6被动模式数据连接
 * @param ftps_obj ftps对象
 * @param action_cmd 读/写命令
 * @param is_read_connect 是否为读连接
 * @return 成功 fd 失败 -1
 */
int ftps_data_connect_ipv6_epsv(ftps_handle_t *ftps_obj, const char *action_cmd, bool is_read_connect) {

    const char *tmp_head = NULL;
    int port = 0;
    struct linger lng = {0, 0};
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "EPSV 2\r\n");                                                            //被动模式
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        return -1;
    }

    tmp_head = strchr(ftps_obj->resp_buf, '(');                                               //寻找服务器回复的IP端口
    if (tmp_head == NULL) {
        PRINT_ERR_HEAD;
        print_err("can not find char '(' ,buf = %s", ftps_obj->resp_buf);
        return -1;
    }
    sscanf(tmp_head, "(|||%d|)", &port);

    PRINT_DBG_HEAD;
    print_dbg("recv = %s ,remote_ip = %s,port = %d", ftps_obj->resp_buf, ftps_obj->remote_ip, port);

    struct sockaddr_in6 sin;
    int on = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ftps_obj->remote_ip, &sin.sin6_addr) != 1) {
        PRINT_ERR_HEAD;
        print_err("inet_pton failed:%s", strerror(errno));
        return -1;
    }

    ftps_obj->data_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (ftps_obj->data_fd == -1) {
        PRINT_ERR_HEAD;
        print_err("create socket failed:%s", strerror(errno));
        return -1;
    }
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {  //关闭端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_REUSEADDR failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;

    }
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_LINGER, (void *) &lng, sizeof(lng)) == -1) {   //延时关闭待数据发送完成
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_LINGER failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) { //设置超时
        PRINT_ERR_HEAD;
        print_err("set time out failed:%s", strerror(errno));
        return -1;
    }

    if ((connect(ftps_obj->data_fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)) {                        //连接数据端口
        PRINT_ERR_HEAD;
        print_err("cmd_connect failed:%s", strerror(errno));
        close(ftps_obj->data_fd);
        return -1;
    }

    if (is_read_connect) {
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) <
            0) {//设置读超时
            PRINT_ERR_HEAD;
            print_err("set read time out failed:%s", strerror(errno));
            return -1;
        }
    }

    if (ftps_send_cmd_ssl(ftps_obj, action_cmd, '1') == -1) {                            //发送读/写命令
        close(ftps_obj->data_fd);
        PRINT_ERR_HEAD;
        print_err("send %s failed", action_cmd);
        return -1;
    }


    PRINT_DBG_HEAD;
    print_dbg("create ftps(pasv) data cmd_connect success,fd = %d", ftps_obj->data_fd);

    return ftps_obj->data_fd;

}

/**
 * ftps创建ipv6主动模式数据连接
 * @param ftps_obj ftps对象
 * @param action_cmd 读/写命令
 * @param is_read_connect 是否为读连接
 * @return 成功 fd 失败 -1
 */
int ftps_data_connect_ipv6_eprt(ftps_handle_t *ftps_obj, const char *action_cmd, bool is_read_connect) {

    int local_port = 0;
    int lfd = 0;
    int on = 1;
    struct sockaddr_in6 cli;
    struct sockaddr_in6 srv;
    struct linger lng = {0, 0};
    socklen_t srv_len = sizeof(srv);
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    memset(&srv, 0, sizeof(srv));
    memset(&cli, 0, sizeof(cli));

    lfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    srv.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ftps_obj->local_ip, &srv.sin6_addr);
    srv.sin6_port = htons(0);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) == -1) {   //关闭端口立即复用
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_REUSEADDR failed:%s", strerror(errno));
        close(lfd);
        return -1;

    }
    if (setsockopt(lfd, SOL_SOCKET, SO_LINGER, (void *) &lng, sizeof(lng)) == -1) {    //延时关闭待数据发送完成
        PRINT_ERR_HEAD;
        print_err("setsockopt SO_LINGER failed:%s", strerror(errno));
        close(lfd);
        return -1;
    }

    if (bind(lfd, (struct sockaddr *) &srv, sizeof(srv)) == -1) {                      //绑定IP端口
        PRINT_ERR_HEAD;
        print_err("bind data fd = %d failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }

    if (listen(lfd, 1) == -1) {                                                     //监听本地任意端口,队列长度1
        PRINT_ERR_HEAD;
        print_err("listen fd = %d failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }
    if (getsockname(lfd, (struct sockaddr *) &srv, &srv_len) < 0) {                    //获取监听fd信息
        PRINT_ERR_HEAD;
        print_err("get fd = %d sock name failed:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    } else {
        local_port = ntohs(srv.sin6_port);                                              //获取本地监听端口
    }

    sprintf(cmd, "EPRT |2|%s|%d|\r\n", ftps_obj->local_ip, local_port);
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {                         //告知服务器本地IP及端口
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
        close(lfd);
        return -1;
    }

    if (ftps_send_cmd_ssl(ftps_obj, action_cmd, '1') == -1) {                 //向服务器发送读/写命令
        PRINT_ERR_HEAD;
        print_err("send %s failed", action_cmd);
        close(lfd);
        return -1;
    }


    int flags = fcntl(lfd, F_GETFL, 0);
    if (fcntl(lfd, F_SETFL, flags | O_NONBLOCK) < 0) {                                //设置非阻塞
        PRINT_ERR_HEAD;
        print_err("set lfd = %d error:%s", lfd, strerror(errno));
        close(lfd);
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        if ((ftps_obj->data_fd = accept(lfd, NULL, 0)) == -1) {         //等待建立连接
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            } else if (i == 2) {
                close(lfd);
                PRINT_ERR_HEAD;
                print_err("lfd = %d ,accept failed:%s", lfd, strerror(errno));
                return -1;
            }
        } else {
            close(lfd);
            PRINT_DBG_HEAD;
            print_dbg("data fd = %d,accept success", ftps_obj->data_fd);
            break;
        }
    }

    if (ftps_obj->data_fd == -1) {
        close(lfd);
        PRINT_ERR_HEAD;
        print_err("lfd = %d ,accept failed:%s", lfd, strerror(errno));
        return -1;
    }

    struct timeval time_out = {FSYNC_CONNECT_TIME_OUT, 0};
    if (is_read_connect) {                                                          //设置读超时
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;
            print_err("set read time out failed:%s", strerror(errno));
            return -1;
        }
    } else {
        if (setsockopt(ftps_obj->data_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &time_out, sizeof(time_out)) < 0) {
            PRINT_ERR_HEAD;                                                         //设置写超时
            print_err("set write time out failed:%s", strerror(errno));
            return -1;
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("create ftps(port) data cmd_connect success ,data fd = %d,data port = %d", ftps_obj->data_fd, local_port);
    return ftps_obj->data_fd;
}

/**
 * ftps创建数据连接
 * @param ftps_obj ftps对象
 * @param action_cmd 读/写命令
 * @param is_read_connect 是否为数据连接
 * @return 成功 0 失败 -1
 */
int ftps_data_connect(ftps_handle_t *ftps_obj, const char *action_cmd, bool is_read_connect, bool is_binary) {

    char buf[FSYNC_CMD_MAX_LEN] = {0};
    if (is_binary) {
        sprintf(buf, "TYPE I\r\n");
    } else {
        sprintf(buf, "TYPE A\r\n");
    }

    if (ftps_send_cmd_ssl(ftps_obj, buf, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", buf);
        return -1;
    }

    if (ftps_obj->ip_type == FSYNC_IPV4) {
        ftps_obj->data_fd = ftps_data_connect_ipv4_pasv(ftps_obj, action_cmd, is_read_connect);
        /*if (ftps_obj->data_fd < 0) {
            ftps_obj->data_fd = ftps_data_connect_ipv4_port(ftps_obj, action_cmd, is_read_connect);
        }*/
    } else {
        ftps_obj->data_fd = ftps_data_connect_ipv6_epsv(ftps_obj, action_cmd, is_read_connect);
        /*if (ftps_obj->data_fd < 0) {
            ftps_obj->data_fd = ftps_data_connect_ipv6_eprt(ftps_obj, action_cmd, is_read_connect);
        }*/
    }

    if (ftps_obj->data_fd >= 0) {
        ftps_obj->data_ssl = SSL_new(ftps_obj->ctx);
        SSL_set_fd(ftps_obj->data_ssl, ftps_obj->data_fd);
        SSL_SESSION *se = SSL_get_session(ftps_obj->cmd_ssl);
        SSL_set_session(ftps_obj->data_ssl, se);
        if (SSL_connect(ftps_obj->data_ssl) == -1) {
            PRINT_ERR_HEAD;
            print_err("connect data ssl failed:%s", ERR_error_string(ERR_get_error(), NULL));
            SSL_free(ftps_obj->data_ssl);
            ftps_obj->data_ssl = NULL;
            close(ftps_obj->data_fd);
            return -1;
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("create ftps data connect failed !");
        return -1;
    }


    return 0;
}

/**
 * ftps打开文件
 * @param ftps_obj ftps对象
 * @param path 文件路径
 * @param mod 'r'读 'w'写
 * @return 成功 fd 失败 -1
 */
bool ftps_open_source_file(void *handle, const char *source_file) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    for (int i = 0; i < 3; ++i) {
        sprintf(cmd, "RETR %s\r\n", source_file);
        ret = ftps_data_connect(ftps_handle, cmd, true, true);

        if (ret < 0) {
            PRINT_ERR_HEAD;
            print_err("open path = %s failed !", source_file);
            usleep(100000);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("open path = %s success", source_file);
            break;
        }
    }
    return ret < 0 ? false : true;
}

bool ftps_open_target_file(void *handle, const char *target_file) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int ret = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    char file_dir[FSYNC_PATH_MAX_LEN] = {0};

    strcpy(file_dir, target_file);
    dirname(file_dir);
    sprintf(cmd, "STOR %s\r\n", target_file);
    ftps_mkdir_r(handle, file_dir);

    for (int i = 0; i < 3; i++) {
        ret = ftps_data_connect(ftps_handle, cmd, false, true);

        if (ret < 0) {
            PRINT_ERR_HEAD;
            print_err("open path = %s failed", target_file);
            usleep(100000);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("open path = %s success", target_file);
            break;
        }
    }

    return ret < 0 ? false : true;

}

/**
 * ftps读数据
 * @param ftps_obj ftps对象
 * @param tmp_queue 缓存队列
 * @return 读取的字节数
 */
int ftps_read(void *handle, void *buf, unsigned int buf_len) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int read_len = 0;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        read_len = SSL_read(ftps_handle->data_ssl, buf, buf_len);
        if (read_len < 0) {
            if (SSL_get_error(ftps_handle->data_ssl, read_len) == SSL_ERROR_WANT_READ) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("read failed:%s", ERR_error_string(ERR_get_error(), NULL));
                break;
            }
        } else {
            break;
        }
    }

    return read_len;
}

/**
 * ftps写数据
 * @param ftps_obj ftps对象
 * @param tmp_queue 缓存队列
 * @return 写入的字节数
 */
int ftps_write(void *handle, void *buf, unsigned int data_len) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    int write_len = 0;

    for (int i = 0; i < FSYNC_RW_TRY_TIMES; i++) {
        write_len = SSL_write(ftps_handle->data_ssl, buf, data_len);
        if (write_len < 0) {
            if (SSL_get_error(ftps_handle->data_ssl, write_len) == SSL_ERROR_WANT_WRITE) {
                usleep(1000);
                continue;
            } else {
                PRINT_ERR_HEAD;
                print_err("write failed:%s", ERR_error_string(ERR_get_error(), NULL));
                break;
            }
        } else {
            break;
        }
    }

    return write_len;
}

/**
 * ftps关闭数据连接fd
 * @param ftps_obj ftps对象
 */
void ftps_close_data_handle(void *handle) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;

    if (ftps_handle->data_ssl != NULL) {
        SSL_shutdown(ftps_handle->data_ssl);
        SSL_free(ftps_handle->data_ssl);
        ftps_handle->data_ssl = NULL;
    }
    shutdown(ftps_handle->data_fd, SHUT_RDWR);
    close(ftps_handle->data_fd);
    ftps_handle->data_fd = -1;

    ftps_read_resp_ssl(ftps_handle, '2');

    return;
}

/**
 * ftps退出登录
 * @param ftps_obj ftps对象
 * @return 成功 0 失败 -1
 */
int ftps_quit(ftps_handle_t *ftps_obj) {

    char cmd[FSYNC_CMD_MAX_LEN] = {0};
    sprintf(cmd, "QUIT\r\n");
    if (ftps_send_cmd_ssl(ftps_obj, cmd, '2') == -1) {
        PRINT_ERR_HEAD;
        print_err("send %s failed", cmd);
    }
    close(ftps_obj->cmd_fd);
    ftps_obj->cmd_fd = -1;
    PRINT_DBG_HEAD;
    print_dbg("quit success");
    return 0;

}

void ftps_disconnect(void *handle) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    ftps_quit(ftps_handle);
    if (ftps_handle->cmd_ssl != NULL) {
        SSL_shutdown(ftps_handle->cmd_ssl);
        SSL_free(ftps_handle->cmd_ssl);
        ftps_handle->cmd_ssl = NULL;
    }
}

/**
 * 获取文件基本信息
 * @param ftps_obj ftps对象
 * @param file_info 文件信息结构体(结构体中需有路径)
 * @return
 */
int ftps_get_stat(void *handle, const char *path_name, struct stat *file_stat) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;

    if (!ftps_check_access(handle, path_name)) {
        PRINT_ERR_HEAD;
        print_err("get file = %s info failed:%s", path_name, ftps_handle->resp_buf);
        return -1;
    }

    if (ftps_get_size(ftps_handle, path_name) == -1) {
        file_stat->st_mode = FSYNC_IS_DIR;
        file_stat->st_size = 0;
        file_stat->st_mtime = FSYNC_DIR_DEFAULT_TIME;
    } else {
        file_stat->st_mode = FSYNC_IS_FILE;
        file_stat->st_size = ftps_get_size(ftps_handle, path_name);
        file_stat->st_mtime = ftps_modify(ftps_handle, path_name);
    }

    return 0;
}

/**
 * 路径解析
 * @param parent_path 父目录
 * @param buf 路径报文缓冲区
 * @param path_list 路径列表(返回值)
 * @return 成功 0 失败 -1
 */
int ftps_parse_path_windows(const char *parent_path, char *buf, GList **path_list) {

    char *p = buf;
    char *key_point;
    while ((key_point = strsep(&p, "\r\n")) != NULL) {    //关键字为空格
        if (*key_point == 0) {
            continue;
        } else {
            char file_date[FSYNC_NAME_MAX_LEN] = {0};
            char file_time[FSYNC_NAME_MAX_LEN] = {0};
            char file_size[FSYNC_NAME_MAX_LEN] = {0};
            char file_name[FSYNC_NAME_MAX_LEN] = {0};
            //printf("key_point = %s\n", key_point);

            if (sscanf(key_point, "%s %s %s %255c", file_date, file_time, file_size, file_name) == 4) {
                PRINT_DBG_HEAD;
                print_dbg("file date= %s ,time = %s ,size = %s ,name = %s ", file_date, file_time, file_size,
                          file_name);
            } else {
                PRINT_ERR_HEAD;
                print_err("parse [%s] info failed !", key_point);
                continue;
            }

            if ((strcmp(".", basename(file_name)) == 0) || (strcmp("..", basename(file_name)) == 0)) {
                continue;
            }

            fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
            if (strchr(key_point, '/') != NULL) {
                strcpy(tmp_task->path, file_name);
            } else {
                if (parent_path[strlen(parent_path) - 1] == '/') {
                    sprintf(tmp_task->path, "%s%s", parent_path, file_name);
                } else {
                    sprintf(tmp_task->path, "%s/%s", parent_path, file_name);
                }
            }

            if (strspn(file_size, "0123456789") == strlen(file_size)) {
                tmp_task->type = FSYNC_IS_FILE;
                tmp_task->size = atol(file_size);
            } else {
                tmp_task->type = FSYNC_IS_DIR;
                tmp_task->size = 0;
            }

            //printf("path = %s\n", tmp_task->path);
            *path_list = g_list_prepend(*path_list, tmp_task);
        }
    }

    return 0;
}

/**
 * 路径解析
 * @param parent_path 父目录
 * @param buf 路径报文缓冲区
 * @param path_list 路径列表(返回值)
 * @return 成功 0 失败 -1
 */
int ftps_parse_path_unix(const char *parent_path, char *buf, GList **path_list) {

    char *p = buf;
    char *key_point;
    while ((key_point = strsep(&p, "\r\n")) != NULL) {    //关键字为空格
        if (*key_point == 0) {
            continue;
        } else {
            char file_type[FSYNC_NAME_MAX_LEN] = {0};
            int file_count = {0};
            char file_user[FSYNC_NAME_MAX_LEN] = {0};
            char file_group[FSYNC_NAME_MAX_LEN] = {0};
            off_t file_size = 0;
            char file_month[FSYNC_NAME_MAX_LEN] = {0};
            int file_day = 0;
            char file_minute[FSYNC_NAME_MAX_LEN] = {0};
            char file_name[FSYNC_NAME_MAX_LEN] = {0};
            //printf("key_point = %s\n", key_point);
            if (sscanf(key_point, "%s %d %s %s %lu %s %d %s %255c", file_type, &file_count, file_user, file_group,
                       &file_size, file_month, &file_day, file_minute, file_name) == 9) {
                PRINT_DBG_HEAD;
                print_dbg("file type = %s ,size = %lu ,name = %s", file_type, file_size, file_name);
            } else {
                PRINT_ERR_HEAD;
                print_err("parse [%s] info failed !", key_point);
                continue;
            }

            if ((strcmp(".", basename(file_name)) == 0) || (strcmp("..", basename(file_name)) == 0)) {
                continue;
            }

            fs_task_t *tmp_task = (fs_task_t *) calloc(1, sizeof(fs_task_t));
            if (strchr(key_point, '/') != NULL) {
                strcpy(tmp_task->path, file_name);
            } else {
                if (parent_path[strlen(parent_path) - 1] == '/') {
                    sprintf(tmp_task->path, "%s%s", parent_path, file_name);
                } else {
                    sprintf(tmp_task->path, "%s/%s", parent_path, file_name);
                }
            }

            if (file_type[0] != 'd') {
                tmp_task->type = FSYNC_IS_FILE;
                tmp_task->size = file_size;
            } else {
                tmp_task->type = FSYNC_IS_DIR;
                tmp_task->size = 0;
            }

            //printf("path = %s\n", tmp_task->path);
            *path_list = g_list_prepend(*path_list, tmp_task);
        }
    }

    return 0;
}

/**
 * ftps扫描目录
 * @param ftps_obj ftps对象
 * @param path 路径
 * @param path_queue 文件信息队列(文件信息结构中此时仅有路径)
 * @return
 */
int ftps_scan_dir(ftps_handle_t *ftps_obj, const char *path, GList **path_list) {

     long recv_len = 0;
    char cmd[FSYNC_CMD_MAX_LEN] = {0};

    sprintf(cmd, "LIST -a %s\r\n", path);
    if (ftps_data_connect(ftps_obj, cmd, true, false) == -1) {
        PRINT_ERR_HEAD;
        print_err("exec cmd = %s failed !", cmd);
        return -1;
    }

    unsigned int all_len = 10240;
    unsigned int off_set = 0;
    char *all_recv = (char *) calloc(1, all_len);
    while ((recv_len = ftps_read(ftps_obj, cmd, sizeof(cmd))) > 0) {
        if ((all_len - off_set) <= FSYNC_CMD_MAX_LEN) {
            char tmp_buf[FSYNC_CMD_MAX_LEN] = {0};
            char *p_end = NULL;
            p_end = strrchr(all_recv, '\n');
            if (p_end == NULL) {
                break;
            }
            p_end++;
            strcpy(tmp_buf, p_end);
            *p_end = '\0';
            if (ftps_obj->is_windows) {
                ftps_parse_path_windows(path, all_recv, path_list);
            } else {
                ftps_parse_path_unix(path, all_recv, path_list);
            }
            memset(all_recv, 0, all_len);
            strcpy(all_recv, tmp_buf);
            off_set = strlen(all_recv);
        }
        memcpy(all_recv + off_set, cmd, recv_len);
        off_set += recv_len;
    }

    if (off_set > 0) {
        all_recv[off_set] = '\0';
        if (ftps_obj->is_windows) {
            ftps_parse_path_windows(path, all_recv, path_list);
        } else {
            ftps_parse_path_unix(path, all_recv, path_list);
        }
    }
    free(all_recv);
    ftps_close_data_handle(ftps_obj);

    for (GList *p_elem = *path_list; p_elem != NULL; p_elem = p_elem->next) {
        fs_task_t *tmp_task = (fs_task_t *) (p_elem->data);
        if (tmp_task->type == FSYNC_IS_FILE) {
            tmp_task->modify = ftps_modify(ftps_obj, tmp_task->path);
        } else {
            tmp_task->modify = FSYNC_DIR_DEFAULT_TIME;
        }
    }

    return 0;
}


bool ftps_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                     GAsyncQueue *ready_queue, int delay_time) {

    ftps_handle_t *ftps_handle = (ftps_handle_t *) handle;
    bool bover = false;
    GList *tmp_list = NULL;
    char scan_dir[FSYNC_PATH_MAX_LEN] = {0};
    strcpy(scan_dir, dir_name);

    while (1) {
        ftps_scan_dir(ftps_handle, scan_dir, &tmp_list);

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
    print_dbg("ftps first scan over,dir = %d ,file = %d", g_list_length(*dir_list), g_list_length(*file_list));

    return true;
}

bool ftps_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue) {

    struct stat stat_buf;
    fs_task_t *tmp_task = NULL;
    for (GList *p_elem = *file_list; p_elem != NULL; p_elem = *file_list) {
        tmp_task = (fs_task_t *) (p_elem->data);
        memset(&stat_buf, 0, sizeof(stat_buf));
        if (ftps_get_stat(handle, tmp_task->path, &stat_buf) != 0) {         //文件不存在
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
    print_dbg("ftps second scan over ,file = %d", g_async_queue_length(ready_queue));

    return true;
}


