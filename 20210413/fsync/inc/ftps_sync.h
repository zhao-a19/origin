
#ifndef __FTPS_SYNC_H__
#define __FTPS_SYNC_H__

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "protocol_api.h"

typedef struct ftps_handle_t {
    int protocol;
    char user[FSYNC_NAME_MAX_LEN];
    char password[FSYNC_NAME_MAX_LEN];
    int ip_type;
    char remote_ip[FSYNC_IP_MAX_LEN];
    int port;
    bool is_windows;

    SSL_CTX *ctx;
    SSL *cmd_ssl;
    int data_fd;
    SSL *data_ssl;

    char scan_path[FSYNC_PATH_MAX_LEN];
    char local_ip[FSYNC_IP_MAX_LEN];
    int cmd_fd;
    char cmd_buf[FSYNC_CMD_MAX_LEN];
    char resp_buf[FSYNC_CMD_MAX_LEN];

} ftps_handle_t;

fs_work_t *create_ftps_worker(void);

int init_ftps_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info);

void destroy_ftps_worker_obj(fs_work_t *worker);

bool ftps_connect_server(void *handle);

bool ftps_check_server_connect(void *handle);

bool ftps_check_scan_path(void *handle);

bool ftps_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                    GAsyncQueue *ready_queue, int delay_time);

bool ftps_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue);

int ftps_get_stat(void *handle, const char *path_name, struct stat *file_stat);

long ftps_get_size(void *handle, const char *path_name);

int ftps_mkdir(void *handle, const char *dir_path);

int ftps_mkdir_r(void *handle, const char *dir_path);

bool ftps_check_access(void *handle, const char *path_name);

int ftps_remove(void *handle, const char *path_name);

bool ftps_rename(void *handle, const char *old_name, const char *new_name);

int ftps_rmdir(void *handle, const char *path_name);

bool ftps_rmdir_r(void *handle, const char *path_name);

bool ftps_open_source_file(void *handle, const char *source_file);

bool ftps_open_target_file(void *handle, const char *target_file);

int ftps_read(void *handle, void *buf, unsigned int buf_len);

int ftps_write(void *handle, void *buf, unsigned int data_len);

void ftps_disconnect(void *handle);

void ftps_close_data_handle(void *handle);

/*******************************************************************************************************************/


int ftps_cmd_connect(ftps_handle_t *ftps_obj);

int ftps_login(ftps_handle_t *ftps_obj);

int ftps_pwd(ftps_handle_t *ftps_obj, char *path, int buf_len);

time_t ftps_modify(ftps_handle_t *ftps_obj, const char *path);

int ftps_quit(ftps_handle_t *ftps_obj);


#endif //__FTPS_SYNC_H__
