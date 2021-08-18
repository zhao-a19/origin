#include "global_define.h"
#include <curl.h>

#define CURL_DIR_DEFAULT_TIME           1531702800

#define SFTPLIB_BUFSIZ 81920
#define CURLSFTP_IPV6 6
#define CURLSFTP_IPV4 4

typedef struct curl_hanlde_t {
    int protocol;
    CURL *curl;

    char scan_path[FSYNC_PATH_MAX_LEN];
    char user[FSYNC_NAME_MAX_LEN];
    char password[FSYNC_NAME_MAX_LEN];
    int ip_type;
    char remote_ip[FSYNC_IP_MAX_LEN];
    int port;

}curl_handle_t;

typedef struct rw_info_t {
    int protocol;
    size_t size;
    fs_work_t *worker;
    GAsyncQueue *data_queue;
    char path[FSYNC_PATH_MAX_LEN];
} rw_info_t;

typedef struct rw_data_t {
    int len;
    char buf[FSYNC_BUF_MAX_LEN];
} rw_data_t;

size_t curl_sftp_read_cb(void *buf, size_t size, size_t count, void *arg_cb);

size_t curl_sftp_write_cb(void *buf, size_t size, size_t count, void *arg_cb);

fs_work_t *create_sftp_curl_worker(void);

int curl_sftp_init_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info);

bool curl_sftp_connect_server(void *handle);

bool curl_sftp_check_connect(void *handle);

bool curl_sftp_check_path(void *handle);

bool curl_sftp_check_access(void *handle, const char *path_name);

int curl_sftp_stat(void *handle, const char *path_name, struct stat *file_stat);

bool curl_sftp_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                     GAsyncQueue *ready_queue, int delay_time);

bool curl_sftp_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue);

int curl_sftp_mkdir_r(void *handle, const char *dir_path);

bool curl_sftp_rmdir(void *handle, const char *dir_path);

bool curl_sftp_rename(void *handle, const char *old_name, const char *new_name);

int curl_sftp_remove(void *handle, const char *path_name);

bool curl_sftp_open_source_file(void *handle, const char *source_file);

bool curl_sftp_open_target_file(void *handle, const char *target_file);

int curl_sftp_read(void *handle, void *buf, unsigned int buf_len);

int curl_sftp_write(void *handle, void *buf, unsigned int data_len);

void curl_sftp_disconnect(void *handle);

void curl_sftp_destroy_worker(fs_work_t *worker);

void curl_sftp_close_data_handle(void *handle);


