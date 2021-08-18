#include "protocol_api.h"
#include <libssh2_sftp.h>

typedef struct sftp_hanlde_t {
    int protocol;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp_session;
    int sock;

    LIBSSH2_SFTP_HANDLE *data_session;

    char scan_path[FSYNC_PATH_MAX_LEN];
    char user[FSYNC_NAME_MAX_LEN];
    char password[FSYNC_NAME_MAX_LEN];
    int ip_type;
    char remote_ip[FSYNC_IP_MAX_LEN];
    int port;


}sftp_handle_t;

fs_work_t *create_sftp_worker(void);

int sftp_init_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info);

bool sftp_connect_server(void *handle);

bool sftp_check_connect(void *handle);

bool sftp_check_path(void *handle);

bool sftp_check_access(void *handle, const char *path_name);

int sftp_stat(void *handle, const char *path_name, struct stat *file_stat);

bool sftp_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                     GAsyncQueue *ready_queue, int delay_time);

bool sftp_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue);

int sftp_mkdir_r(void *handle, const char *dir_path);

int sftp_rmdir(void *handle, const char *dir_path);

bool sftp_rmdir_r(void *handle, const char *dir_path);

bool sftp_rename(void *handle, const char *old_name, const char *new_name);

int sftp_remove(void *handle, const char *path_name);

bool sftp_open_source_file(void *handle, const char *source_file);

bool sftp_open_target_file(void *handle, const char *target_file);

int sftp_read(void *handle, void *buf, unsigned int buf_len);

int sftp_write(void *handle, void *buf, unsigned int data_len);

void sftp_disconnect(void *handle);

void sftp_destroy_worker(fs_work_t *worker);

void sftp_close_data_handle(void *handle);

