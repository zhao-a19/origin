
#ifndef __FTP_SYNC_H__
#define __FTP_SYNC_H__

#include "protocol_api.h"

typedef struct ftp_handle_t {
    int protocol;
    char user[FSYNC_NAME_MAX_LEN];
    char password[FSYNC_NAME_MAX_LEN];
    int ip_type;
    char remote_ip[FSYNC_IP_MAX_LEN];
    int port;
    bool is_windows;

    char scan_path[FSYNC_PATH_MAX_LEN];
    char local_ip[FSYNC_IP_MAX_LEN];
    int cmd_fd;
    char cmd_buf[FSYNC_CMD_MAX_LEN];
    char resp_buf[FSYNC_CMD_MAX_LEN];

    int data_fd;

} ftp_handle_t;

fs_work_t *create_ftp_worker(void);

int init_ftp_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info);

void destroy_ftp_worker_obj(fs_work_t *worker);

bool ftp_connect_server(void *handle);

bool ftp_check_server_connect(void *handle);

bool ftp_check_scan_path(void *handle);

bool ftp_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                    GAsyncQueue *ready_queue, int delay_time);


bool ftp_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue);

int ftp_get_stat(void *handle, const char *path_name, struct stat *file_stat);

long ftp_get_size(void *handle, const char *path_name);

int ftp_mkdir(void *handle, const char *dir_path);

int ftp_mkdir_r(void *handle, const char *dir_path);

bool ftp_check_access(void *handle, const char *path_name);

int ftp_remove(void *handle, const char *path_name);

bool ftp_rename(void *handle, const char *old_name, const char *new_name);

int ftp_rmdir(void *handle, const char *path_name);

bool ftp_rmdir_r(void *handle, const char *path_name);

bool ftp_open_source_file(void *handle, const char *source_file);

bool ftp_open_target_file(void *handle, const char *target_file);

int ftp_read(void *handle, void *buf, unsigned int buf_len);

int ftp_write(void *handle, void *buf, unsigned int data_len);

void ftp_disconnect(void *handle);

void ftp_close_data_handle(void *handle);

/*******************************************************************************************************************/


int ftp_cmd_connect(ftp_handle_t *ftp_obj);

int ftp_login(ftp_handle_t *ftp_obj);

int ftp_pwd(ftp_handle_t *ftp_obj, char *path, int buf_len);

time_t ftp_modify(ftp_handle_t *ftp_obj, const char *path);

int ftp_quit(ftp_handle_t *ftp_obj);


#endif //__FTP_SYNC_H__