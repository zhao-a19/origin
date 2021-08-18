
#ifndef __SMB_SYNC_H_
#define __SMB_SYNC_H_

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/statvfs.h>
#include "protocol_api.h"

#define FSYNC_DIR_DEFAULT_MODE         0777

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
typedef struct smb_handle_t {
    int protocol;
    char user[FSYNC_NAME_MAX_LEN];
    char password[FSYNC_NAME_MAX_LEN];
    int ip_type;
    char remote_ip[FSYNC_IP_MAX_LEN];
    int port;

    char share_path[FSYNC_PATH_MAX_LEN];
    char scan_path[FSYNC_PATH_MAX_LEN];
    char local_path[FSYNC_PATH_MAX_LEN];
    int data_fd;
} smb_handle_t;


fs_work_t *create_smb_worker(void);

int init_smb_worker_obj(fs_work_t *worker_obj, fs_server_t *srv_info);

int smb_stat(void *handle, const char *path_name, struct stat *file_stat);

long smb_size(void *handle, const char *path_name);

int smb_remove(void *handle, const char *path_name);

bool smb_rename(void *handle, const char *old_name, const char *new_name);

bool smb_rmdir(void *handle, const char *path_name);

bool smb_rmdir_r(void *handle, const char *dir_name);

bool smb_access(void *handle, const char *path_name);

int smb_mkdir(void *handle, const char *dir_path);

bool smb_check_path(void *handle);

bool smb_check_mount_stat(void *handle);

bool smb_mount_server(void *handle);

bool mount_cifs(const char *source_ip, int port, const char *share_path, const char *local_path, const char *user,
                const char *password);

bool mount_nfs(const char *source_ip, int port, const char *share_path, const char *local_path);

bool smb_first_scan(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                    GAsyncQueue *ready_queue, int delay_time);

bool smb_second_scan(void *handle, GList **file_list, GAsyncQueue *ready_queue);


bool smb_open_source_file(void *handle, const char *source_file);

bool smb_open_target_file(void *handle, const char *target_file);

int smb_read(void *handle, void *buf, unsigned int buf_len);

int smb_write(void *handle, void *buf, unsigned int buf_len);

void smb_disconnect(void *handle);

void smb_close_data_handle(void *handle);

void destroy_smb_worker_obj(fs_work_t *worker);

#endif //__SMB_SYNC_H_

