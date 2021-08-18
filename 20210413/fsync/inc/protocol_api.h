#ifndef __PROTOCOL_API_H__
#define __PROTOCOL_API_H__

#include <glib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include "debugout.h"

#define FSYNC_NFS_PROTOCOL     12   //01100
#define FSYNC_CIFS_PROTOCOL    10   //01010
#define FSYNC_SAMBA_TYPE       8    //01000
#define FSYNC_FILE_SYSTEM      24   //11000
#define FSYNC_FTP_TYPE         16   //10000
#define FSYNC_FTP_PROTOCOL     18   //10010
#define FSYNC_SFTP_PROTOCOL    20   //10100
#define FSYNC_FTPS_PROTOCOL    21   //10101

#define FSYNC_IS_DIR                   0
#define FSYNC_IS_FILE                  1
#define FSYNC_IPV4                     4
#define FSYNC_IPV6                     6
#define FSYNC_CONNECT_TIME_OUT         15
#define FSYNC_IP_MAX_LEN               64
#define FSYNC_NAME_MAX_LEN             512
#define FSYNC_PATH_MAX_LEN             1024
#define FSYNC_CMD_MAX_LEN              1024
#define FSYNC_LOGIN_TIME_OUT           6000
#define FSYNC_LIST_MAX_SIZE            1000
#define FSYNC_DIR_DEFAULT_TIME         1531702800

#define FSYNC_RW_TRY_TIMES             5


typedef struct fs_task_t {
    bool in_to_out;
    char path[FSYNC_PATH_MAX_LEN];
    off_t size;
    time_t modify;
    int type;
} fs_task_t;

typedef struct fs_server_t {
    int protocol;                                //协议            对应配置项:InFileSys/OutFileSys/InBackupFileSys/OutBackupFileSys
    char user[FSYNC_NAME_MAX_LEN];               //用户名          对应配置项:InUse/OutUser/InBackupUser/OutBackupUser
    char pwd[FSYNC_NAME_MAX_LEN];                //密码            对应配置项:InPWD/OutPWD/InBackupPWD/OutBackupPWD
    char real_ip[FSYNC_IP_MAX_LEN];              //真实主机IP
    char use_ip[FSYNC_IP_MAX_LEN];               //实际使用IP
    int port;                                    //端口            对应配置项:InPort/OutPort/InBackPort/OutBackPort
    char share_path[FSYNC_PATH_MAX_LEN];         //共享路径,选填:仅在cifs/nfs协议有效   对应配置项:InPath/OutPath/InBackupPath/OutBackupPath
    char sub_path[FSYNC_PATH_MAX_LEN];           //子路径           对应配置项: InSubPath/OutSubPath/InBackSubPath/OutBackSubPath

    char scan_path[FSYNC_PATH_MAX_LEN];          //扫描路径

    char mount_path[FSYNC_PATH_MAX_LEN];         //本地挂载路径      选填:仅在cifs/nfs协议有效

} fs_server_t;

typedef struct fs_work_t {
    void *handle;
    int protocol;

    int (*init_worker_obj)(fs_work_t *worker_obj, fs_server_t *srv_info);

    void (*destroy_worker_obj)(fs_work_t *worker);

    bool (*connect_server)(void *handle);

    bool (*check_server_connect)(void *handle);

    bool (*check_scan_path)(void *handle);

    bool (*first_scan)(void *handle, bool in_to_out, const char *dir_name, GList **dir_list, GList **file_list,
                       GAsyncQueue *ready_queue, int delay_time);


    bool (*second_scan)(void *handle, GList **file_list, GAsyncQueue *ready_queue);


    int (*get_stat)(void *handle, const char *path_name, struct stat *file_stat);

    int (*mkdir_r)(void *handle, const char *dir_path);

    bool (*check_access)(void *handle, const char *path_name);

    int (*remove)(void *handle, const char *path_name);

    bool (*rename)(void *handle, const char *old_name, const char *new_name);

    bool (*rmdir)(void *handle, const char *path_name);

    bool (*open_source_file)(void *handle, const char *source_file);

    bool (*open_target_file)(void *handle, const char *target_file);

    int (*read)(void *handle, void *buf, unsigned int buf_len);

    int (*write)(void *handle, void *buf, unsigned int buf_len);

    void (*disconnect)(void *handle);

    void (*close_data_handle)(void *handle);

} fs_work_t;

#endif //__PROTOCOL_API_H__