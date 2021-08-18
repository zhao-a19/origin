/*******************************************************************************************
*文件: authinfo.h
*描述: 授权文件信息相关
*作者: 王君雷
*日期: 2018-09-18
*修改:
*      管理口信息通过参数传递，不读取配置文件了                       ------> 2018-09-28
*      移动头文件中不需要暴露出去的信息                               ------> 2018-10-15
*      对于使用CST时区的系统 签发时间做偏移                           ------> 2019-01-17
*******************************************************************************************/
#ifndef __AUTH_INFO_H__
#define __AUTH_INFO_H__
#include "datatype.h"

#define AUTH_FOREVER -1
#define AUTH_DEFAULT -2
#define AUTH_DEFAULT_DAYS 90
#define SECONDS_PER_DAY (24 * 60 * 60)
#define AUTH_FILE_PATH1 "/etc/httpd/client.cf"
#define AUTH_FILE_PATH2 "/var/lib/tmcvd"

#pragma pack(push, 1)
typedef struct AUTH_HEAD {
    char head[8];
    int version;
} AUTH_HEAD, *PAUTH_HEAD;

typedef struct AUTH_BODY {
    char authid[40];             //授权文件ID
    char user[256];              //用户信息
    int authday;                 //授权天数
    unsigned char bindid[16];    //硬件绑定码

    int64 maketime;              //签发时间
    int64 starttime;             //开始时间
    int64 stoptime;              //结束时间
    int64 lastupdate;            //最后一次更新授权文件的时间
    unsigned char reserved[64];  //保留
    unsigned char md5buff16[16]; //对本结构体上述字段计算的md5
} AUTH_BODY, *PAUTH_BODY;
#pragma pack(pop)

bool import_syscer(const char *mancardname, const char *syscerpath);
bool read_authinfo(const char *syscerpath, AUTH_HEAD &authhead, AUTH_BODY &authbody);
bool check_auth(AUTH_HEAD &authhead, AUTH_BODY &authbody, const char *mancardname);
bool get_mybindid(const char *mancardname, unsigned char *bindid);
bool auth_tofile(AUTH_HEAD &head, AUTH_BODY &body, const char *file);
int cst_seconds_offset(void);
#define CST_CALIBRATE(t1) (t1 + cst_seconds_offset()) //CST时间校准

#endif
