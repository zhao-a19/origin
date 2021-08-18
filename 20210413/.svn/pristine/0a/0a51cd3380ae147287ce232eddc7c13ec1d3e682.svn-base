/*******************************************************************************************
*文件:  transfer.h
*描述:  TCP传输文件
*作者:  王君雷
*日期:  2020-03-07
*修改:
*******************************************************************************************/
#ifndef __TRANSFER_H__
#define __TRANSFER_H__

#define FILE_PATH_LEN 1024
#define TMP_AMTCP_SUFFIX_FILE ".amtcp_tmp" //临时文件后缀
#define RULES_FILE            "SYSRULES"
#define STOP_OUT_BUSINESS     "killall sys6_w webproxy snmpd sul2fwd nginx >/dev/null 2>&1 "
#define SU_FILE_FLAG          "su_file"


enum TRANSFER_MODE {
    TRANSFER_MODE_ASYNC = 0,//异步方式传输 默认
    TRANSFER_MODE_SYNC = 1, //同步方式传输
};

#define DEFAULT_MODE TRANSFER_MODE_ASYNC

#pragma pack(push, 1)
typedef struct transfer_head {
    char filename[FILE_PATH_LEN];
    char reserved[64];
    char checkflag[10];
    int fsize;
    int perm;
    int mode;
} TRANSFER_HEAD, *PTRANSFER_HEAD;
#pragma pack(pop)

#endif
