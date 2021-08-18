/*******************************************************************************************
*文件:  FCSendRules.cpp
*描述:  发送规则接口函数
*作者:  王君雷
*日期:  2015
*
*修改:
*        组播配置文件宏改名为MULTICAST_CONF                      ------> 2018-02-05
*        在发送的规则文件中添加视频联动配置文件                  ------> 2018-04-11
*        在发送的规则文件中添加PDT互联配置文件                   ------> 2018-08-14
*        在发送的规则文件中添加私有协议文件同步配置文件          ------> 2018-08-30
*        在发送的规则文件中添加UTF8关键字文件                    ------> 2019-05-14
*        在发送的规则文件中添加平台互联配置文件                  ------> 2019-08-01 -dzj
*        在发送的规则文件中添加设备唯一码文件                    ------> 2020-02-05 -wjl
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include "FCSendRules.h"
#include "FCSendFileUdp.h"
#include "define.h"
#include "debugout.h"

//发送宏定义 flag为true 说明此文件发送不成功是严重错误
#define SEND_SU_FILE(file, flag, o) \
if (send_file_udp(file) < 0) { \
    PRINT_ERR_HEAD \
    print_err("send file fail[%s]", file); \
    if (flag){goto o;} \
}

/**
 * [file_tran_rule 传输策略相关文件]
 * @return  [成功返回0 失败返回负值]
 */
int file_tran_rule(void)
{
    PRINT_DBG_HEAD
    print_dbg("file tran rule begin");

    SEND_SU_FILE(KEY_CONF, true, _out);
    SEND_SU_FILE(SYSSET_CONF, true, _out);
    SEND_SU_FILE(DEV_CONF, true, _out);
    SEND_SU_FILE(BONDING_CONF, true, _out);
    SEND_SU_FILE(MULTICAST_CONF, true, _out);
    SEND_SU_FILE(SIP_CONF, true, _out);
    SEND_SU_FILE(FILESYNC_CONF, true, _out);
    SEND_SU_FILE(PRIV_FILESYNC_CONF, false, _out);
    SEND_SU_FILE(WEBPROXY_CONF, false, _out);
    SEND_SU_FILE(DBSYNC_CONF, false, _out);
    SEND_SU_FILE(LINK_SIP_CONF, false, _out);
    SEND_SU_FILE(PDT_CONF, false, _out);
    SEND_SU_FILE(KEYUTF8_CONF, false, _out);
    SEND_SU_FILE(SIP_INTER_CNT_CONF, false, _out);
    SEND_SU_FILE(SERIAL_CFG, false, _out);
    SEND_SU_FILE(RULE_CONF, true, _out); //SYSRULES一定要放在最后面

    PRINT_DBG_HEAD
    print_dbg("file tran rule success");
    return 0;
_out:
    return -1;
}

/**
 * [file_tran_auth 传输认证相关文件]
 * @return  [成功返回0 失败返回负值]
 */
int file_tran_auth(void)
{
    PRINT_DBG_HEAD
    print_dbg("file tran auth begin");

    DIR *dirptr = NULL;
    struct dirent *entry;
    char fname[MAX_FILE_PATH_LEN] = {0};

    if ((dirptr = opendir(SYS_AUTH_DIR)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", SYS_AUTH_DIR, strerror(errno));
        return -2;
    }

    SEND_SU_FILE(AUTHUSERCONF, true, _out);

    while ((entry = readdir(dirptr)) != NULL) {
        //包含TMP_SUFFIX_FILE的文件不传输
        if ((entry->d_name[0] != '.') && (strstr(entry->d_name, TMP_SUFFIX_FILE) == NULL)) {
            sprintf(fname, "%s%s", SYS_AUTH_DIR, entry->d_name);
            SEND_SU_FILE(fname, true, _out);
        }
    }

    closedir(dirptr);

    PRINT_DBG_HEAD
    print_dbg("file tran auth success");
    return 0;
_out:
    closedir(dirptr);
    return -1;
}

/**
 * [auth_tran 发送认证文件的线程函数]
 * @param  arg [未使用]
 * @return     [description]
 */
void *auth_tran(void *arg)
{
    pthread_setself("auth_tran");

    struct stat buf;
    time_t tprev = 0;

    //保存一开始文件的最后修改时间
    stat(AUTHUSERCONF, &buf);
    tprev = buf.st_mtime;

    while (1) {
        sleep(1);
        //当发现文件有变动，发送一次认证相关文件
        stat(AUTHUSERCONF, &buf);
        if (buf.st_mtime != tprev) {
            if (file_tran_auth() < 0) {
                PRINT_ERR_HEAD
                print_err("file_tran_auth error");
            }
            tprev = buf.st_mtime;
        }
    }
    return NULL;
}

/**
 * [StartTranAuth 开启一个线程，发送认证相关文件]
 * @return  [成功返回0 失败返回负值]
 */
int StartTranAuth(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, auth_tran, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("pthread create error");
        return -1;
    }

    return 0;
}
