/*******************************************************************************************
*文件:    winsysv.h
*描述:    windows模拟实现System-V系统调用，暂时仅支持消息队列(线程通讯)
*
*作者:    张冬波
*日期:    2018-09-25
*修改:    创建文件                            ------>     2018-09-25

*******************************************************************************************/
#include "datatype.h"

#ifndef __WIN_SYSV_H__
#define __WIN_SYSV_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __CYGWIN__

#define IPC_DEFAULT 0
/* common mode bits */
#define IPC_R           000400  /* read permission */
#define IPC_W           000200  /* write/alter permission */
#define IPC_M           010000  /* permission to change control info */

/* SVID required constants (same values as system 5) */
#define IPC_CREAT       001000  /* create entry if key does not exist */
#define IPC_EXCL        002000  /* fail if key exists */
#define IPC_NOWAIT      004000  /* error if request must wait */

#define IPC_PRIVATE     (key_t)0 /* private key */

#define IPC_RMID        0       /* remove identifier */
#define IPC_SET         1       /* set options */
#define IPC_STAT        2       /* get options */

/**
 * [msgget 创建or获取队列]
 * @param  key  [自定义唯一键]
 * @param  flag [操作标识]
 * @return      [队列id(从1开始），-1：失败]
 */
int msgget(key_t key, int flag);

/**
 * [msgctl 控制参数]
 * @param  msgid [消息ID]
 * @param  cmd   [控制命令]
 * @param  buf   [无效参数]
 * @return       [0：成功]
 */
int msgctl(int msgid, int cmd, void *buf);

/**
 * [msgsnd 阻塞发送]
 * @param  msgid [消息ID]
 * @param  msgp  [数据指针]
 * @param  msgsz [数据大小]
 * @param  flag  [无效参数]
 * @return       [0：成功]
 */
int msgsnd(int msgid, const void *msgp, uint32 msgsz, int flag);

/**
 * [msgrcv 阻塞接收]
 * @param  msgid  [消息ID]
 * @param  msgp   [数据指针]
 * @param  msgsz  [数据大小]
 * @param  msgtyp [无效参数]
 * @param  flag   [无效参数]
 * @return        [实际数据大小，-1：失败]
 */
ssize_t msgrcv(int msgid, void *msgp, uint32 msgsz, long msgtyp, int flag);

#endif

int32 sysv_init(int32 msgmnb, int32 msgmax);

#ifdef __cplusplus
}
#endif

#endif
