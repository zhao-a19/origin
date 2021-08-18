/*******************************************************************************************
*文件:    winsysv.cpp
*描述:    windows模拟实现System-V系统调用，暂时仅支持消息队列(线程通讯)
*
*作者:    张冬波
*日期:    2018-09-25
*修改:    创建文件                            ------>     2018-09-25

*******************************************************************************************/
#include "datatype.h"
#include "debugout.h"
#include "winsysv.h"
#include "errno.h"
#include <pthread.h>

#ifdef __CYGWIN__

typedef struct _sysv_stat {
    key_t queue_uid;            //唯一值
    size_t queue_mnb;           //空间大小
    size_t queue_max;           //系统保留最大空间
    size_t queue_maxusr;        //用户定义最大空间
    puint8 queue_addr;          //空间地址
    volatile puint8 queue_rp;   //读指针
    volatile puint8 queue_wp;   //写指针
    pthread_mutex_t queue_mutex;
    bool bfirst;

} SYSV_STAT;
#define _QUEUE_MAX_ 20

static SYSV_STAT sysv_stat[_QUEUE_MAX_];

/**
 * [msgget 创建or获取队列]
 * @param  key  [自定义唯一键]
 * @param  flag [操作标识]
 * @return      [队列id(从1开始），-1：失败]
 */
int msgget(key_t key, int flag)
{
    if (key == 0 ) {
        PRINT_ERR_HEAD;
        print_err("WSYSV not support");
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("WSYSV key=0x%x, flag=0x%x", key, flag);
    flag &= 037777777000;

    int32 id = -1;
    bool bexist = false;

    for (int32 i = 0; i < _QUEUE_MAX_; i++) {
        if (flag == IPC_CREAT) {
            if (sysv_stat[i].queue_uid == key) {
                bexist = true;
                break;
            }
            if (sysv_stat[i].queue_uid == 0) id = (id == -1) ? i : id;

        } else if (flag == IPC_DEFAULT) {
            if (sysv_stat[i].queue_uid == key) {
                PRINT_DBG_HEAD;
                print_dbg("WSYSV cur [0x%x:%d]%d", key, i, sysv_stat[i].queue_mnb);
                return i + 1;
            }
        } else if (flag == (IPC_CREAT | IPC_EXCL)) {
            if (sysv_stat[i].queue_uid == key) {
                bexist = true;
                break;
            }
            if (sysv_stat[i].queue_uid == 0) id = (id == -1) ? i : id;

        } else {
            PRINT_ERR_HEAD;
            print_err("WSYSV unknown 0x%x:0x%x", flag, (IPC_CREAT | IPC_EXCL));
        }
    }

    if (((flag == IPC_CREAT) || (flag == (IPC_CREAT | IPC_EXCL)))
        && (id != -1)) {

        sysv_stat[id].queue_addr = (puint8)calloc(1, sysv_stat[id].queue_mnb);
        if (sysv_stat[id].queue_addr != NULL) {
            sysv_stat[id].queue_uid = key;
            sysv_stat[id].queue_rp = sysv_stat[id].queue_wp = sysv_stat[id].queue_addr;
            pthread_mutex_init(&sysv_stat[id].queue_mutex, NULL);
            sysv_stat[id].bfirst = true;

            PRINT_DBG_HEAD;
            print_dbg("WSYSV new [0x%x:%d]%d", key, id, sysv_stat[id].queue_mnb);
            return id + 1;
        }

        PRINT_ERR_HEAD;
        print_err("WSYSV no memory [0x%x:%d]%d", key, id, sysv_stat[id].queue_mnb);
        errno = ENOMEM;
        return -1;
    }

    PRINT_ERR_HEAD;
    print_err("WSYSV key=0x%x, flag=0x%x", key, flag);
    if (flag == (IPC_CREAT | IPC_EXCL)) {
        if (bexist)
            errno = EEXIST;
        else
            errno = ENOSPC;
    } else if (flag == IPC_CREAT) {
        errno = ENOSPC;
    } else {
        errno = ENOENT;
    }

    return -1;
}

/**
 * [msgctl 控制参数]
 * @param  msgid [消息ID]
 * @param  cmd   [控制命令]
 * @param  buf   [无效参数]
 * @return       [0：成功]
 */
int msgctl(int msgid, int cmd, void *buf)
{
    if ((msgid == -1) || ((msgid - 1) >= _QUEUE_MAX_)) {
        PRINT_ERR_HEAD;
        print_err("WSYSV %d", msgid);
        errno = EINVAL;
        return -1;
    }

    if (cmd != IPC_RMID) {
        PRINT_ERR_HEAD;
        print_err("WSYSV [0x%x:%d], cmd = 0x%x", sysv_stat[msgid - 1].queue_uid, msgid, cmd);
        errno = EINVAL;
        return -1;
    }


    PRINT_DBG_HEAD;
    print_dbg("WSYSV [0x%x:%d], cmd = 0x%x", sysv_stat[msgid - 1].queue_uid, msgid, cmd);

    msgid -= 1;
    pthread_mutex_lock(&sysv_stat[msgid].queue_mutex);
    sysv_stat[msgid].queue_uid = 0;
    free(sysv_stat[msgid].queue_addr);
    sysv_stat[msgid].queue_addr = NULL;
    sysv_stat[msgid].queue_rp = sysv_stat[msgid].queue_wp = sysv_stat[msgid].queue_addr;
    sysv_stat[msgid].bfirst = true;

    pthread_mutex_unlock(&sysv_stat[msgid].queue_mutex);

    pthread_mutex_destroy(&sysv_stat[msgid].queue_mutex);

    return 0;
}

/**
 * [msgsnd 阻塞发送]
 * @param  msgid [消息ID]
 * @param  msgp  [数据指针]
 * @param  msgsz [数据大小]
 * @param  flag  [无效参数]
 * @return       [0：成功]
 */
//#define ptr_diff(s1,s2) (ptr_t)((s1)-(s2))

int msgsnd(int msgid, const void *msgp, uint32 msgsz, int flag)
{
    if ((msgid == -1) || ((msgid - 1) >= _QUEUE_MAX_) || (msgp == NULL)) {
        PRINT_ERR_HEAD;
        print_err("WSYSV %d", msgid);
        errno = EINVAL;
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("WSYSV send [0x%x:%d], size=%u", sysv_stat[msgid - 1].queue_uid, msgid, msgsz);

    msgid -= 1;
    if (sysv_stat[msgid].queue_uid == 0) {
        errno = EIDRM;
        return -1;
    }

    if (sysv_stat[msgid].queue_addr == NULL) {
        errno = EFAULT;
        return -1;
    }

    if (sysv_stat[msgid].queue_maxusr <= msgsz) {
        errno = EINVAL;
        return -1;
    }

    if ((sysv_stat[msgid].queue_wp + sysv_stat[msgid].queue_max) >=
        (sysv_stat[msgid].queue_addr + sysv_stat[msgid].queue_mnb)) {
        sysv_stat[msgid].queue_wp = sysv_stat[msgid].queue_addr;
    }

    //等待
    int32 waitcnt = 0;
_wait: {
        ptr_t s = 0;
        if ((ptr_t)sysv_stat[msgid].queue_wp < (ptr_t)sysv_stat[msgid].queue_rp) {
            s = ptr_diff(sysv_stat[msgid].queue_rp, sysv_stat[msgid].queue_wp);
            s = (ptr_t)(sysv_stat[msgid].queue_mnb) - s;

        } else {
            s = ptr_diff(sysv_stat[msgid].queue_wp, sysv_stat[msgid].queue_rp);
        }

        //队列满阻塞, 保留100个消息空间
        if ((ssize_t)s > (ssize_t)(sysv_stat[msgid].queue_mnb - sysv_stat[msgid].queue_max * 100)) {
            if (waitcnt == 0) {
                PRINT_DBG_HEAD;
                print_dbg("WSYSV send wait");
            }
            usleep(1);
            if (++waitcnt > 1000) {
                waitcnt = 0;
            }
            goto _wait;
        }
    }

    //写保护
    pthread_mutex_lock(&sysv_stat[msgid].queue_mutex);
    memcpy(sysv_stat[msgid].queue_wp, &msgsz, sizeof(msgsz));
    memcpy(sysv_stat[msgid].queue_wp + sizeof(msgsz), msgp, sizeof(long) + msgsz);
    sysv_stat[msgid].queue_wp += sysv_stat[msgid].queue_max;
    sysv_stat[msgid].bfirst = false;        //切换写等待
    pthread_mutex_unlock(&sysv_stat[msgid].queue_mutex);

    PRINT_DBG_HEAD;
    print_dbg("WSYSV send ok [0x%x:%d], size=%u", sysv_stat[msgid].queue_uid, msgid + 1, msgsz);
    return 0;

}

/**
 * [msgrcv 阻塞接收]
 * @param  msgid  [消息ID]
 * @param  msgp   [数据指针]
 * @param  msgsz  [数据大小]
 * @param  msgtyp [无效参数]
 * @param  flag   [无效参数]
 * @return        [实际数据大小，-1：失败]
 */
ssize_t msgrcv(int msgid, void *msgp, uint32 msgsz, long msgtyp, int flag)
{
    if ((msgid == -1) || ((msgid - 1) >= _QUEUE_MAX_) || (msgp == NULL)) {
        PRINT_ERR_HEAD;
        print_err("WSYSV %d", msgid);
        errno = EINVAL;
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("WSYSV recv [0x%x:%d], size=%u", sysv_stat[msgid - 1].queue_uid, msgid, msgsz);

    msgid -= 1;
    if (sysv_stat[msgid].queue_uid == 0) {
        errno = EIDRM;
        return -1;
    }

    if (sysv_stat[msgid].queue_addr == NULL) {
        errno = EFAULT;
        return -1;
    }

    if (sysv_stat[msgid].queue_maxusr <= msgsz) {
        errno = EINVAL;
        return -1;
    }

    if ((sysv_stat[msgid].queue_rp + sysv_stat[msgid].queue_max) >=
        (sysv_stat[msgid].queue_addr + sysv_stat[msgid].queue_mnb)) {
        sysv_stat[msgid].queue_rp = sysv_stat[msgid].queue_addr;
    }

    //等待
    int32 waitcnt = 0;
    while (sysv_stat[msgid].queue_rp == sysv_stat[msgid].queue_wp) {
        if (waitcnt == 0) {
            PRINT_DBG_HEAD;
            print_dbg("WSYSV recv wait");
        }
        usleep(1);
        if (++waitcnt > 1000) {
            waitcnt = 0;
        }
    }

    //读保护
    uint32 len = 0;
    pthread_mutex_lock(&sysv_stat[msgid].queue_mutex);
    memcpy(&len, sysv_stat[msgid].queue_rp, sizeof(len));
    if (len > msgsz) {
        PRINT_ERR_HEAD;
        print_err("WSYSV recv too big [0x%x:%d], size=%u", sysv_stat[msgid].queue_uid, msgid + 1, len);
        len = msgsz;
    }
    memcpy(msgp, sysv_stat[msgid].queue_rp + sizeof(msgsz), sizeof(long) + len);
    sysv_stat[msgid].queue_rp += sysv_stat[msgid].queue_max;
    pthread_mutex_unlock(&sysv_stat[msgid].queue_mutex);

    PRINT_DBG_HEAD;
    print_dbg("WSYSV recv ok [0x%x:%d], size=%u", sysv_stat[msgid].queue_uid, msgid + 1, len);
    return (ssize_t)len;

}

#endif

int32 sysv_init(int32 msgmnb, int32 msgmax)
{
#ifdef __CYGWIN__
    PRINT_DBG_HEAD;
    print_dbg("WSYSV mnb=%d, max=%d", msgmnb, msgmax);

    for (int32 i = 0; i < _QUEUE_MAX_; i++) {
        sysv_stat[i].queue_uid = 0;
        sysv_stat[i].queue_maxusr = msgmax;
        //264B对齐，前4B为数据有效大小, long为消息类型，最后为有效数据
        sysv_stat[i].queue_max = (msgmax + 255) / 256 * 256 + 4 + sizeof(long);
        sysv_stat[i].queue_mnb = (msgmnb + sysv_stat[i].queue_max - 1) / sysv_stat[i].queue_max;
        sysv_stat[i].queue_mnb *= sysv_stat[i].queue_max;
        sysv_stat[i].queue_addr = NULL;
        sysv_stat[i].queue_rp = sysv_stat[i].queue_wp = sysv_stat[i].queue_addr;
        sysv_stat[i].bfirst = true;
    }
#endif

    return 0;
}
