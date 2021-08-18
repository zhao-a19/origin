/*******************************************************************************************
*文件:  transfer_server.cpp
*描述:  TCP传输文件 服务器端
*作者:  王君雷
*日期:  2020-03-07
*修改:
*       修正put_file_queue函数中遗漏的memcpy操作,异步传输时会导致传输文件错误------> 2020-03-15
*       添加使用NOHUP_RUN宏，解决飞腾平台启动程序差异                       ------> 2020-09-20
*       g_async_queue_try_pop改为g_async_queue_pop，解决CPU占用高的问题    ------> 2020-12-21
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include "glib.h"
#include "socket.h"
#include "transfer.h"
#include "debugout.h"

#if (SUOS_V==2000)
#define NOHUP_RUN "nohup"
#else
#define NOHUP_RUN "busybox nohup"
#endif

#define FILE_BLOCK_LEN     102400 //接收数据块缓冲区大小
#define TASK_IDLE_SLEEP_US 1000
#define TRANSFER_FILE_END  -1
#define TRANSFER_FILE_ERR  -2
typedef void *(*PROCESS_FUNC)(void *arg);

//线程池
typedef struct _thread_pool {
    GAsyncQueue *gasync_queue;
    int shutdown;
    pthread_t *threadid;
    int max_thread_num;
} THREADPOOL;

//任务
typedef struct _worker {
    PROCESS_FUNC cb;      //回调函数
    void *arg;            //回调函数的参数
} WORKER;

//每个客户连接任务 线程参数
typedef struct _conn_arg {
    THREADPOOL *wrpool;
    int connfd;
} CONNARG;

//每个文件写入任务 线程参数
typedef struct _write_arg {
    TRANSFER_HEAD fhead;
    GAsyncQueue *gasync_queue;
} WRITEARG;

//接收到的一条文件数据
typedef struct _file_data {
    int len;
    char *data;
} FILEDATA;

/**
 * [thread_routine 线程池中每个线程执行的函数]
 * @param  arg [线程池指针]
 * @return     [未使用]
 */
void *thread_routine(void *arg)
{
    THREADPOOL *pool = (THREADPOOL *)arg;
    assert(pool != NULL);

    while (1) {
        if (pool->shutdown == 1) {
            pthread_exit(NULL);
        }

        WORKER *worker = (WORKER *)g_async_queue_pop(pool->gasync_queue);
        if (worker != NULL) {
            (worker->cb)(worker->arg);
            free(worker);
            worker = NULL;
        } else {
            usleep(TASK_IDLE_SLEEP_US);
        }
    }
    return NULL;
}

/**
 * [pool_add_worker 向线程池添加一个任务]
 * @param  pool [线程池指针]
 * @param  cb   [回调函数]
 * @param  arg  [回调函数参数]
 */
void pool_add_worker(THREADPOOL *pool, PROCESS_FUNC cb, void *arg)
{
    assert(pool != NULL);
    assert(cb != NULL);
    assert(arg != NULL);
    WORKER *newworker = NULL;
_flag:
    newworker = (WORKER *)malloc(sizeof(WORKER));
    if (newworker == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc newworker fail[%s] retry", strerror(errno));
        usleep(1000);
        goto _flag;
    }

    newworker->cb = cb;
    newworker->arg = arg;
    g_async_queue_push(pool->gasync_queue, newworker);
}

/**
 * [pool_init 线程池初始化]
 * @param pool           [线程池二级指针]
 * @param max_thread_num [最大线程数]
 * @param freefunc       [数据释放函数]
 */
void pool_init(THREADPOOL **pool, int max_thread_num, GDestroyNotify freefunc)
{
    assert(pool != NULL);
    assert(max_thread_num > 0);
    assert(freefunc != NULL);

_flag:
    *pool = (THREADPOOL *)malloc(sizeof(THREADPOOL));
    if (*pool == NULL) {
        PRINT_ERR_HEAD
        print_err("malloc threadpool fail[%s] retry", strerror(errno));
        usleep(1000);
        goto _flag;
    }
    memset(*pool, 0, sizeof(THREADPOOL));
    (*pool)->gasync_queue = g_async_queue_new_full(freefunc);
    (*pool)->shutdown = 0;
    (*pool)->threadid = (pthread_t *)malloc(max_thread_num * sizeof(pthread_t));
    for (int i = 0; i < max_thread_num; i++) {
        pthread_create(&((*pool)->threadid[i]), NULL, thread_routine, (void *)(*pool));
    }
    PRINT_DBG_HEAD
    print_dbg("create thread over. threadnum[%d]", max_thread_num);
}

/**
 * [pool_destroy 销毁线程池 等待队列中的任务不会再被执行，但是正在运行的线程会一直把任务运行完后再退出]
 * @param  pool [线程池二级指针]
 * @return      [成功返回0]
 */
int pool_destroy(THREADPOOL **pool)
{
    assert((pool != NULL) && (*pool != NULL));

    if ((*pool)->shutdown == 1) {
        PRINT_ERR_HEAD
        print_err("can not destroy again");
        return -1;
    }
    (*pool)->shutdown = 1;

    //阻塞等待线程退出
    for (int i = 0; i < (*pool)->max_thread_num; i++) {
        pthread_join((*pool)->threadid[i], NULL);
    }
    free((*pool)->threadid);

    g_async_queue_unref((*pool)->gasync_queue);
    free(*pool);
    *pool = NULL;
    return 0;
}

/**
 * [su_mkdir 如果目录不存在，则逐级创建目录]
 * @param  file_path [绝对路径名]
 * @return           [成功返回0]
 */
int su_mkdir(const char *file_path)
{
    int len = 0;
    char tmp_path[FILE_PATH_LEN] = {0};

    if (file_path == NULL) {
        PRINT_ERR_HEAD
        print_err("su mkdir para null");
        return -1;
    }

    len = strlen(file_path);
    if (len > FILE_PATH_LEN) {
        PRINT_ERR_HEAD
        print_err("file path is too long %d, max support %d", len, FILE_PATH_LEN);
        return -1;
    }

    for (int i = 0; i < len; i++) {
        if (file_path[i] != '/') {
            continue;
        }
        strncpy(tmp_path, file_path, i + 1);
        if (mkdir(tmp_path, S_IRWXO | S_IRWXG | S_IRWXU) != 0) {
            if (errno == EEXIST) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("create dir fail[%s][%s]", tmp_path, strerror(errno));
                return  -1;
            }
        }
    }
    return 0;
}

/**
 * [su_rename 把临时文件重命名为真实文件]
 * @param  filename [临时文件名]
 * @return          [成功返回0]
 */
int su_rename(char *filename)
{
    char buf[FILE_PATH_LEN * 2 + 10] = {0};
    char realname[FILE_PATH_LEN] = {0};

    //文件名中没找到该临时后缀
    char *p = strstr(filename, TMP_AMTCP_SUFFIX_FILE);
    if (p == NULL) {
        PRINT_ERR_HEAD
        print_err("not find tmp suffix[%s][%s]", filename, TMP_AMTCP_SUFFIX_FILE);
        return -1;
    }

    //避免路径中正好有该后缀而出错
    while (strstr(p + 1, TMP_AMTCP_SUFFIX_FILE) != NULL) {
        p = strstr(p + 1, TMP_AMTCP_SUFFIX_FILE);
    }

    memcpy(realname, filename, p - filename);
    sprintf(buf, "mv -f %s %s", filename, realname);
    system(buf);
    PRINT_INFO_HEAD
    print_info("rename file ok[%s]", realname);
    return 0;
}

/**
 * [data_to_file 把收到的数据写入文件]
 * @param  fp   [文件描述符]
 * @param  data [数据]
 * @param  len  [数据长度]
 * @return      [成功返回0 失败返回负值]
 */
int data_to_file(FILE *fp, const char *data, int len)
{
    int wlen = 0;
    int ret = 0;
    if ((fp != NULL) && (data != NULL) && (len > 0)) {
        while (wlen < len) {
            ret = fwrite(data + wlen, 1, len - wlen, fp);
            if (ret < 0) {
                PRINT_ERR_HEAD
                print_err("write file error[%s]", strerror(errno));
                break;
            } else {
                wlen += ret;
            }
        }
    }
    if (wlen == len) {
        return 0;
    }
    PRINT_ERR_HEAD
    print_err("data to file fail. wlen[%d] len[%d]", wlen, len);
    return -1;
}

/**
 * [check_rules 如果接收到的文件是规则文件 需要重启规则]
 * @param filename [文件名称]
 */
void check_rules(const char *filename)
{
    char chcmd[1024] = {0};

    if ((filename != NULL) && (strstr(filename, RULES_FILE) != NULL)) {
        system("killall -s SIGUSR1 recvmain_w");
        system(STOP_OUT_BUSINESS);
        sprintf(chcmd, "%s /initrd/abin/sys6_w >/dev/null &", NOHUP_RUN);
        system(chcmd);
        system("sync");
    }
}

/**
 * [check_file 文件已经传输完成 检查文件是否传输完整]
 * @param pfhead   [文件头结构指针]
 * @param realsize [文件落地大小]
 */
void check_file(TRANSFER_HEAD *pfhead, int realsize)
{
    char chcmd[1024] = {0};

    if (realsize != pfhead->fsize) {
        unlink(pfhead->filename);
        PRINT_ERR_HEAD
        print_err("file[%s]transfer error. fsize[%d][%d]", pfhead->filename, pfhead->fsize, realsize);
    } else {
        if (pfhead->perm == 1) {
            //sprintf(chcmd, "chmod +x %s", pfhead->filename);
            //system(chcmd);
            chmod(pfhead->filename, 0755);
        }
        su_rename(pfhead->filename);
        check_rules(pfhead->filename);
        PRINT_INFO_HEAD
        print_info("file[%s]transfer ok. fsize[%d] mode[%d]", pfhead->filename, pfhead->fsize, pfhead->mode);
    }
}

/**
 * [filefunc 从异步队列取文件数据 并处理]
 * @param  arg [WRITEARG结构指针]
 * @return     [未使用]
 */
void *filefunc(void *arg)
{
    PRINT_INFO_HEAD
    print_info("async transfer file...");

    assert(arg != NULL);

    WRITEARG *pwrarg = (WRITEARG *)arg;
    int realsize = 0;

    FILE *fp = fopen(pwrarg->fhead.filename, "wb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("cannot open file[%s] err[%s]", pwrarg->fhead.filename, strerror(errno));
    }

    while (1) {
        FILEDATA *filedata = (FILEDATA *)g_async_queue_pop(pwrarg->gasync_queue);
        if (filedata == NULL) {
            usleep(TASK_IDLE_SLEEP_US);
            continue;
        }
        switch (filedata->len) {
        case TRANSFER_FILE_END:
        case TRANSFER_FILE_ERR:
            fseek(fp, 0, SEEK_END);
            realsize = ftell(fp);
            FCLOSE(fp);
            check_file(&pwrarg->fhead, realsize);//检查文件是否传输成功
            g_async_queue_unref(pwrarg->gasync_queue);
            free(filedata);
            filedata = NULL;
            goto _over;
        default:
            data_to_file(fp, filedata->data, filedata->len);
            free(filedata);
            filedata = NULL;
            break;
        }
    }

_over:
    free(pwrarg);
    pwrarg = NULL;

    return NULL;
}

/**
 * [free_filedata 释放文件块]
 * @param data [文件块指针]
 */
void free_filedata(gpointer data)
{
    FILEDATA *filedata = (FILEDATA *)data;
    if (filedata->data != NULL) {
        free(filedata->data);
        filedata->data = NULL;
    }
    free(filedata);
}

/**
 * [recv_filehead 接收文件头]
 * @param  fd      [接收描述符]
 * @param  buff    [接收缓冲区]
 * @param  recvlen [要接收的长度]
 * @return         [成功返回true]
 */
bool recv_filehead(int fd, void *buff, int recvlen)
{
    int cnt = 0, ret = 0;
    while (cnt < recvlen) {
        ret = recv(fd, buff + cnt, recvlen - cnt, 0);
        if (ret > 0) {
            cnt += ret;
        } else if (ret == 0) {
            PRINT_ERR_HEAD
            print_err("peer close socket[%d]", fd);
            return false;
        } else {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%s] fd[%d]", strerror(errno), fd);
                return false;
            }
        }
    }
    return true;
}

/**
 * [put_file_queue 文件块放入异步队列]
 * @param buf        [文件块数据]
 * @param len        [文件块长度]
 * @param asyncqueue [队列]
 */
void put_file_queue(const char *buf, int len, GAsyncQueue *asyncqueue)
{
    FILEDATA *filedata = NULL;
_flag1:
    filedata = (FILEDATA *)malloc(sizeof(FILEDATA));
    if (filedata == NULL) {
        PRINT_ERR_HEAD
        print_err("filedata malloc fail.len[%d] err[%s],retry", sizeof(FILEDATA), strerror(errno));
        usleep(1000);
        goto _flag1;
    }

    filedata->len = len;
    switch (len) {
    case TRANSFER_FILE_END:
    case TRANSFER_FILE_ERR:
        filedata->data = NULL;
        break;
    default:
_flag2:
        filedata->data = (char *)malloc(len);
        if (filedata->data == NULL) {
            PRINT_ERR_HEAD
            print_err("filedata data malloc fail.len[%d] err[%s],retry", len, strerror(errno));
            usleep(1000);
            goto _flag2;
        }
        memcpy(filedata->data, buf, len);
        break;
    }
    g_async_queue_push(asyncqueue, filedata);
}

/**
 * [recvfile_async 异步方式接收文件]
 * @param  pconnarg [CONNARG指针]
 * @param  pfhead   [文件头部结构指针]
 * @return          [成功返回0 失败返回负值]
 */
int recvfile_async(CONNARG *pconnarg, TRANSFER_HEAD *pfhead)
{
    WRITEARG *wrarg = NULL;
    char recvbuff[FILE_BLOCK_LEN] = {0};
    int ret = 0;

_flag:
    wrarg = (WRITEARG *)malloc(sizeof(WRITEARG));
    if (wrarg == NULL) {
        PRINT_ERR_HEAD
        print_err("write arg malloc fail retry");
        usleep(1000);
        goto _flag;
    }
    memcpy(&(wrarg->fhead), pfhead, sizeof(TRANSFER_HEAD));

    //创建异步队列
    wrarg->gasync_queue = g_async_queue_new_full(free_filedata);
    pool_add_worker(pconnarg->wrpool, filefunc, (void *)wrarg);

    while (1) {
        ret = recv(pconnarg->connfd, recvbuff, sizeof(recvbuff), 0);
        if (ret > 0) {
            put_file_queue(recvbuff, ret, wrarg->gasync_queue);
        } else if (ret == 0) {
            PRINT_DBG_HEAD
            print_dbg("peer close socket[%d]", pconnarg->connfd);
            put_file_queue(recvbuff, TRANSFER_FILE_END, wrarg->gasync_queue);
            break;
        } else {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%s] fd[%d]", strerror(errno), pconnarg->connfd);
                put_file_queue(recvbuff, TRANSFER_FILE_ERR, wrarg->gasync_queue);
                return -1;
            }
        }
    }
    return 0;
}

/**
 * [recvfile_sync 同步方式接收文件]
 * @param  pconnarg [CONNARG指针]
 * @param  pfhead   [文件头部结构指针]
 * @return          [成功返回0 失败返回负值]
 */
int recvfile_sync(CONNARG *pconnarg, TRANSFER_HEAD *pfhead)
{
    PRINT_INFO_HEAD
    print_info("sync transfer file ...");

    int ret = 0;
    char recvbuff[FILE_BLOCK_LEN] = {0};
    int realsize = 0;

    FILE *fp = fopen(pfhead->filename, "wb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("cannot open file[%s] err[%s]", pfhead->filename, strerror(errno));
        return -1;
    }

    while (1) {
        ret = recv(pconnarg->connfd, recvbuff, sizeof(recvbuff), 0);
        if (ret > 0) {
            data_to_file(fp, recvbuff, ret);
        } else if (ret == 0) {
            PRINT_DBG_HEAD
            print_dbg("peer close socket[%d]", pconnarg->connfd);
            break;
        } else {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%s] fd[%d]", strerror(errno), pconnarg->connfd);
                break;
            }
        }
    }
    fseek(fp, 0, SEEK_END);
    realsize = ftell(fp);
    FCLOSE(fp);
    check_file(pfhead, realsize);

    return 0;
}

/**
 * [connfunc 客户端连接线程函数]
 * @param  arg [线程参数]
 * @return     [未使用]
 */
void *connfunc(void *arg)
{
    assert(arg != NULL);

    CONNARG *pconnarg = (CONNARG *)arg;
    TRANSFER_HEAD fhead;
    if (!recv_filehead(pconnarg->connfd, (void *)&fhead, sizeof(fhead))) {
        goto _flag;
    }

    if (strcmp(SU_FILE_FLAG, fhead.checkflag) != 0) {
        PRINT_ERR_HEAD
        print_err("checkflag error[%s]", fhead.checkflag);
        goto _flag;
    }

    strcat(fhead.filename, TMP_AMTCP_SUFFIX_FILE);
    su_mkdir(fhead.filename);

    PRINT_INFO_HEAD
    print_info("file[%s] mode[%d]", fhead.filename, fhead.mode);

    if (fhead.mode == TRANSFER_MODE_ASYNC) {
        recvfile_async(pconnarg, &fhead);
    } else if (fhead.mode == TRANSFER_MODE_SYNC) {
        recvfile_sync(pconnarg, &fhead);
    } else {
        PRINT_ERR_HEAD
        print_err("fhead mode unknown %d", fhead.mode);
    }

_flag:
    CLOSE(pconnarg->connfd);
    free(pconnarg);
    return NULL;
}

/**
 * [freeworker_connarg 释放连接参数结构]
 * @param data [WORKER指针]
 */
void freeworker_connarg(gpointer data)
{
    WORKER *worker = (WORKER *)data;
    CONNARG *connarg = (CONNARG *)worker->arg;
    if (connarg != NULL) {
        CLOSE(connarg->connfd);
        free(connarg);
        connarg = NULL;
    }
    free(worker);
    worker = NULL;
}

/**
 * [freeworker_writearg 释放写文件参数结构]
 * @param data [WORKER指针]
 */
void freeworker_writearg(gpointer data)
{
    WORKER *worker = (WORKER *)data;
    WRITEARG *wrarg = (WRITEARG *)worker->arg;
    if (wrarg != NULL) {
        g_async_queue_unref(wrarg->gasync_queue);
        free(wrarg);
        wrarg = NULL;
    }
    free(worker);
    worker = NULL;
}

/**
 * [do_server 服务器端处理]
 * @param  ip   [IP]
 * @param  port [端口]
 * @param  threadnum [线程个数]
 * @return      [失败返回-1]
 */
int do_server(const char *ip, int port, int threadnum)
{
    g_thread_init(NULL);

    THREADPOOL *accept_pool = NULL;
    THREADPOOL *write_pool = NULL;
    pool_init(&accept_pool, threadnum, freeworker_connarg);
    pool_init(&write_pool, threadnum, freeworker_writearg);

    int sockfd = server_socket(ip, port);
    if (sockfd < 0) {
        pool_destroy(&accept_pool);
        pool_destroy(&write_pool);
        return -1;
    }

    while (1) {
        int connfd = accept(sockfd, NULL, NULL);
        if (connfd == -1) {
            PRINT_ERR_HEAD
            print_err("accept error[%s]", strerror(errno));
            break;
        }

        struct timeval tval = {10, 0};
        setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tval, sizeof(tval));

        CONNARG *parg = (CONNARG *)malloc(sizeof(CONNARG));
        if (parg == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc fail[%s]", strerror(errno));
            CLOSE(connfd);
            continue;
        }
        memset(parg, 0, sizeof(CONNARG));
        parg->connfd = connfd;
        parg->wrpool = write_pool;
        pool_add_worker(accept_pool, connfunc, (void *)parg);
    }

    CLOSE(sockfd);
    pool_destroy(&accept_pool);
    pool_destroy(&write_pool);
    return -1;
}
