/*******************************************************************************************
*文件:  transfer_client.cpp
*描述:  TCP传输文件 客户端
*作者:  王君雷
*日期:  2020-03-07
*修改:
*       修改transfer客户端通过%d打印字符串的BUG，不严重，通常不会进入 ------> 2021-04-09
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/sendfile.h>
#include "socket.h"
#include "transfer.h"
#include "debugout.h"

/**
 * [fill_fhead 填充文件头结构]
 * @param fhead   [文件头]
 * @param dstpath [对端文件路径]
 * @param size    [文件大小]
 * @param perm    [权限]
 * @param mode    [模式]
 */
void fill_fhead(TRANSFER_HEAD &fhead, const char *dstpath, int size, int perm, int mode)
{
    memset(&fhead, 0, sizeof(fhead));
    strcpy(fhead.filename, dstpath);
    fhead.fsize = size;
    fhead.perm = perm;
    fhead.mode = mode;
    strcpy(fhead.checkflag, SU_FILE_FLAG);
}

/**
 * [send_filehead 把文件头部发送出去]
 * @param  fd      [描述符]
 * @param  buff    [待发送的缓冲区]
 * @param  sendlen [待发送的长度]
 * @return         [成功返回true]
 */
bool send_filehead(int fd, void *buff, int sendlen)
{
    int slen = 0, cnt = 0;

    while (cnt < sendlen) {
        slen = send(fd, buff + cnt, sendlen - cnt, 0);
        if (slen > 0) {
            cnt += slen;
        } else if (slen == 0) {
            PRINT_ERR_HEAD
            print_err("peer may close sock. cnt[%d] fhead size[%d]", cnt, slen);
            break;
        } else {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                PRINT_DBG_HEAD
                print_dbg("send fhead again[%s]", strerror(errno));
            } else {
                PRINT_ERR_HEAD
                print_err("send fail[%s] slen[%d]", strerror(errno), slen);
                break;
            }
        }
    }
    return (cnt == sendlen);
}

/**
 * [send_file 发送文件]
 * @param  sockfd [socket描述符]
 * @param  filefd [文件描述符]
 * @param  fsize  [文件大小]
 * @return        [成功返回true]
 */
bool send_file(int sockfd, int filefd, int fsize)
{
    int slen = 0, cnt = 0;

    while (cnt < fsize) {
        slen = sendfile(sockfd, filefd, NULL, fsize - cnt);
        if (slen > 0) {
            cnt += slen;
        } else  if (slen == 0) {
            PRINT_ERR_HEAD
            print_err("peer may close sock. cnt[%d] fsize[%d]", cnt, fsize);
            break;
        } else {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                PRINT_DBG_HEAD
                print_dbg("sendfile again[%s] cnt[%d]", strerror(errno), cnt);
            } else {
                PRINT_ERR_HEAD
                print_err("sendfile fail[%s] slen[%d] cnt[%d]", strerror(errno), slen, cnt);
                break;
            }
        }
    }

    return (cnt == fsize);
}


/**
 * [do_client 客户端发送文件]
 * @param  ip      [IP]
 * @param  port    [端口]
 * @param  srcpath [源文件路径]
 * @param  dstpath [目的文件路径]
 * @param  perm    [权限]
 * @param  mode    [模式]
 * @return         [成功返回0 失败返回负值]
 */
int do_client(const char *ip, int port, const char *srcpath, const char *dstpath, int perm, int mode)
{
    int ret = -1;
    if ((dstpath == NULL) || (dstpath[0] != '/') || strlen(dstpath) >= FILE_PATH_LEN) {
        PRINT_ERR_HEAD
        print_err("dstpath error[%s]", dstpath);
        return -1;
    }

    int sockfd = client_socket(ip, port);
    if (sockfd < 0) {
        PRINT_ERR_HEAD
        print_err("client socket error[%d]", sockfd);
        return -1;
    }

    struct timeval tval = {10, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tval, sizeof(tval));

    int filefd = open(srcpath, O_RDONLY);
    if (filefd < 0) {
        PRINT_ERR_HEAD
        print_err("open file[%s] error[%s]", srcpath, strerror(errno));
        CLOSE(sockfd);
        return -1;
    }

    struct stat stat_buf;
    fstat(filefd, &stat_buf);
    TRANSFER_HEAD fhead;
    fill_fhead(fhead, dstpath, stat_buf.st_size, perm, mode);

    time_t t1, t2;
    time(&t1);
    if (send_filehead(sockfd, (void *)&fhead, sizeof(fhead)) && send_file(sockfd, filefd, stat_buf.st_size)) {
        time(&t2);
        PRINT_DBG_HEAD
        print_dbg("send Success[%s][%d]B [%d]s [%d]MB/s", fhead.filename, fhead.fsize, t2 - t1,
                  fhead.fsize / 1024 / 1024 / MAX(t2 - t1, 1));
        printf("Send Success[%s][%d]B [%d]s [%d]MB/s\n", fhead.filename, fhead.fsize, t2 - t1,
               fhead.fsize / 1024 / 1024 / MAX(t2 - t1, 1)); //Success是成功的标识 不要修改
        ret = 0;
    }

    CLOSE(sockfd);
    CLOSE(filefd);
    return ret;
}
