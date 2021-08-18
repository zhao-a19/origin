/*******************************************************************************************
*文件:    FCRecvFile.cpp
*描述:    接收文件
*作者:    王君雷
*日期:    2015
*修改:
*         加入zlog记录日志;文件传输时使用 FILE_HEAD_PCKT结构           ------> 2018-04-09
*         不使用中文的叹号                                             ------> 2018-10-09
*         接收文件由进程改为线程                                       ------> 2020-02-24
*         可以设置线程名称                                            ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <pthread.h>
#include "FCRecvFile.h"
#include "FCSendFileUdp.h"
#include "define.h"
#include "FCMD5.h"
#include "debugout.h"
#include "struct_info.h"

/*
 *如果目录不存在，则逐级创建目录
 */
int Mkdir(const char *file_path)
{
    int len = 0;
    char tmp_path[MAX_FILE_PATH_LEN] = {0};

    //参数为NULL则退出
    if (file_path == NULL) {
        PRINT_ERR_HEAD
        print_err("para null");
        return -1;
    }

    //目录长度不合法退出
    len = strlen(file_path);
    if (len > MAX_FILE_PATH_LEN) {
        PRINT_ERR_HEAD
        print_err("file path is too long %d, max support %d", len, MAX_FILE_PATH_LEN);
        return -1;
    }

    //逐级创建目录
    for (int i = 0; i < len; i++) {
        if (file_path[i] != '/') {
            continue;
        }
        strncpy(tmp_path, file_path, i + 1);
        if ( mkdir(tmp_path, S_IRWXO | S_IRWXG | S_IRWXU) != 0 ) {
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
 * [RenameFile 把临时文件重命名为真实文件]
 * @param  filename [临时文件名]
 * @return          [成功返回0]
 */
int RenameFile(char *filename)
{
    char buf[MAX_FILE_PATH_LEN * 2 + 10] = {0};
    char realname[MAX_FILE_PATH_LEN] = {0};

    //文件名中没找到该临时后缀
    char *p = strstr(filename, TMP_SUFFIX_FILE);
    if (p == NULL) {
        PRINT_ERR_HEAD
        print_err("not find tmp suffix[%s]", filename);
        return -1;
    }

    //避免路径中正好有该后缀而出错
    while (strstr(p + 1, TMP_SUFFIX_FILE) != NULL) {
        p = strstr(p + 1, TMP_SUFFIX_FILE);
    }

    memcpy(realname, filename, p - filename);
    sprintf(buf, "mv -f %s %s", filename, realname);
    system(buf);
    return 0;
}

/*
 * 处理接收到的文件数据
 */
int do_with_file_data(int clifd, const char *recv_buf, int recv_size,
                      char *name, FILE **fp, int *pfile_size, char *md5str, int *premainder, int *p_isopen)
{
    unsigned int length = 0;
    unsigned int wlen = 0;
    int  file_len = 0;
    unsigned char md5str_temp[MD5_STR_LEN + 1] = {0};
    FILE_HEAD_PCKT fhead;

    if (recv_size == 0) {
        //要处理的数据长度为0时正确退出，进入下次接收
        return 0;
    } else if (recv_size < 0) {
        //要处理的数据长度为负数，错误退出
        PRINT_ERR_HEAD
        print_err("recv size error [%d]", recv_size);
        unlink(name);
        strcpy(name, "");
        return -1;
    } else if (recv_size < (int)sizeof(length)) {
        //要处理的数据长度为小于4时正确退出，进入下次接收
        *premainder = recv_size;
        return 0;
    }

    //解析出长度
    memcpy(&length, recv_buf, sizeof(length));

    //检查长度合法性，非法则错误退出
    if ((int)length > (FILE_BLOCKSIZE + (int)sizeof(length))
        && ((int)length != FILE_END)
        && ((int)length != FILE_BEGIN)) {

        PRINT_ERR_HEAD
        print_err("invalid length:%d", length);

        unlink(name);
        strcpy(name, "");
        return -1;
    }

    if ((int)length == FILE_BEGIN) {
        //新文件

        //首条发过来的不够长，退出进入下次接收
        if (recv_size < (int)sizeof(length) + FILE_BLOCKSIZE) {
            *premainder = recv_size;
            return 0;
        }

        //判断是否已经打开文件
        memcpy(&fhead, recv_buf + sizeof(length), sizeof(fhead));
        if (*p_isopen == 1) {
            fclose(*fp);
            *p_isopen = 0;

            //由于多个文件同时传输产生混乱，把之前正传输的文件删掉

            PRINT_ERR_HEAD
            print_err("Transfer multiple files at the same time is not allowed.last file[%s] current file[%s]",
                      name, fhead.fname);
            unlink(name);
            strcpy(name, "");
        }

        //得到校验值，文件大小，文件名
        memcpy(md5str, fhead.md5str, sizeof(fhead.md5str));
        memcpy(pfile_size, &(fhead.fsize), sizeof(fhead.fsize));
        memcpy(name, fhead.fname, sizeof(fhead.fname));
        strcat(name, TMP_SUFFIX_FILE);

        //printf("MD5 :%s\n",md5str);
        //printf("FLEN:%d\n",*pfile_size);
        PRINT_DBG_HEAD
        print_dbg("NAME:%s", name);

        //如果目录不存在，则创建之
        Mkdir(name);

        //打开文件
        *fp = fopen(name, "wb");
        if (*fp == NULL) {
            PRINT_ERR_HEAD
            print_err("fopen fail,[%s][%s]", name, strerror(errno));
            strcpy(name, "");
            return -1;
        }

        //修改文件状态为已打开
        *p_isopen = 1;

        //递归处理剩下的数据
        return do_with_file_data(clifd, recv_buf + sizeof(length) + FILE_BLOCKSIZE ,
                                 recv_size - (sizeof(length) + FILE_BLOCKSIZE), name, fp, pfile_size, md5str, premainder, p_isopen);
    } else if ( (int)length == FILE_END) {
        //文件结束

        //判断是否已经打开文件
        if (*p_isopen != 1) {
            //文件尚未打开，不能关闭，出错
            PRINT_ERR_HEAD
            print_err("Unpened file can not be closed");
            strcpy(name, "");
            return do_with_file_data(clifd, recv_buf + sizeof(length) ,
                                     recv_size - sizeof(length), name, fp, pfile_size, md5str, premainder, p_isopen);
        }

        //得到实际文件长度
        fseek(*fp, 0, SEEK_END);
        file_len = ftell(*fp);
        fclose(*fp);

        //修改文件状态为未打开
        *p_isopen = 0;

        //计算MD5检验码
        md5sum(name, md5str_temp);

        //比较大小和md5校验码是否正确
        if ( (file_len != *pfile_size) || (memcmp(md5str_temp, md5str, 16) != 0)) {

            PRINT_ERR_HEAD
            print_err("File transfer error.[%s],size should be %d, actual is %d", name, *pfile_size, file_len);

            //传输失败则把接收到的文件删除掉
            unlink(name);
            strcpy(name, "");

            //告诉客户端 文件校验失败
            send(clifd, "0", 1, 0);
            return -1;
        } else {
            RenameFile(name);
            strcpy(name, "");
            //告诉客户端 文件处理成功
            send(clifd, "1", 1, 0);

            //递归处理剩下的数据
            return do_with_file_data(clifd, recv_buf + sizeof(length) ,
                                     recv_size - sizeof(length), name, fp, pfile_size, md5str, premainder, p_isopen);
        }
    } else {
        //文件内容

        //如果该条不完整，则正确退出，进入下次接收
        if (recv_size < (int)length) {
            *premainder = recv_size;
            return 0;
        }

        //判断是否已经打开文件
        if (*p_isopen != 1) {
            //文件还没有打开，直接发来内容，说明可能首条丢失了，出错
            PRINT_ERR_HEAD
            print_err("Unopened file can not be writen");

            unlink(name);
            strcpy(name, "");

            return do_with_file_data(clifd, recv_buf + length,
                                     recv_size - length, name, fp, pfile_size, md5str, premainder, p_isopen);
        }

        //把内容写入文件
        wlen = fwrite(recv_buf + sizeof(length), 1, length - sizeof(length), *fp);
        if (wlen != length - sizeof(length)) {

            PRINT_ERR_HEAD
            print_err("fwrite ret = [%d],expected = %d,[%s]", wlen, (int)(length - sizeof(length)), strerror(errno));

            unlink(name);
            strcpy(name, "");
            return -1;
        }
        fflush(*fp);

        //递归处理剩下的数据
        return do_with_file_data(clifd, recv_buf + length,
                                 recv_size - length, name, fp, pfile_size, md5str, premainder, p_isopen);
    }
}

/*
 * 接收文件接口
 * 返回值 0:成功   -1:失败
 */
int RecvFile(void)
{
    struct sockaddr_un addr_srv, addr_cli;
    socklen_t addr_len_cli = 0;
    int clifd = 0;
    char recv_buf[MAX_BUF_LEN + sizeof(unsigned int)] = {0};
    int recv_size = 0;
    FILE *fp = NULL;
    int file_size = 0;
    int ret = 0;
    char new_file_name[MAX_FILE_PATH_LEN + strlen(TMP_SUFFIX_FILE) + 1] = {0};
    char md5str[MD5_STR_LEN + 1] = {0};
    //文件是否打开了
    int isopen = 0;
    //remainder存放上次处理剩余的长度
    int remainder = 0;

    //接收数据socket描述符
    int recv_fd;
    recv_fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (recv_fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error,[%s]", strerror(errno));
        return (-1);
    }

    //处理网络通信的地址
    char path_unix[128] = {0};
    snprintf(path_unix, sizeof(path_unix), "%s-%d-%d-%d-%d", UNIX_SERV_PATH, -1, -1, FILE_TRANSFER_TYPE, -1);

    memset(&addr_srv, 0, sizeof(addr_srv));
    addr_srv.sun_family = AF_LOCAL;
    strcpy(addr_srv.sun_path, path_unix);

    //先删除要使用的路径
    unlink(path_unix);

    //服务端绑定UNIX域路径
    if (bind(recv_fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv)) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error,[%s]", strerror(errno));
        close(recv_fd);
        return (-1);
    }

    //UNIX域套接字开始监听
    if (listen(recv_fd, 10) < 0) {
        PRINT_ERR_HEAD
        print_err("listen error,[%s]", strerror(errno));
        close(recv_fd);
        return (-1);
    }

FILE_ACCEPT:
    //接收客户端连接
    addr_len_cli = sizeof(addr_cli);
    memset(&addr_cli, 0, sizeof(addr_cli));
    clifd = accept(recv_fd, (struct sockaddr *)&addr_cli, &addr_len_cli);
    if (clifd < 0) {
        PRINT_ERR_HEAD
        print_err("accept error,[%s]", strerror(errno));
        goto FILE_ACCEPT;
    }

    int yes = 1;
    setsockopt(clifd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

    //在循环中接收文件
    while (1) {
        //把上次剩余没处理的部分前移
        memmove(recv_buf, recv_buf + recv_size - remainder, remainder);

        //接收文件数据
        recv_size = recv(clifd, recv_buf + remainder, MAX_BUF_LEN + sizeof(unsigned int) - remainder, 0);
        if (recv_size < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("recv error[%d],[%s]", recv_size, strerror(errno));
                break;
            }
        } else if (recv_size == 0) {
            break;
        }

        recv_size += remainder;
        remainder = 0;

        //处理文件数据
        ret = do_with_file_data(clifd, recv_buf, recv_size, new_file_name, &fp, &file_size, md5str, &remainder, &isopen);
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("do_with_file_data error %d", ret);
            break;
        }
    }
    unlink(path_unix);
    close(clifd);
    close(recv_fd);
    return -1;
}

/**
 * [recvfileudp UDP收取文件线程函数]
 * @param  arg [未使用]
 * @return     [未使用]
 */
void *recvfileudp(void *arg)
{
    pthread_setself("recvfileudp");
    while (1) {
        int ret = RecvFile();
        if (ret < 0) {
            PRINT_ERR_HEAD
            print_err("recvfile error %d, recv again", ret);
        }
    }
    return NULL;
}

/**
 * [StartRecvFileUDP 开启UDP接收文件线程]
 * @return  [成功返回0]
 */
int StartRecvFileUDP(void)
{
    pthread_t threadid;
    if (pthread_create(&threadid, NULL, recvfileudp, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create thread recvfileudp fail");
        return -1;
    }
    return 0;
}

