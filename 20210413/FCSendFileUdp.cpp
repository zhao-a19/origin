/*******************************************************************************************
*文件:  FCSendFileUdp.cpp
*描述:  UDP方式发送文件接口
*作者:  王君雷
*日期:  2016-03
*       使用zlog记录日志                                    ------> 2020-07-31
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include "FCSendFileUdp.h"
#include "struct_info.h"
#include "define.h"
#include "FCMD5.h"
#include "FCMsgAck.h"
#include "debugout.h"

extern int g_linklanipseg;
extern int g_linklanport;

/*******************************************************************************************
*功  能: UDP方式发送文件接口函数
*作  者：王君雷
*参  数:
*        srcfile  发送文件的绝对路径
*        dstfile  目标文件的绝对路径
*        trytimes 发送失败时，尝试重发的次数，超过该值就返回错误。-1表示尝试无限次
*
*返回值: 0成功     -1失败
*修  改：
*        send_file_udp失败超过一定次数后可选择返回错误，避免无限循环     ----> 2017-08-16
*        发送文件时使用结构体 FILE_HEAD_PCKT 组发送内容                  ----> 2018-04-10
*******************************************************************************************/
int send_file_udp(const char *srcfile, const char *dstfile, int trytimes)
{
    FILE *fp = NULL;
    unsigned int length = 0;
    int slen = 0;
    int rlen = 0;
    int trycnt = 0;//失败计数
    char r_buf[FILE_BLOCKSIZE + sizeof(HEADER) + sizeof(length)] = {0};
    FILE_HEAD_PCKT fhead;
    int fd = 0;
    char ip[IP_STR_LEN] = {0};
    struct sockaddr_in add;

    HEADER header;
    header.ipnum = -1;
    header.rulenum = -1;
    header.appnum = FILE_TRANSFER_TYPE;
    header.tomirror = -1;
    memset(&fhead, 0, sizeof(fhead));

    int bcnt = 0;

    //创建socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail[%d:%s]", fd, strerror(errno));
        return -1;
    }

    //填写地址结构
    add.sin_family = AF_INET;
    add.sin_port = htons(g_linklanport);
    sprintf(ip, "%d.0.0.%s", g_linklanipseg, (DEVFLAG[0] == 'I') ? "253" : "254");
    int ret = inet_pton(AF_INET, ip, (void *)&add.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton fail[%d:%s] ip[%s]", ret, strerror(errno), ip);
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //如果没指定目标文件名，就认为和要发送的文件路径一致
    strcpy(fhead.fname, (dstfile == NULL) ? srcfile : dstfile);
    md5sum(srcfile, fhead.md5str);

SEND_FILE_FLAG:
    bcnt = 0;
    //打开文件
    fp = fopen(srcfile, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen fail[%s:%s]", srcfile, strerror(errno));
        close(fd);
        return -1;
    }

    //得到文件长度
    fseek(fp, 0, SEEK_END);
    fhead.fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //printf("NAME:%s\n",srcfile);

    //把文件的MD5校验值、文件大小、文件名，发送过去
    memset(r_buf, 0, sizeof(r_buf));
    length = FILE_BEGIN;
    memcpy(r_buf, &header, sizeof(header));
    memcpy(r_buf + sizeof(header), &length, sizeof(length));
    memcpy(r_buf + sizeof(header) + sizeof(length), &fhead, sizeof(fhead));

    while (1) {
        slen = sendto(fd, r_buf, FILE_BLOCKSIZE + sizeof(header) + sizeof(length), 0, 
            (struct sockaddr *)&add, sizeof(add));
        if (slen < 0) {
            PRINT_ERR_HEAD
            print_err("sendto fail[%d:%s]", slen, strerror(errno));
            fclose(fp);
            close(fd);
            return -1;
        }

        //第一条 正确接收到对端的确认后 才继续下面的发送
        if (RecvMsgAck(fd, &add, sizeof(add), FILE_TRANSFER_TYPE) == 0) {
            break;
        } else {
            trycnt++;
            PRINT_ERR_HEAD
            print_err("send file begin timeout[%s] trycnt[%d]", fhead.fname, trycnt);
            if ((trytimes >= 0) && (trycnt > trytimes)) {
                PRINT_ERR_HEAD
                print_err("The number of failures exceeded the set value [%d][%s]", 
                    trytimes, fhead.fname);
                fclose(fp);
                close(fd);
                return -1;
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("send file begin ok[%s] size[%d]", fhead.fname, fhead.fsize);

    //按块发送文件
    while (1) {
        memset(r_buf + sizeof(header), 0, FILE_BLOCKSIZE + sizeof(length));
        if ( (rlen = fread(r_buf + sizeof(header) + sizeof(length), 1, FILE_BLOCKSIZE, fp)) <= 0) {
            //文件发送完毕
            length = FILE_END;
            memcpy(r_buf + sizeof(header), &length, sizeof(length));
            slen = sendto(fd, r_buf, sizeof(header) + sizeof(length), 0, 
                (struct sockaddr *)&add, sizeof(add));
            if (slen < 0) {
                PRINT_ERR_HEAD
                print_err("sendto fail[%d:%s]", slen, strerror(errno));
                fclose(fp);
                close(fd);
                return -1;
            }

            for (int i = 0; i < 10; i++ ) {
                ret = RecvMsgAck(fd, &add, sizeof(add), FILE_TRANSFER_TYPE);
                if (ret == 0 || ret == -4) {
                    break;
                }
            }

            //当收不到对端发来的确认及其他错误时 重新发送该文件
            if (ret != 0) {
                trycnt++;
                if ((trytimes >= 0) && (trycnt > trytimes)) {
                    PRINT_ERR_HEAD
                    print_err("The number of failures exceeded the set value [%d][%s]", 
                        trytimes, fhead.fname);
                    fclose(fp);
                    close(fd);
                    return -1;
                }

                fclose(fp);
                fp = NULL;
                PRINT_ERR_HEAD
                print_err("send file end timeout[%s] trycnt[%d],retry", fhead.fname, trycnt);
                goto SEND_FILE_FLAG;
            }

            break;
        } else {
            bcnt++;
            //发送文件内容
            length = rlen + sizeof(length);
            memcpy(r_buf + sizeof(header), &length, sizeof(length));
            slen = sendto(fd, r_buf, length + sizeof(header), 0, 
                (struct sockaddr *)&add, sizeof(add));
            if (slen < 0) {
                PRINT_ERR_HEAD
                print_err("sendto fail[%d:%s]", slen, strerror(errno));
                fclose(fp);
                close(fd);
                return -1;
            }

            if (RecvMsgAck(fd, &add, sizeof(add), FILE_TRANSFER_TYPE) != 0) {
                trycnt++;
                if ((trytimes >= 0) && (trycnt > trytimes)) {
                    PRINT_ERR_HEAD
                    print_err("The number of failures exceeded the set value [%d][%s]", 
                        trytimes, fhead.fname);
                    fclose(fp);
                    close(fd);
                    return -1;
                }

                fclose(fp);
                fp = NULL;
                PRINT_ERR_HEAD
                print_err("send file content timeout.fname[%s] trycnt[%d] bcnt[%d],retry", 
                    fhead.fname, trycnt, bcnt);
                goto SEND_FILE_FLAG;
            }
        }
    }
    fclose(fp);
    close(fd);

    PRINT_DBG_HEAD
    print_dbg("send file[%s] fsize[%d] ok", fhead.fname, fhead.fsize);
    return 0;
}
