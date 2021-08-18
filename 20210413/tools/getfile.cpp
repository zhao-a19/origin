/*******************************************************************************************
*文件:  getfile.cpp
*描述:  获取外网文件工具。该程序运行在内网端，用于获取外网的文件，需要一个参数，即绝对路径的
*       文件名。第二个参数可选，当有任何第二个参数时，表示获取完保留源文件。
*
*调用方法：./getfile filename(绝对路径) [remain]
*作者:  王君雷
*日期:
*修改:
*       阻塞，保证调用完后，要么已经获取文件完成，要么获取出错。         ------> 2017-07-17
*       使用utf8编码,unix风格                                            ------> 2018-12-18
*******************************************************************************************/
//
//请求协议:
//  HEADER|LEN|MODE|filename
//  LEN 其自身长度以及紧随其后的部分的长度之和
//  MODE 文件处理方式int类型    1:发送完保留    2:发送完删除(默认方式)
//  filename 绝对路径的文件名
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "define.h"
#include "struct_info.h"
#include "fileoperator.h"
#include "FCMsgAck.h"
#include "debugout.h"

loghandle glog_p = NULL;

int readlinkseg()
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        return 1;
    }

    char tmp[100] = {0};
    if (m_fileop.ReadCfgFile("SYSTEM", "LinkLanIPSeg", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        strcpy(tmp, "1");
    }
    m_fileop.CloseFile();

    int seg = atoi(tmp);
    if (seg < 1 || seg > 255) {
        return 1;
    }
    return seg;
}

int readlinkport()
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        return 1;
    }

    char tmp[100] = {0};
    if (m_fileop.ReadCfgFile("SYSTEM", "LinkLanPort", tmp, sizeof(tmp)) == E_FILE_FALSE) {
        strcpy(tmp, "");
    }
    m_fileop.CloseFile();

    int port = atoi(tmp);
    if (port < 1 || port > 65535) {
        return DEFAULT_LINK_PORT;
    }
    return port;
}

int main(int argc, char **argv)
{
    int sendcmdflag = false;
    char filename[MAX_FILE_PATH_LEN] = {0};
    char filename_tmp[MAX_FILE_PATH_LEN] = {0};
    int mode = 2;
    unsigned int length = 0;
    char sendbuf[MAX_BUF_LEN] = {0};
    HEADER header;
    memset(&header, 0, sizeof(header));

    _log_init_(glog_p, getfile);
    if (argc < 2 || argc > 3) {
        printf("\nUsage:%s filename(绝对路径) [remain]\n\n", argv[0]);
        return -1;
    }

    //检查文件名
    strcpy(filename, argv[1]);
    if (filename[0] != '/') {
        printf("Please input ABSOLUTE filename!\n");
        return -1;
    }

    //文件处理方式
    if (argc == 3) {
        mode = 1;
    }

    //设置应用号
    header.appnum = GET_FILE_TYPE;
    length = sizeof(length) + sizeof(mode) + strlen(filename);

    //按协议组装信息
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), &mode, sizeof(mode));
    memcpy(sendbuf + sizeof(header) + sizeof(length) + sizeof(mode), filename, strlen(filename));

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("getfile socket");
        return -1;
    }

    //填写地址结构
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    int seg = readlinkseg();
    char ip[16] = {0};
    sprintf(ip, "%d.0.0.253", seg);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(readlinkport());
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        perror("getfile inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    for (int i = 0; i < 3 ; i++) {
        //发送到外网
        ret = sendto( fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0) {
            perror("getfile sendto");
            close(fd);
            return -1;
        }

        if (RecvMsgAck(fd, &addr, sizeof(addr), header.appnum) == 0) {
            sendcmdflag = true;
            break;
        }
    }
    //close
    close(fd);

    if (!sendcmdflag) {
        printf("请求发送失败[%d]!\n", GET_FILE_TYPE);
        return -1;
    }

    //获取文件结果。。。
    sprintf(filename_tmp, "%s.anmit_tmp", filename);

    struct stat buf;
    time_t tprev = time(NULL);
    sleep(2);

    while (1) {
        if (stat(filename_tmp, &buf) == 0) {
            if (buf.st_mtime != tprev) {
                tprev = buf.st_mtime;
                sleep(1);
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if (stat(filename, &buf) == 0) {
        printf("getfile ok![%s]\n", filename);
        return 0;
    } else {
        printf("getfile error![%s]\n", filename);
        return 0;
    }
}
