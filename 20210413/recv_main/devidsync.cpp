/*******************************************************************************************
*文件:  devidsync.cpp
*描述:  把内网的设备ID号同步到外网
*作者:  王君雷
*日期:  2020-02-14
*修改:
*       可以设置线程名称                                               ------> 2021-02-23
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "devidsync.h"
#include "define.h"
#include "fileoperator.h"
#include "debugout.h"
#include "struct_info.h"
#include "gap_cmdtype.h"

extern int g_linklanipseg;
extern int g_linklanport;

/**
 * [read_devid 读取设备ID]
 * @param  devid [设备ID 出参]
 * @param  size  [出参缓冲区大小]
 * @return       [成功返回0]
 */
int read_devid(char *devid, int size)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile error[%s]", SYSINFO_CONF);
        return -1;
    }

    fileop.ReadCfgFile("SYSTEM", "DevIndex", devid, size);
    fileop.CloseFile();

    PRINT_DBG_HEAD
    print_dbg("read devid is [%s]", devid);
    return 0;
}

/**
 * [write_devid 写设备ID]
 * @param  devid [设备ID]
 * @return       [成功返回0]
 */
int write_devid(const char *devid)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r+") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile error[%s]", SYSINFO_CONF);
        return -1;
    }

    fileop.WriteCfgFile("SYSTEM", "DevIndex", devid);
    fileop.CloseFile();

    PRINT_INFO_HEAD
    print_info("write devid[%s]", devid);
    return 0;
}

/**
 * [devid_sync 同步设备ID到对端]
 * @param  devid [设备ID]
 * @return       [成功返回true]
 */
bool devid_sync(const char *devid)
{
    pthread_setself("devidsync");
    if ((devid == NULL) || (devid[0] == 0) || (strlen(devid) >= DEV_ID_LEN)) {
        PRINT_ERR_HEAD
        print_err("devid is [%s]", devid);
        return false;
    }

    char send_buf[sizeof(HEADER) + DEV_ID_LEN + 100] = {0};
    HEADER header;
    BZERO(header);
    header.appnum = DEVID_SYNC_TYPE;
    unsigned int length = sizeof(length) + strlen(devid);
    memcpy(send_buf, &header, sizeof(header));
    memcpy(send_buf + sizeof(header), &length, sizeof(length));
    memcpy(send_buf + sizeof(header) + sizeof(length), devid, strlen(devid));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return false;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.253", g_linklanipseg);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("inet_pton error[%s][%s]", strerror(errno), ip);
        close(fd);
        return false;
    }

    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    ret = sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("sendto error[%s]", strerror(errno));
        close(fd);
        return false;
    }

    char recvbuf[DEV_ID_LEN + 100] = {0};
    socklen_t addrlen = sizeof(addr);
    ret = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&addr, &addrlen);
    if (ret < 0) {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            PRINT_ERR_HEAD
            print_err("recvfrom timeout");
        } else {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s]", strerror(errno));
        }
        close(fd);
        return false;
    }
    close(fd);
    PRINT_INFO_HEAD
    print_info("peer devid replace from[%s] to [%s] successfully", recvbuf, devid);
    return true;
}

/**
 * [devid_sync 同步设备ID号线程函数]
 * @param  arg [暂未使用]
 * @return     [未使用]
 */
void *devid_sync(void *arg)
{
    char devid[DEV_ID_LEN] = {0};

    read_devid(devid, sizeof(devid));
    if (devid[0] != 0) {
        while (!devid_sync(devid)) {
            sleep(5);
            PRINT_INFO_HEAD
            print_info("devid sync try again[%s]", devid);
        }

    }

    PRINT_INFO_HEAD
    print_info("devid sync over[%s]", devid);
    return NULL;
}

/**
 * [StartDevIDSync 启动一个线程，负责把内网的设备ID号同步给外网]
 * @return  [成功返回true]
 */
bool StartDevIDSync(void)
{
    PRINT_INFO_HEAD
    print_info("create devid sync thread");

    pthread_t threadid;
    if (pthread_create(&threadid, NULL, devid_sync, NULL) != 0) {
        PRINT_ERR_HEAD
        print_err("create devid sync thread fail");
        return false;
    }
    return true;
}
