/*******************************************************************************************
*文件:  version_sync.c
*描述:  程序版本同步  内网调用该程序，可以把当前start.cf中配置的版本同步到外网
*协议:
*  HEADER|LEN|version_name
*  LEN 其自身长度以及紧随其后的部分的长度之和
*  version_name 为当前版本号(test or anmit)
*作者:  王君雷
*日期:
*修改:
*      完善注释信息                                                     ------> 20181109
*******************************************************************************************/
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include "fileoperator.h"
#include "define.h"
#include "struct_info.h"
#include "debugout.h"

loghandle glog_p = NULL;

/**
 * [readversion 读取版本信息]
 * @param  ver [版本 出参]
 * @param  len [版本缓冲区长度]
 * @return     [成功返回true]
 */
bool readversion(char *ver, int len)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(START_CF, "r") == E_FILE_FALSE) {
        return false;
    }
    m_fileop.ReadCfgFile("SYSTEM", "Version", ver, len);
    m_fileop.CloseFile();
    return true;
}

/**
 * [readlinkseg 读取内部通讯使用的网段]
 * @return [网段值]
 */
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

/**
 * [readlinkport 读取内部连接使用的端口号]
 * @return [端口号]
 */
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
    _log_init_(glog_p, version_sync);

    //读取程序版本
    char version[100] = {0};
    if (!readversion(version, sizeof(version))) {
        printf("readversion error!");
        return -1;
    }

    //按协议组装消息
    char sendbuf[MAX_BUF_LEN] = {0};
    unsigned int length = 0;
    HEADER header;
    memset(&header, 0, sizeof(header));

    header.appnum = VERSION_SYNC_TYPE;

    length = sizeof(length) + strlen(version);
    memcpy(sendbuf, &header, sizeof(header));
    memcpy(sendbuf + sizeof(header), &length, sizeof(length));
    memcpy(sendbuf + sizeof(header) + sizeof(length), version, strlen(version));

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("version_sync socket");
        return -1;
    }

    //填写地址结构
    struct sockaddr_in addr_test;
    struct sockaddr_in addr_anmit;
    memset(&addr_test, 0, sizeof(addr_test));
    memset(&addr_anmit, 0, sizeof(addr_anmit));

    addr_test.sin_family = AF_INET;
    addr_test.sin_port = htons(ANMIT_TEST_LINK_PORT);
    int ret = inet_pton(AF_INET, "1.0.0.253", (void *)&addr_test.sin_addr);
    if ( ret <= 0 ) {
        perror("version_sync inet_pton");
        close(fd);
        return -1;
    }

    char ip[16] = {0};
    sprintf(ip, "%d.0.0.253", readlinkseg());

    addr_anmit.sin_family = AF_INET;
    addr_anmit.sin_port = htons(readlinkport());
    ret = inet_pton(AF_INET, ip, (void *)&addr_anmit.sin_addr);
    if ( ret <= 0 ) {
        perror("version_sync inet_pton");
        close(fd);
        return -1;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //因为调用version_sync的时候 不知道是哪个版本 所以都发一次
    sendto( fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr_test, sizeof(addr_test));
    sendto( fd, sendbuf, sizeof(header) + length, 0, (struct sockaddr *)&addr_anmit, sizeof(addr_anmit));

    return 0;
}
