/*******************************************************************************************
*文件: sendsig.cpp
*描述: 发送信号程序  通过向对端发送不同的信号，实现设备重启、设备初始化等功能
*
*作者: 王君雷
*日期: 2015
*修改:
*      把程序中使用到目录的地方，都改用宏。V8系统进行了目录规划，
*      通过宏控制，实现读取不同的目录。改用linux风格，utf8编码       ------> 2018-04-23
*      屏幕输出避免出现汉字,引入zlog                                 ------> 2018-08-15
*      初始化时自动创建last目录，兼容目录不存在的情况                ------> 2019-09-09
*      对于飞腾平台，初始化时touch重建error.log日志文件             ------> 2020-10-09
*      解决飞腾平台忘记创建var/log/mysql/目录的问题                 ------> 2020-10-14
*      初始化时添加调用新的数据库同步恢复出厂设置脚本                ------> 2020-10-29
*      初始化时自动删除文件PREDBSYNC_BAK                           ------> 2021-03-30
*      按宋宇的需求，系统重启前先killall一下msync程序               ------> 2021-04-28
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "FCTimeToPeer.h"
#include "struct_info.h"
#include "define.h"
#include "FCMsgAck.h"
#include "fileoperator.h"
#include "debugout.h"

loghandle glog_p = NULL;

/**
 * [revert 还原配置文件]
 * @return [成功返回0]
 */
int revert()
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "mkdir -p %s", LAST_RULE_DIR);
    system(chcmd);

    //清空last目录
    sprintf(chcmd, "rm -rf %s*", LAST_RULE_DIR);
    system(chcmd);

    //把当前的备份到last
    sprintf(chcmd, "mv %s* %s", RULES_DIR, LAST_RULE_DIR);
    system(chcmd);
    sprintf(chcmd, "mv %s %s", HTTPD_SSL_CONF, LAST_RULE_DIR);
    system(chcmd);

    //恢复最初的文件
    sprintf(chcmd, "cp -rf %sconf/ %s", ORIGINAL_DIR, RULES_DIR);
    system(chcmd);
    sprintf(chcmd, "cp -rf %sprecfg/ %s", ORIGINAL_DIR, RULES_DIR);
    system(chcmd);
    sprintf(chcmd, "cp -rf %sauth/ %s", ORIGINAL_DIR, RULES_DIR);
    system(chcmd);

    sprintf(chcmd, "cp -f %s %s", ORIGINAL_NORMAL_HTTPD_SSL_CONF, NORMAL_HTTPD_SSL_CONF);
    system(chcmd);
    sprintf(chcmd, "cp -f %s %s", ORIGINAL_NORMAL_HTTPD_SSL_CONF, HTTPD_SSL_CONF);
    system(chcmd);
    system("sync");
    return 0;
}

/**
 * [revert 还原配置文件 内置测试版]
 * @return [成功返回0]
 */
int revert_test()
{
    char chcmd[CMD_BUF_LEN] = {0};
    //清空last目录
    sprintf(chcmd, "rm -rf %s*", LAST_RULE_DIR);
    system(chcmd);

    //把当前的备份到last
    sprintf(chcmd, "mv %s* %s", RULES_DIR_TEST, LAST_RULE_DIR);
    system(chcmd);
    sprintf(chcmd, "mv %s %s", HTTPD_SSL_CONF, LAST_RULE_DIR);
    system(chcmd);

    //恢复最初的文件
    sprintf(chcmd, "cp -rf %sconf/ %s", ORIGINAL_TEST_DIR, RULES_DIR_TEST);
    system(chcmd);
    sprintf(chcmd, "cp -rf %sprecfg/ %s", ORIGINAL_TEST_DIR, RULES_DIR_TEST);
    system(chcmd);
    sprintf(chcmd, "cp -rf %sauth/ %s", ORIGINAL_TEST_DIR, RULES_DIR_TEST);
    system(chcmd);

    sprintf(chcmd, "cp -f %s %s", ORIGINAL_TEST_HTTPD_SSL_CONF, TEST_HTTPD_SSL_CONF);
    system(chcmd);
    sprintf(chcmd, "cp -f %s %s", ORIGINAL_TEST_HTTPD_SSL_CONF, HTTPD_SSL_CONF);
    system(chcmd);
    system("sync");
    return 0;
}

/**
 * [readversion 读取版本信息]
 * @param  ver  [版本]
 * @param  size [缓冲区大小]
 * @return      [成功返回0]
 */
int readversion(char *ver, int size)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(START_CF, "r") == E_FILE_FALSE) {
        return -1;
    }
    m_fileop.ReadCfgFile("SYSTEM", "Version", ver, size);
    m_fileop.CloseFile();
    return 0;
}

/**
 * [readlinkseg 读取内部通讯地址段]
 * @return [返回地址段]
 */
int readlinkseg()
{
    int seg = 1;
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        return 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", &seg);
    m_fileop.CloseFile();

    if (seg < 1 || seg > 255) {
        seg = 1;
    }

    return seg;
}

/**
 * [readlinkport 读取内部通讯端口]
 * @return [端口号]
 */
int readlinkport()
{
    int port = DEFAULT_LINK_PORT;
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        return 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanPort", &port);
    m_fileop.CloseFile();

    if (port < 1 || port > 65535) {
        port = DEFAULT_LINK_PORT;
    }

    return port;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage:%s num\n", argv[0]);
        printf("1.initsys 2.restart 3.synctime 4.gettime\n");
        exit(-1);
    }

    _log_init_(glog_p, sendsig);

    HEADER header;
    char send_buf[256] = {0};
    char version[32] = {0};
    struct sockaddr_in addrts;
    struct sockaddr_in addr;
    BZERO(header);
    BZERO(addrts);
    BZERO(addr);

    int ipseg = readlinkseg();
    int port = readlinkport();

    //组装要发送的消息类型
    switch (atoi(argv[1])) {
    case 1:
        header.appnum = SYS_INIT_TYPE;
        break;
    case 2:
        header.appnum = DEV_RESTART_TYPE;
        break;
    case 3:
        time_to_peer(ipseg, port);
        return 0;
    case 4:
        header.appnum = GET_TIME_TYPE;
        break;
    default:
        printf("Input Error!\n");
        return -1;
    }

    //socket
    int fdts = socket(AF_INET, SOCK_DGRAM, 0);
    if (fdts < 0) {
        perror("socket");
        return 0;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        close(fdts);
        return 0;
    }

    //读取当前版本 anmit or test
    readversion(version, sizeof(version));

    //test
    addrts.sin_family = AF_INET;
    addrts.sin_port = htons(ANMIT_TEST_LINK_PORT);
    int ret = inet_pton(AF_INET, "1.0.0.253", (void *)&addrts.sin_addr);
    if (ret <= 0) {
        perror("inet_pton");
        close(fdts);
        close(fd);
        return -1;
    }

    //normal
    char ip[16] = {0};
    sprintf(ip, "%d.0.0.253", ipseg);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if (ret <= 0) {
        perror("inet_pton");
        close(fdts);
        close(fd);
        return -1;
    }

    //按协议组消息
    unsigned int length = sizeof(length);
    memcpy(send_buf, &header, sizeof(header));
    memcpy(send_buf + sizeof(header), &length, sizeof(length));

    sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addrts, sizeof(addrts));
    sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addrts, sizeof(addrts));
    sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addrts, sizeof(addrts));

    sendto(fdts, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
    sendto(fdts, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
    sendto(fdts, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));

    if (header.appnum == SYS_INIT_TYPE) {
        printf("system init!!!\n");
        system("killall sys6 msync >/dev/null 2>&1 ");
        system("killall sys6_test >/dev/null 2>&1 ");
        system("rm -rf /var/log/*");
        char chcmd[1024] = {0};
        sprintf(chcmd, "chmod +x %s", NEW_DBSYNC_CLEAR);
        system(chcmd);
        system(NEW_DBSYNC_CLEAR);
        unlink(PREDBSYNC_BAK);
#if (SUOS_V==2000)
        system("mkdir -p /var/log/mysql/");
        system("touch /var/log/mysql/error.log");
        system("chown -R mysql:mysql /var/log/mysql/error.log");
        PRINT_INFO_HEAD
        print_info("ft os touch mysql error.log");
#endif
        if (strncmp(version, "test", 4) == 0) {
            revert_test();
        } else {
            revert();
        }
        sleep(5);
        system("reboot");
    } else if (header.appnum == DEV_RESTART_TYPE) {
        printf("system restart!!!\n");
        system("killall msync >/dev/null 2>&1");
        sleep(5);
        system("reboot");
    }

    close(fdts);
    close(fd);
    return 0;
}
