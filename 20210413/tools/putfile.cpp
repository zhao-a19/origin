/*******************************************************************************************
*文件: putfile.cpp
*描述: 把文件放到对端指定目录下
*
*作者: 王君雷
*日期: 2019-03-20
*修改:
*       先按TCP传输，若失败再按UDP传输                                  ------> 2020-02-25
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "define.h"
#include "fileoperator.h"
#include "debugout.h"
#include "FCSendFileUdp.h"
#include "sendfiletcp.h"

loghandle glog_p = NULL;
int g_linklanipseg = 0;
int g_linklanport = 0;
int g_linktcpfileport = 0;

int readlinkinfo(void)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        printf("openfile %s error\n", SYSINFO_CONF);
        return -1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", &g_linklanipseg);
    if (g_linklanipseg < 1 || g_linklanipseg > 255) {
        g_linklanipseg = 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanPort", &g_linklanport);
    if (g_linklanport < 1 || g_linklanport > 65535) {
        g_linklanport = DEFAULT_LINK_PORT;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkTCPFilePort", &g_linktcpfileport);
    if ((g_linktcpfileport < 1) || (g_linktcpfileport > 65535)) {
        g_linktcpfileport = DEFAULT_LINK_TCP_FILE_PORT;
    }
    m_fileop.CloseFile();
    return 0;
}

#define VERSION_DATE "2020-02-25"

int main(int argc, char **argv)
{
    _log_init_(glog_p, putfile);

    if (argc != 3) {
        printf("\nUsage(%s):\n\t%s localfile dstfile\n\n", VERSION_DATE, argv[0]);
        return -1;
    }

    //检查文件名
    if ((argv[1][0] != '/') || (argv[2][0] != '/')) {
        printf("Please input ABSOLUTE filename!\n");
        return -1;
    }

    readlinkinfo();

    if ((send_file_tcp(argv[1], argv[2], 0) == 0)
        || (send_file_udp(argv[1], argv[2], 5) == 0)) {
        PRINT_DBG_HEAD
        print_dbg("putfile ok. src[%s] dst[%s]", argv[1], argv[2]);
        return 0;
    }
    return -1;
}
