
/*******************************************************************************************
*文件:  sendfiletcp.cpp
*描述:  TCP方式发送文件接口
*作者:  王君雷
*日期:  2020-02-24
*修改:
*       TCP文件上传客户端 改用transfer程序                               ------> 2020-03-10
*       修改调用transfer时没有加-C参数的错误                             ------> 2020-03-11
*******************************************************************************************/
#include <stdio.h>
#include "define.h"
#include "debugout.h"
#include "common.h"

extern int g_linklanipseg;
extern int g_linktcpfileport;

/**
 * [send_file_tcp TCP方式发送文件接口]
 * @param  srcfile [源文件]
 * @param  dstfile [目的文件]
 * @param  perm    [权限]
 * @param  mode    [模式 0为一步 1为同步]
 * @return         [成功返回0]
 */
int send_file_tcp(const char *srcfile, const char *dstfile, int perm, int mode)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char outbuf[CMD_BUF_LEN] = {0};
    time_t t1, t2;

    CCommon common;
    sprintf(chcmd, "%s -C -a %d.0.0.%d -p %d -s %s -d %s -P %d -m %d", TRANSFER_FILE, g_linklanipseg, (DEVFLAG[0] == 'I') ? 253 : 254,
            g_linktcpfileport, srcfile, dstfile, perm, mode);
    t1 = time(NULL);
    if (common.Sysinfo(chcmd, outbuf, sizeof(outbuf)) == NULL) {
        PRINT_ERR_HEAD
        print_err("sysinfo[%s] fail", chcmd);
        return -1;
    }
    t2 = time(NULL);
    if (strstr(outbuf, "Success") == NULL) {
        PRINT_ERR_HEAD
        print_err("outbuf[%s],send file tcp fail", outbuf);
        return -1;
    }

    PRINT_INFO_HEAD
    print_info("send file tcp success[%s] use[%d]s", dstfile, t2 - t1);
    return 0;
}
