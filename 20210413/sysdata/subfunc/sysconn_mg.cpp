/*******************************************************************************************
*文件:  sysconn_mg.cpp
*描述:  系统并发数管理
*作者:  王君雷
*日期:  2020-10-28
*修改:
*******************************************************************************************/
#include "sysconn_mg.h"
#include "debugout.h"
#include "define.h"
#include "readcfg.h"
#include "fileoperator.h"

/**
 * [SetSysMaxConn 设置并发数]
 * @param maxconn [最大并发数]
 */
void SetSysMaxConn(int maxconn)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (maxconn > SYS_MAX_CONN_HIGH) {
        PRINT_INFO_HEAD
        print_info("sysmaxconn too big [%d],set to [%d]", maxconn, SYS_MAX_CONN_HIGH);
        maxconn = SYS_MAX_CONN_HIGH;
    } else if ((maxconn > 0) && (maxconn < SYS_MAX_CONN_LOW)) {
        PRINT_INFO_HEAD
        print_info("sysmaxconn too small [%d],set to [%d]", maxconn, SYS_MAX_CONN_LOW);
        maxconn = SYS_MAX_CONN_LOW;
    } else if (maxconn <= 0) {
        maxconn = SYS_MAX_CONN_DEFAULT;
    }

    //设置系统最大并发数时允许设置的值不应该小于SYS_MAX_CONN_LOW
    sprintf(chcmd, "echo %d > /proc/sys/net/nf_conntrack_max", maxconn);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("[%s]", chcmd);
}

/**
 * [ReadMaxConn 读取最大连接数设置]
 * @return  [最大连接数]
 */
int ReadMaxConn(void)
{
    int maxconn = -1;
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSSET_CONF);
        return maxconn;
    }
    READ_INT(fileop, "SYSTEM", "SYSMaxConn", maxconn, false, _out);

_out:
    fileop.CloseFile();
    return maxconn;
}

/**
 * [SetSysMaxConn 设置系统并发数]
 */
void SetSysMaxConn(void)
{
    int maxconn = ReadMaxConn();
    SetSysMaxConn(maxconn);
}
