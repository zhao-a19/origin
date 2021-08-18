/*******************************************************************************************
*文件:  start.c
*描述:  通知scancfg扫描配置文件
*作者:  赵子昂
*日期:
*修改:
*      创建文件                                      ------> 2020-10-22
*******************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "debugout.h"
#include "diffcfg.h"
#include "stringex.h"
#include "define.h"
#include <stdlib.h>

loghandle glog_p = NULL;
int main(int argc, char **argv)
{
    _log_init_(glog_p, start);

    PRINT_DBG_HEAD
    print_dbg("INFO: into start");

    pchar msg = "DEV-INIT";

    if (scan_client(msg, sizeof("DEV-INIT")) != 0) {
        PRINT_ERR_HEAD
        print_err("INFO: sendmsg DEV-INIT fail ");
        system("/etc/init.d/startall &");
    }

    _log_finish_(glog_p);

    return 0;
}
