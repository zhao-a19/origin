/*******************************************************************************************
*文件: auth_tool.cpp
*描述: 授权期限工具
*作者: 王君雷
*日期: 2018-09-10
*修改:
*      把获取硬件信息和导入授权功能拆分到多个文件里                       ------> 2018-09-19
*      对于使用CST时区的系统 签发时间做偏移                               ------> 2019-01-17
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "debugout.h"
#include "devinfo.h"
#include "authinfo.h"

loghandle glog_p = NULL;

#define CREATE_TIME "2019-01-17"

void usage(const char *name)
{
    printf("Usage(%s):\n\n\t%s getinfo mancardname outputfile\n\t%s syscer mancardname syscerfile\n\n",
           CREATE_TIME, name, name);
}

int main(int argc, char **argv)
{
    _log_init_(glog_p, auth_tool);

    if (argc < 4) {
        usage(argv[0]);
        return -1;
    }

    if ((strcmp(argv[1], "getinfo") == 0) && (argc == 4)) {
        if (!get_info(argv[2], argv[3])) {
            printf("get info error!\n");
            return -1;
        }
    } else if ((strcmp(argv[1], "syscer") == 0) && (argc == 4)) {
        if (!import_syscer(argv[2], argv[3])) {
            printf("import syscer error!\n");
            return -1;
        }
    } else {
        usage(argv[0]);
        return -1;
    }

    printf("success\n");
    return 0;
}
