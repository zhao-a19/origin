/*******************************************************************************************
*文件:  localip.cpp
*描述:  输入目的IP 输出本地使用的IP
*作者:  王君雷
*日期:  2019-12-17
*修改:
*******************************************************************************************/
#include <stdio.h>
#include "localip_api.h"
#include "debugout.h"
#include "define.h"

#define DATE "2019-12-18"
loghandle glog_p = NULL;

int g_linklanipseg = 1;
int g_linklanport = 59876;

int main(int argc, char **argv)
{
    _log_init_(glog_p, localip);

    if (argc != 2) {
        printf("Usage(%s): %s dstip\n", DATE, argv[0]);
        return -1;
    }

    char output[IP_STR_LEN] = {0};
    if (get_localip(argv[1], output, sizeof(output)) == 0) {
        printf("LOCALIP:%s\n", output);
    }
    return 0;
}
