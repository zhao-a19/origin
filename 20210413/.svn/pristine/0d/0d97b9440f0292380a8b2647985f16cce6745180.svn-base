/*******************************************************************************************
*文件: checkfilevir.cpp
*描述: 查毒测试程序
*作者: 王君雷
*日期:
*修改:
*******************************************************************************************/
#include <stdio.h>
#include "FCVirusAPI.h"
#include "debugout.h"

loghandle glog_p = NULL;

int main(int argc, char **argv)
{
    _log_init_(glog_p, checkfilevir);

    if (argc != 2) {
        printf("Usage: %s filename(absolute path)\n", argv[0]);
        return 2;
    }
    char virusname[1024] = {0};
    int ret = FileSearchVirus(argv[1], C_FILE_NOCODE, virusname);
    if (ret == E_FINDED_VIRUS) {
        printf("find virus:%s\n", virusname);
    } else if (ret == E_OK) {
        printf("no virus\n");
    } else {
        printf("check fail\n");
    }
    return 0;
}
