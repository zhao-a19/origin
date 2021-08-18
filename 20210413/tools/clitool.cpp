/*******************************************************************************************
*文件:    clitool.cpp
*描述:    用来生成key的工具 为了隐蔽取此名
*作者:    王君雷
*日期:    2016-04-15
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "FCKey.h"
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"

loghandle glog_p = NULL;

int readlinklan(int *plinklan)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        return -1;
    }

    if (m_fileop.ReadCfgFileInt("SYSTEM", "LinkLan", plinklan) == E_FILE_FALSE) {
        m_fileop.CloseFile();
        return -1;
    }
    m_fileop.CloseFile();
    return 0;
}

int main(int argc, char *argv[])
{
    _log_init_(glog_p, clitool);

    //尽快获取当前时间
    int t1 = time(NULL);
    int t2 = t1 - 1;
    int t3 = t1 - 2;

    //参数个数检查
    if ((argc != 2) || (strlen(argv[1]) != 32)) {
        //这里不要输出任何信息
        return -1;
    }

    int linklan = 0;
    if (readlinklan(&linklan) == 0) {
        //生成KEY对象
        KEY mykey(KEY_FILE, linklan);

        if (mykey.md5_ck(t1, argv[1]) || mykey.md5_ck(t2, argv[1]) || mykey.md5_ck(t3, argv[1])) {

            printf("para check pass!\n");

            if (mykey.build_key()) {
                printf("build OK!\n");
                PRINT_DBG_HEAD
                print_dbg("build key ok");
                return 0;
            } else {
                printf("build Err!\n");
                return -1;
            }
        }
    }

    return -1;
}
