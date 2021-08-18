/*******************************************************************************************
*文件:  FCMacInfo.cpp
*描述:  把网口的mac信息写入文件mac.info,供WEB展示读取
*作者:  王君雷
*日期:  2016-04-11
*修改:
*       mac.info文件INTERFACE 和OUTERFACE 都用大写字母               ------> 2016-04-19
*       线程ID使用pthread_t类型                                      ------> 2018-08-07
*       使用zlog;使用hardinfo.cpp中的获取mac信息函数                 ------> 2018-09-09
*       可以设置线程名称                                            ------> 2021-02-23
*******************************************************************************************/
#include "FCMacInfo.h"
#include "define.h"
#include "fileoperator.h"
#include "hardinfo.h"
#include "simple.h"
#include "debugout.h"
#include <stdlib.h>
#include <string.h>

/**
 * [GetMacInfo 收集内外网网口MAC线程函数]
 * @param  arg [description]
 * @return     [description]
 */
void *GetMacInfo(void *arg)
{
    pthread_setself("getmac");
    PRINT_INFO_HEAD
    print_info("collect mac begin");

    int innet_num = 0;
    int outnet_num = 0;
    char innet_mac[MAX_NIC_NUM][20];
    char outnet_mac[MAX_NIC_NUM][20];
    char chlan[20] = {0};
    CFILEOP fileop;
    BZERO(innet_mac);
    BZERO(outnet_mac);

    //打开文件
    if (fileop.OpenFile(SYSINFO_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SYSINFO_CONF);
        return NULL;
    }

    //读取网口数目
    fileop.ReadCfgFileInt("SYSTEM", "InterfaceNum", &innet_num);
    innet_num = MIN(MAX_NIC_NUM, innet_num);
    fileop.ReadCfgFileInt("SYSTEM", "OuterfaceNum", &outnet_num);
    outnet_num = MIN(MAX_NIC_NUM, outnet_num);
    fileop.CloseFile();

    //读取内网网卡mac
    for (int i = 0; i < innet_num; i++) {
        while (!get_mac(i, innet_mac[i])) {
            printf("INTERFACE[eth%d]get_mac ... retry\n", i);
            sleep(1);
        }
    }

    //读取外网网卡mac
    for (int i = 0; i < outnet_num; i++) {
        while (!get_out_mac(i, outnet_mac[i])) {
            printf("OUTERFACE[eth%d]get_out_mac ... retry\n", i);
            sleep(1);
        }
    }

    //打开mac.info文件 没有就创建
    if (fileop.OpenFile(MAC_INFO_FILE, "w+") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("open file err[%s]", MAC_INFO_FILE);
        return NULL;
    }

    //写入内网mac信息
    for (int i = 0; i < innet_num; i++) {
        sprintf(chlan , "INTERFACE%d", i);
        fileop.WriteCfgFile(chlan, "MAC", innet_mac[i]);

        PRINT_INFO_HEAD
        print_info("%s %s", chlan, innet_mac[i]);
    }

    //写入外网mac信息
    for (int i = 0; i < outnet_num; i++) {
        sprintf(chlan , "OUTERFACE%d", i);
        fileop.WriteCfgFile(chlan, "MAC", outnet_mac[i]);

        PRINT_INFO_HEAD
        print_info("%s %s", chlan, outnet_mac[i]);
    }

    //关闭文件
    fileop.CloseFile();

    PRINT_INFO_HEAD
    print_info("collect mac over");
    return NULL;
}

/**
 * [StartMacInfo 开启收集内外网网口MAC的线程]
 * @return [成功返回true]
 */
bool StartMacInfo()
{
    PRINT_INFO_HEAD
    print_info("create get mac info thread");

    pthread_t threadid;
    if (pthread_create(&threadid, NULL, GetMacInfo, NULL) != 0) {
        return false;
    }
    return true;
}
