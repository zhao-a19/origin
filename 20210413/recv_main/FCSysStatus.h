/*******************************************************************************************
*文件:  FCSysStatus.h
*描述:  系统状态采集函数
*作者:  王君雷
*日期:  2016-03
*修改:
*       网卡吞吐量采集使用uint64类型，修改32位系统收发字节数超4G自动归零吞吐量计算错误
*       的BUG                                                             ------> 2018-09-27
*       获取系统状态线程移动到recvmain                                    ------> 2019-11-19-dzj
*       把GetNetICValue函数放入单独文件中                                 ------> 2020-06-22
*******************************************************************************************/
#ifndef __FC_SYSSTATUS_H__
#define __FC_SYSSTATUS_H__

#include "datatype.h"

//存储一个CPU断面信息
typedef struct CPU_INFO {
    float total;     //总CPU时间
    float user;      //用户CUP时间
    float nice;      //niceCPU时间
    float system;    //系统CPU时间
    float idle;      //空闲CPU时间
    float cpu_usage; //CPU使用率，不仅仅跟本结构体内的其他字段有关
} CPU_INFO;

typedef struct TNETFLOW {
    uint64 prevrbyte;    //上次采集时的收字节数
    uint64 prevsbyte;    //上次采集时的发字节数
    uint64 prevbps;      //上次采集计算得到的吞吐量
    time_t prevtm;       //上次采集时间
} TNETFLOW;

int StartGetSysStatus(void);

#endif
