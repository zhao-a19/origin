/*******************************************************************************************
*文件:  nic.h
*描述:  网卡相关操作
*作者:  王君雷
*日期:  2020-06-22
*修改:
*******************************************************************************************/
#ifndef __NIC_H__
#define __NIC_H__

#include "datatype.h"

typedef struct SNDEVINFO {
    uint64 rbyte;
    uint64 rpkt;
    uint64 rerrs;
    uint64 rdrop;
    uint64 rfifo;
    uint64 rframe;
    uint64 rcompressed;
    uint64 multicast;
    uint64 sbyte;
    uint64 spkt;
    uint64 serrs;
    uint64 sdrop;
    uint64 sfifo;
    uint64 scolls;
    uint64 scarrier;
    uint64 scompressed;
} SNDEVINFO;

int GetNetICValue(char *dname, SNDEVINFO *cvalue);

#endif
