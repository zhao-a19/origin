/*******************************************************************************************
*文件:    sysfastq_s.h
*描述:    socket层的报头结构以及以及包的状态
*
*作者:    金美忠
*日期:    2019-01-03
*修改:    创建文件，提出公用信息                            ------>     2019-01-03
*
*
*
*******************************************************************************************/
#ifndef _SYSFASTQ_S_H
#define _SYSFASTQ_S_H
#include "datatype.h"


/**
 * 内外网数据包结构
 */
#pragma pack(push, 1)
//#pragma pack(1)   //gcc 3.x不支持
typedef struct {
    char head[12];
    uint8 ver;
    uint32 uid;
    uint16 protocol;
    int8 repeat;    //不再使用 2018-09-30
    uint32 size;
    int32 taskid_connect;
    uint64 pkg_num;
    struct {
        uint8 ctrl;
        //puint8 data;
    } data;
} susocketdata, *psusocketdata;
#pragma pack(pop)


enum {
    DATA_S = 0xF0,      //开始
    DATA_X = 0xF3,      //数据
    DATA_X_ACK = 0xF4,  //数据ACK
    DATA_E = 0xF6,      //结束
    DATA_R = 0xF7,      //重连

    DATA_TCP = 1,
    DATA_UDP,
    DATA_DB,
    DATA_DDB,
};

#endif