/*******************************************************************************************
*文件:  struct_info.h
*描述:  结构定义
*作者:  王君雷
*日期:  2015
*修改:
*     添加FILE_HEAD_PCKT结构                                          ------> 2018-04-10
*     添加NIC_STATUS枚举类型                                          ------> 2018-08-29
*     添加汇报头部REPORT_HEAD,其他进程向hotbakmain汇报信息时使用      ------> 2018-11-22
*     NIC_MAC_STRUCT按1字节对齐                                       ------> 2018-11-23
*     添加NIC_REPORT_HEAD结构                                         ------> 2018-12-03
*******************************************************************************************/
#ifndef __STRUCT_INFO_H__
#define __STRUCT_INFO_H__

#include "critical.h"

/*
 * 内外网间传输协议
 * HEADER|length|data
 *
 * 描述：
 * HEADER：
    结构体类型
 * length
    unsigned int型，值为其自身及紧跟其后的所有字段长度之和
    length = FILE_END  (此时data部分长度为0)
            or FILE_BEGIN (此时data为：md5_str file_len file_name)
            or sizeof(length) + LEN(data)
 * data
    发送的数据 字符型
 */
//
//头部 传输协议的一部分
//
//为了兼容以前的版本，头部没做改动
//现在主要用appnum字段，其实命名为cmdtype更合适，表示内部传输命令的类型
//如:传输文件 传输日志等，在define.h中详细定义
//其他字段暂时保留，没有删除
//
typedef struct _header {
    int ipnum;//ip编号
    int rulenum;//规则编号
    int appnum;//应用编号
    int tomirror;//是否发送给mirror
} HEADER, *PHEADER;

enum NIC_STATUS {
    NIC_STATUS_ERR = 0,
    NIC_STATUS_OK
};

enum REPORT_TYPE {
    REPORT_NIC_STATUS = 200,
};

#pragma pack(push, 1)
//内外网发送文件会使用到该结构
typedef struct _file_head_pckt {
    unsigned char md5str[MD5_STR_LEN];
    int fsize;
    char fname[MAX_FILE_PATH_LEN];
} FILE_HEAD_PCKT, *PFILE_HEAD_PCKT;

//其他进程向hotbakmain汇报运行状态时使用的头部
typedef struct _report_head {
    REPORT_TYPE type;
    int len; //后续所有部分的长度 不包括本结构体的长度
} REPORT_HEAD, *PREPORT_HEAD;

typedef struct _nic_report_head {
    int status;
    int nicnum_in;
    int nicnum_out;
} NIC_REPORT_HEAD, *PNIC_REPORT_HEAD;

//向hotbakmain汇报网卡信息以及热备通知网卡信息 都会用到该结构
typedef struct _nic_mac_info {
    char ethname[8];
    char mac[32];
} NIC_MAC_STRUCT, *PNIC_MAC_STRUCT;
#pragma pack(pop)

#endif
