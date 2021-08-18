/*****************************************************************************
*                                                                            *
*  Copyright (C) 2014 www.anmit.com All rights reserved.                     *
*                                                                            *
*  @file     protocol_define                                                 *
*  @brief    协议定义文件                                                      *
*  Details.                                                                  *
*                                                                            *
*  @author   yumm                                                            *
*  @email    yumm@anmit.com                                                  *
*  @version  0.1                                                             *
*  @date     2017/10/24                                                      *
*                                                                            *
*----------------------------------------------------------------------------*
*  Remark         : Description                                              *
*----------------------------------------------------------------------------*
*  Change History :                                                          *
*  <Date>     | <Version> | <Author>       | <Description>                   *
*----------------------------------------------------------------------------*
*  2017/10/24 | 0.1.0     | 于明明          | 添加注释                         *
*----------------------------------------------------------------------------*
*                                                                            *
*****************************************************************************/


//
// Created by yumm on 2017/10/24.
//

#ifndef DPDK_FIREWALL_PROTOCOL_DEFINE_H
#define DPDK_FIREWALL_PROTOCOL_DEFINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "epan/etypes.h"
#include "glib.h"


#define PROTOCOL_KEY_MAX_NUMBER 30

enum {
    PROTOCOL_FLAG_BIGENDIAN = 1 << 0,       //抓取的数据类型为大端，需要进行转换
    PROTOCOL_FLAG_FROM_SHOW = 1 << 1,       //从show属性中获取值，适用于MMS协议
    PROTOCOL_FLAG_TWO_WAY   = 1 << 2,       //双向解析
    PROTOCOL_FLAG_MASTER    = 1 << 3,       //OPC还需要开启逆向端口
};

typedef enum {
    RULES_FILTER_MATCH,
    RULES_FILTER_NOMATCH,
    RULES_FILTER_NODATA,
    RULES_FILTER_NO_PROTOCOL_DATA,
    RULES_FILTER_UNKNOWN,
} rules_filter_ack_t;

struct su_protocol_define_t {
    const char *name;                           //协议名称
    int         level;                          //协议在wireshark以太网帧中的层次
    uint16_t    port;                           //以太网帧的端口号
    uint16_t    flag;                           //协议解析标志位
    const char *keys[PROTOCOL_KEY_MAX_NUMBER];  //解析协议中的关键字段
    GHashTable *key_map;                        //NULL
};

struct mac_hdr_t {
    uint8_t src_mac[6];     //6字节-源MAC地址
    uint8_t dst_mac[6];     //6字节-目的MAC地址
    uint16_t l2_protocol;   //2字节-类型
};


struct su_pkg_hdr_t {
    uint16_t l3_protocol;   //3层协议类型 TCP/UDP/ICMP
    uint8_t l4_protocol;    //4层协议类型 OPCUA/OPC/S7/FTP
    uint64_t src_mac;
    uint64_t dst_mac;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

int get_key_index(const struct su_protocol_define_t *protocol, const char *key);

#ifdef __cplusplus
}
#endif

#endif //DPDK_FIREWALL_PROTOCOL_DEFINE_H
