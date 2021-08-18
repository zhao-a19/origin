/*******************************************************************************************
*文件:  netinfo.h
*描述:  网络信息相关宏定义
*
*作者:  王君雷
*日期:  2019-06-25
*修改:
*       添加DEFAULT_LINK_MASK、GETNUM1等宏                               ------> 2019-07-20
*       添加SYSLOG默认端口                                               ------> 2020-01-16
*       添加内部TCP传输文件使用的默认端口                                ------> 2020-02-25
*       添加内部模块规则变化通知TCP端口                                  ------> 2020-10-27
*       系统并发数控制相关宏移出本文件                                   ------> 2020-10-28
*******************************************************************************************/
#ifndef __NET_INFO_H__
#define __NET_INFO_H__

#define ANMIT_TEST_LINK_PORT  59876           //网闸内部通信使用的UDP端口
#define DEFAULT_LINK_PORT     59876
#define DEFAULT_LINK_TCP_FILE_PORT 59877      //内部传输文件TCP端口
#define DEFAULT_NOTICE_PORT        59878      //内部模块规则变化通知TCP端口
#define DEFAULT_LINK_MASK     "255.255.224.0" //网闸内部通信卡地址掩码
#define DEFAULT_MTU           1500
#define MAX_MTU               9000
#define DEFAULT_SYSLOG_PORT   514
#define DEFAULT_CSPORT        443
#define DEFAULT_CSMASK        "255.255.255.0"
#define DEFAULT_HOST          "localhost"
#define ANMIT_BOND_NO         99              //负载均衡 约定网卡号
#define DEFAULT_SYSLOG_PORT   514

#define IP_TYPE4 0
#define IP_TYPE6 1

#define INT_TO_CARDNAME(num, dev) if (num==ANMIT_BOND_NO){sprintf(dev,"bond0");}else{sprintf(dev, "eth%d",num);}

//num为第多少个IP 从1开始计数的。 计算内部通信IP时使用的宏
#define GETNUM1(num) (((num) - 1) / 100)
#define GETNUM2(num) (((num) - 1) % 100 + 1)
#define GETNUM3(num) (((num) - 1) % 100 + 101)

#endif
