/*******************************************************************************************
*文件:  gap_cmdtype.h
*描述:  网闸内外网主机间私有协议通信，使用的命令类型 相关宏定义
*
*作者:  王君雷
*日期:  2019-06-25
*修改:
*      添加 GET_LOCAL_IP_TYPE 类型                                   ------> 2019-12-19 wjl
*      添加 DEVID_SYNC_TYPE 类型                                     ------> 2020-02-14 wjl
*******************************************************************************************/
#ifndef __GAP_CMDTYPE_H__
#define __GAP_CMDTYPE_H__

#define FILE_TRANSFER_TYPE    2000//传输文件
#define LOG_INFO_TYPE         2100//传输日志
#define SYNC_TIME_TYPE        2200//同步时间
#define GET_TIME_TYPE         2201//要求同步时间
#define SYNC_MICRO_TIME_TYPE  2211//同步时间(微妙级别)
#define SYS_INIT_TYPE         2300//系统初始化
#define DEV_RESTART_TYPE      2400//设备重启
#define DEVID_SYNC_TYPE       2401//同步设备ID号
#define CMD_PROXY_TYPE        2500//命令代理 需返回详细结果信息
#define CMD_EXECUTE_TYPE      2501//命令执行 无需返回详细结果信息
#define VERSION_SYNC_TYPE     2600//版本同步
#define GET_FILE_TYPE         2700//请求发送文件
#define GET_OUT_MAC_TYPE      2800//请求外网MAC
#define GET_CARD_STATUS_TYPE  2805//获取网卡状态
#define GET_DPDK_STATUS_TYPE  2810//获取DPDK网卡状态
#define GET_LOCAL_IP_TYPE     2900//获取去往指定的IP时本地使用的IP

#endif
