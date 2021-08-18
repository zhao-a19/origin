/*******************************************************************************************
*文件: define.h
*描述: 各种宏定义文件
*
*作者: 王君雷
*日期: 2015
*修改: 把路径配置、日志翻译、视频厂商信息移动到单独的文件里     ------> 2018-01-23
*      添加DELETE相关宏                                         ------> 2018-03-14
*      注释RUN_LOG相关宏;添加MD5_STR_LEN等宏                    ------> 2018-04-10
*      添加DEFAULT_MTU等宏定义                                  ------> 2018-05-16
*      通过makefile的参数,决定是内网还是外网,不再写死了;添加MY_CLOSE宏
*                                                               ------> 2018-08-01
*      添加宏BZERO、ARRAY_SIZE                                  ------> 2018-08-02
*      添加killall停止业务相关宏                                ------> 2018-08-28
*      磁盘空间告警阈值默认值修改为10                           ------> 2018-11-19
*      把与原始套接字通信有关的宏定义移出本文件                 ------> 2018-11-21
*      临界值相关宏移出本文件                                   ------> 2018-12-21
*      添加组装IPTABLES语句的宏                                 ------> 2019-02-16
*      stop停止业务时，把kill sys6的逻辑提前                    ------> 2019-02-28
*      通过宏可以指定是否启用授权检查                           ------> 2019-04-11
*      将SIP代码回滚开关放在编辑选项里                          ------> 2019-06-04
*      killall启停业务时考虑nginx进程                           ------> 2019-06-13
*      添加宏SUPPORT_WEBPROXY_USE_NGINX                         ------> 2019-06-19
*      把部分内容拆分到work_mode.h、gap_cmdtype.h、netinfo.h等文件中
*                                                               ------> 2019-06-25
*      V8支持使用nginx实现web代理功能                           ------> 2019-09-16
*      arm64_1043合并进工程                                    ------> 2020-05-15
*      重新约定SUOS_V，arm64对应1000，飞腾对应2000              ------> 2020-07-27
*      添加NOHUP_RUN宏                                         ------> 2020-09-20
*      WEB代理支持分模块生效，WEB代理强制使用nginx实现，tinyproxy彻底移除
*                                                              ------> 2020-11-18
*      添加是否支持看门狗功能宏                                  ------> 2021-03-10
*******************************************************************************************/
#ifndef __DEFINE_H__
#define __DEFINE_H__

#include "gap_config.h"
#include "video.h"
#include "log_translate.h"
#include "critical.h"
#include "stop_process.h"
#include "work_mode.h"
#include "gap_cmdtype.h"
#include "str_oper.h"
#include "netinfo.h"

#if (SIDE==100)
#define DEVFLAG        "I"
#elif (SIDE==200)
#define DEVFLAG        "O"
#else
//....
#endif

#if (SUOS_V==81)
#define MAX_IPTABLES_QUEUE_NUM 10 //最多使用多少个iptables的队列
#define USE_NFQUEUE_NETLINK
#define SUPPORT_IPV6 1
#define USE_LICENSE_CHECK 1
#define KERNVER "8.1"
#define SUPPORT_SPEACKER
#define NOHUP_RUN "busybox nohup"
#define SUPPORT_WATCHDOG

#elif (SUOS_V==1000)
#define MAX_IPTABLES_QUEUE_NUM 10
#define USE_NFQUEUE_NETLINK
#define SUPPORT_IPV6 1
#define USE_LICENSE_CHECK 1
#define KERNVER "arm64_8.1"
//#define SUPPORT_SPEACKER
#define NOHUP_RUN "busybox nohup"
//#define SUPPORT_WATCHDOG

#elif (SUOS_V==2000)
#define MAX_IPTABLES_QUEUE_NUM 10
#define USE_NFQUEUE_NETLINK
#define SUPPORT_IPV6 1
#define USE_LICENSE_CHECK 1
#define KERNVER "ft_8.1"
//#define SUPPORT_SPEACKER
#define NOHUP_RUN "nohup"
//#define SUPPORT_WATCHDOG

#elif (SUOS_V==8)
#define MAX_IPTABLES_QUEUE_NUM 1
#define USE_IPQUEUE_NETLINK
#define SUPPORT_IPV6 0
#define USE_LICENSE_CHECK 1
#define KERNVER "6"
#define SUPPORT_SPEACKER
#define NOHUP_RUN "busybox nohup"
//#define SUPPORT_WATCHDOG

#elif (SUOS_V==6)
#define MAX_IPTABLES_QUEUE_NUM 1
#define USE_IPQUEUE_NETLINK
#define SUPPORT_IPV6 0
#define USE_LICENSE_CHECK 0
#define KERNVER "6"
#define SUPPORT_SPEACKER
#define NOHUP_RUN "busybox nohup"
//#define SUPPORT_WATCHDOG

#else
//....
#endif

//SIP接口封装和针对厂家不同处理封装接口
#ifdef RESEAL_SIP
#define RESEAL_SIP_INTERFACE
#endif

#define DEFAULT_NET_TIME_CYCL 60
#define DEFAULT_BUFFALERT     10
#define PACKET_CHANGED        0x99
#define GET_SYS_STATUS_CYCLE  10 //采集系统状态信息的周期s

//消息确认的接收超时时间s
#define MSG_ACK_TIME_SEC   1

#define MOD_LICENSE_KEY       (0x4C) //模块授权时 异或加解密使用的字符
#define HEX_FLAG "16"                //对于TCP or UDP自定义模块 当配置的参数为16时 按十六进制来处理
#define DELTE_AFTER_SEND 2           //文件发送后删除
#define REMAIN_AFTER_SEND 1          //文件发送后保留

#define DELETE(P) if ((P) != NULL){delete (P); (P) = NULL;}
#define DELETE_N(P,n) for (int i = 0; i < (n); i++){DELETE((P)[i]);}
#define CLOSE(fd) if (fd > 0) {close(fd); fd = 0;}
#define FCLOSE(fd) if (fd != NULL){fclose(fd); fd = NULL;}
#define BZERO(ch) memset(&(ch), 0, sizeof(ch))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define ALL_OBJ(ip) (strncmp((ip), ALLIP, 7) == 0)
#define IPV6_ALL_OBJ(ip) (strcmp((ip), IPV6ALLIP)==0)

#endif
