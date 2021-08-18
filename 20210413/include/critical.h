/*******************************************************************************************
*文件:  critical.h
*描述:  临界值相关定义 主要是会影响空间分配大小的值
*作者:  王君雷
*日期:  2018-12-20
*修改:
*       IP_STR_LEN由32扩大到80，适应IPV6的情况                            ------> 2019-01-26
*       组播转发的数据包大小放大到65535，原来的太小，无法完整转发大数据包 ------> 2019-06-24
*       普通规则支持500;SMB文件交换支持200;业务IP支持500;多IP对应支持500
*       每侧支持的最大网卡个数由20改为64                                  ------> 2019-07-20
*       添加设备ID、hostname、设备类型缓存区长度宏                        ------> 2020-02-05
*       对象名称长度移动到本文件中                                        ------> 2020-02-07
*       内置数据库同步任务，最大支持200个，界面最大支持100，因为双向策略时
*       界面的一条对应后台的2条                                           ------> 2020-02-24
*       后台取消多规则数、多IP对应条数限制                                ------> 2020-07-03
*******************************************************************************************/
#ifndef __CRITICAL_H__
#define __CRITICAL_H__

#define MAX_BUSINESS_NUM 10          //最大业务数
//#define C_MAX_SYSRULE 500            //系统支持最大规则数
#define C_MUTICAST_MAXNUM 200        //系统支持组播任务数 20140901
#define C_FILESYNC_MAXNUM 200        //系统文件同步任务数 20141104
#define C_DBSYNC_MAXNUM (2*100)      //系统内置的数据库同步功能最多支持的任务数 20160527
#define C_BONDING_IP_MAXNUM 500      //每个bond网卡上可设置的最多IP数
#define C_BONDING_DEV_MAXNUM 10      //每个bond网卡上可设置的最多设备数
#define C_WEB_PROXY_MAXNUM 20        //系统支持WEB代理任务数
#define C_OBJECT_MAXNUM 500          //对象数
#define C_SERVICE_MAXNUM 500         //应用数
#define C_APPSINGLE_MAXNUM 500       //应用对象数
#define C_NETWAY_MAXNUM 100          //安全通道数
#define C_MAX_CMD 200                //命令数
#define C_MAX_LINE_BUF (1024 * 1024) //配置文件一行内容最长字节数
#define C_MAX_NETWORKNAME 32         //用于WEB展示的接口名称字符串最大长度 如:MAN、 HA等
#define C_MAX_FILTERFILETYPE_LEN 512 //过滤文件类型填写的列表 最大长度
#define APP_NAME_LEN 100             //WEB界面为每个应用起的名字的最大支持长度
#define TRANSPORT_PROTO_LEN 20       //传输层协议字符串最大长度 TCP、UDP等
#define APP_MODEL_LEN 32             //应用层所属模块长度   HTTP等
#define MAX_CMD_NAME_LEN 128         //命令名称最大支持长度  GET
#define MAX_PARA_NAME_LEN 128        //命令的参数最大支持长度 sina.com
#define AUTH_NAME_LEN 100            //认证用户名称长度

#define MULTICAST_MAX_LEN 65535
#define MULTICAST_MAX_SRC_NUM 20
#define MULTICAST_RULE_NAME_LEN 100

#define PDT_RULE_NAME_LEN 100
#define PDT_COMMON_RULE_NUM     100   //规则最大支持数

#define MAX_IPNUM 500
#define MAX_RTNUM 2000
#define MAX_SPINNER_ROUTE_LIST 100
//#define MAX_DIPNUM 500
#define MAX_BIND_MAC 300
#define MAX_PHONE_NUMBER 16

#define SNMP_COMM_LEN 32
#define MAX_ROUTE_STR_LEN 500

#define CMD_BUF_LEN 1024             //组命令时缓冲区大小
#define SYSLOG_BUF_LEN 1024          //组系统日志时缓冲区大小
#define PORT_STR_LEN 20
#define IP_STR_LEN 80
#define MASK_STR_LEN 16
#define MD5_STR_LEN 32
#define MAC_STR_LEN 20
#define RULE_NAME_LEN 500

#define MAX_BUF_LEN           4000 //最大缓冲区长度
#define MAX_NIC_NUM           64   //最大网卡数
#define MAX_FILTER_KEY_LEN    90   //审查关键字长度最大值
#define MAX_FILE_PATH_LEN     256  //文件存放路径最大长度
#define MAX_SQL_LEN           1024 //sql语句最大长度

#define DEV_ID_LEN 100   //存放设备ID号缓冲区长度
#define HOST_NAME_LEN 64 //存放hostname缓冲区长度
#define DEV_TYPE_LEN 64  //存放设备类型缓冲区长度

#define OBJ_NAME_LEN 100 //对象名称的最大长度

#endif
