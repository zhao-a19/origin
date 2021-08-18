/*******************************************************************************************
*文件:  FCDevBS.h
*描述:  设备业务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       添加是否开启STP选项支持,路由列表兼容带双引号的情况     ------> 2017-12-04 王君雷
*       使用UTF8编码，linux风格，引入zlog,加入DPDK相关选项     ------> 2018-05-16
*       支持SSH管理设备                                        ------> 2018-11-01
*       磁盘空间告警与检测线程移动到recvmain中                 ------> 2018-12-07
*       通过宏控制是否启用IPV6支持                             ------> 2019-02-12
*       代理对应结构中添加IP类型字段,IPV6支持做准备            ------> 2019-02-20
*       添加SNMP告警IP对IPV6的支持                             ------> 2019-06-14
*       添加配置项WebProxyUseNginx,可以选择是否使用nginx实现web代理  ------> 2019-06-19
*       通信口检查时，根据选项UpDownCard决定是否需要周期性up down网卡------> 2019-11-08
*       添加管理口路由字段                                           ------> 2019-11-19-dzj
*       添加读取代理模式下、同侧网口是否路由通选项，默认不联通           ------> 2020-06-11 wjl
*       去除多IP对应条数限制                                         ------> 2020-07-03 wjl
*       添加读取RuleNoticePort                                      ------> 2020-10-27
*       WEB代理支持分模块生效，废弃WebProxyUseNginx选项，强制使用nginx实现
*                                                                  ------> 2020-11-18
*       注释DPDK相关内容                                            ------> 2020-12-03
*       多IP对应结构体添加appnamemd5字段                             ------> 2021-05-07
*******************************************************************************************/
#ifndef __FC_DEV_BS_H__
#define __FC_DEV_BS_H__

#include "FCThread.h"
#include "FCSYSBS.h"
#include "fileoperator.h"
#include "define.h"
#include "srtlist.h"

typedef struct _sipinfo {
    int ID;
    int TYPE; //为1表示ipv6 其他表示ipv4
    char IP[IP_STR_LEN];
    char MASK[MASK_STR_LEN];
} SIPINFO, *PSIPINFO;

typedef struct _sdevinfo {
    SIPINFO myip[MAX_IPNUM];
    int myipnum;
    int rtnum;
    char rtlist[MAX_RTNUM][MAX_ROUTE_STR_LEN];
    int srtnum;
    SPINNERRLIST srtlist[MAX_SPINNER_ROUTE_LIST];
} SDEVINFO, *PSDEVINFO;

typedef struct _sdipinfo {
    char appname[APP_NAME_LEN];
    char appnamemd5[40];      //应用名称的MD5值
    char myip[IP_STR_LEN];   //代理IP
    char myser[PORT_STR_LEN];//代理端口
    int myiptype;            //代理IP类型 IPV4 or IPV6
    char dip[IP_STR_LEN];    //目的IP
    char dport[PORT_STR_LEN];//目的端口
    int diptype;             //目的IP类型 IPV4 or IPV6
} SDIPINFO, *PSDIPINFO;

typedef struct _bindmacinfo {
    int area;
    char ip[IP_STR_LEN];
    char mac[MAC_STR_LEN];
    int iptype;
} BINDMACINFO, *PBINDMACINFO;

//设备业务类
class CDEVBS: public CSYSBS
{
public:
    CDEVBS(void);
    virtual ~CDEVBS(void);

public:
    bool LoadData(void);
    bool Start(void);
    bool LoadDevConfig(void);
    bool LoadSysInfo(void);

    bool recordlog;               //记录日志标志
    bool ck_ids;                  //启用IDS标志
    bool ck_ddos;
    bool ck_otherprotocal;        //基于IP的其他协议支持，如OSPF、IGMP等  add by wjl 20170608
    bool ck_stp;                  //透明模式下是否开启STP add by wjl 20171204
    bool ck_ping;
    bool hidesrc;
    int m_mtu;
    char m_logserver[IP_STR_LEN]; //日志服务器
    int m_logserverport;
    int m_logtype;

    int m_workflag;                //工作模式
    int indipnum;
    int outdipnum;
    //SDIPINFO indipinfo[MAX_DIPNUM];
    //SDIPINFO outdipinfo[MAX_DIPNUM];
    SDIPINFO *indipinfo;
    SDIPINFO *outdipinfo;

    int m_linklan;                //网闸间通信使用的网口
    int m_linklanipseg;
    int m_linklanport;

    int m_noticeport;

    int m_cslan;                    //网闸管理口
    int m_csport;                   //管理口监听端口
    char m_csip[IP_STR_LEN];        //网闸管理口IP
    char m_csmask[MASK_STR_LEN];    //网闸管理口掩码
    char m_csgw[IP_STR_LEN];        //网闸管理口网关
    char m_mgclientip[IP_STR_LEN];  //管理者ip
    char m_mgclientmac[MAC_STR_LEN];//管理者mac

#if (SUPPORT_IPV6==1)
    char m_csipv6[IP_STR_LEN];
    char m_csipv6mask[MASK_STR_LEN];
    char m_csgwipv6[IP_STR_LEN];        //网闸管理口网关
    char m_mgclientipv6[IP_STR_LEN];
    char m_defgwipv6[IP_STR_LEN];      //默认网关IPV6
    char m_defdnsipv6[IP_STR_LEN];     //DNS IPV6
#endif

    bool m_cksshd;                 //是否开启ssh管理
    int m_sshdport;                //ssh服务端口

    int m_smsalert;                //是否开启手机短信报警
    char m_smsserverip[IP_STR_LEN];//短信平台服务器IP
    int m_smsserverport;           //短信平台服务器PORT
    char m_smsalertphone[MAX_PHONE_NUMBER]; //管理员手机号

    bool m_ckvirus;                //是否查病毒

    char m_defgw[IP_STR_LEN];      //默认网关
    char m_defdns[IP_STR_LEN];     //DNS

    bool m_ckauth;                 //是否启用认证
    int m_authport;                //客户端认证使用的端口

    int m_cklineswitch;
    int m_updowncard;

    bool ck_snmp;
    char m_snmpctrlip[IP_STR_LEN];
    char m_snmpcomm[SNMP_COMM_LEN];
#if (SUPPORT_IPV6==1)
    char m_snmpctrlipv6[IP_STR_LEN];
#endif

    bool m_ckweblogintx; //是否开启内网通信口管理功能
    bool m_ckmacbind;    //是否开启ip mac 绑定
    //bool m_cktrunk;    //是否支持TRUNK 20171114添加，20171115注释掉。共用ck_otherprotocal，不单独加选项了
    int m_macbindnum;
    BINDMACINFO m_macbind[MAX_BIND_MAC];

    int m_sysmaxflow;

    int m_portconnect;   //代理模式下 同侧网口是否可以路由通

    int interfacenum;
    int outerfacenum;
    char interface[MAX_NIC_NUM][C_MAX_NETWORKNAME];
    char outerface[MAX_NIC_NUM][C_MAX_NETWORKNAME];

    SDEVINFO m_innet;
    SDEVINFO m_outnet;
#if 0
#if (SUPPORT_DPDK==1)
    bool m_ckdpdk;            //是否启用dpdk
    int m_dpdklan;            //dpdk端口 在配置文件sysinfo中指定的
    int m_dpdk_dynamic_inlan; //dpdk内网动态端口
    int m_dpdk_dynamic_outlan;//dpdk外网动态端口
#endif
#endif
private:
    CFILEOP m_file;
};

#endif
