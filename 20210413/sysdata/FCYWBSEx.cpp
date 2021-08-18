/*******************************************************************************************
*文件:  FCYWBSEx.cpp
*描述:  业务处理实现文件 扩展文件
*作者:  王君雷
*日期:  2018-01-22
*
*修改:
*        添加arping相关函数                                            ------> 2018-01-22
*        重写Start函数，缩减函数体                                     ------> 2018-02-05
*        修改BUG，代理模式和路由模式时CHAIN1默认ACCEPT插入位置不对     ------> 2018-02-26
*        修改BUG，CHAIN1默认ACCEPT在start最后插入                      ------> 2018-02-28
*        拆分缩小启动组播的函数                                        ------> 2018-03-04
*        视频相关函数命名统一风格                                      ------> 2018-04-23
*        添加执行irq.sh脚本的线程                                      ------> 2018-05-18
*        添加JudgeDPDK函数，为添加DPDK功能做准备                       ------> 2018-05-21
*        完成视频代理联动编码;程序重启后执行一下clean_track            ------> 2018-06-08
*        视频联动支持多个节点转发                                      ------> 2018-07-14
*        把外网发送日志到内网的线程、内网磁盘容量检查的线程移动到设置
*        规则之前，因为设置规则可能会耗费很长时间，这段时间它们不能停  ------> 2018-07-20
*        添加私有协议文件同步                                          ------> 2018-08-31
*        支持SSH管理设备                                               ------> 2018-11-01
*        解决180905引入的问题：检查安全通道接口失败时直接退出导致内外
*        网之间无法通信                                                ------> 2018-11-16
*        命令代理服务移出sys6                                          ------> 2018-11-28
*        磁盘空间告警与检测线程移动到recvmain中                        ------> 2018-12-07
*        去除ICMPMAP相关内容，因为使用不到了                           ------> 2018-12-27
*        修改透明模式组播方向控制不住的问题                            ------> 2019-01-02
*        启动规则时，负载均衡网卡上的IP也广播自己的mac                 ------> 2019-01-03
*        修改路由模式时，有一个方向的OPC数据没有进队列的BUG            ------> 2019-01-30
*        通过宏控制是否启用IPV6支持,开发过程版                         ------> 2019-02-12
*        修改透明模式对IPV6支持,开发过程版                             ------> 2019-02-16
*        修改路由模式对IPV6支持,开发过程版                             ------> 2019-02-19
*        修改代理模式自动代理对应对IPV6支持，开发过程版                ------> 2019-02-25
*        修改代理模式普通规则模块对IPV6支持，开发过程版                ------> 2019-02-26
*        私有文件交换支持ipv6                                          ------> 2019-06-05
*        组播支持IPV6                                                  ------> 2019-06-24
*        支持平台互联                                                  ------> 2019-07-31 -dzj
*        互联模块支持平台级联功能                                      ------> 2019-08-07 -dzj
*        调用clean_track提前，原来会sleep 10s以后才执行                ------> 2019-08-27
*        V6开启STP时不限制内部通信IP的ARP外发，其他版本时限制外发      ------> 2019-09-04
*        路由和代理模式支持指定出口IP                                  ------> 2019-11-07 -dzj
*        加入指定出口IP容错机制
*        ORCALE和RTSP支持指定出口IP                                    ------> 2019-11-08 -dzj
*        获取系统状态线程和外网同步日志线程移动到recvmain              ------> 2019-11-19-dzj
*        修改设置iptables规则为iptables-restore方式                    ------> 2019-12-01-dzj
*        变量名称拼写修改                                              ------> 2019-12-09-dzj
*        添加OPC需要开放端口的iptables                                 ------> 2019-12-18-dzj
*        解决代理模式手动代理对应46交叉访问，没有判断源对象跟代理IP
*        是否同类型的BUG                                               ------> 2020-01-19 wjl
*        检查视频互联策略配置的IP是否合法                              ------> 2020-02-13-dzj
*        解决StartSipInterConnectNorm函数少return的问题               ------> 2020-05-15
*        添加函数SetPortConnect，可设置代理模式同侧网口是否联通         ------> 2020-06-11 wjl
*        透明模式组播，放通IGMP协议                                   ------> 2020-06-16
*        注释掉StartDBSync的调用，系统使用的重构后的数据库同步          ------> 2020-08-17
*        添加对RFC3261平台互联任务的调用                              ------> 2020-08-19
*        判断重构后的数据库同步脚本是否存在，不存在则依旧按老的数据库同步处理，
*        可以自动兼容新旧数据库同步                                    ------> 2020-09-02
*        私有文件交换支持分模块生效                                    ------> 2020-11-05
*        组播支持分模块生效                                           ------> 2020-11-12
*        解决透明模式组播转发异常问题                                  ------> 2020-12-01
*        注释DPDK相关内容                                             ------> 2020-12-03
*        优化程序，应用模块只在必要时才进iptables队列                   ------> 2020-12-10
*        可以设置线程名称                                             ------> 2021-02-23
*        按质量例会要求，配OPC策略时不默认开放TCP445端口                ------> 2021-05-13
*******************************************************************************************/
#include "FCYWBS.h"
#include "video_mod.h"
#include "industry_mod.h"
#include "database_mod.h"
#include "common_mod.h"
#include "user_mod.h"
#include "debugout.h"

extern CardMG g_cardmg;

#define DIFF_IPTYPE_CONTINUE(pdobj,psobj) \
if (pdobj->m_iptype!=psobj->m_iptype){ \
    PRINT_INFO_HEAD \
    print_info("iptype diff.dobj[ip %s, type %d] sobj[ip %s,type %d].ignore it", \
              pdobj->m_ipaddress, pdobj->m_iptype, \
              psobj->m_ipaddress, psobj->m_iptype); \
    continue; \
}

#define NOT_IPV4_CONTINUE(pdobj) if (pdobj->m_iptype!=IP_TYPE4){continue;}
#define NOT_IPV6_CONTINUE(pdobj) if (pdobj->m_iptype!=IP_TYPE6){continue;}

#define NOT_IPV4_RETURN(pdobj) \
if (pdobj->m_iptype!=IP_TYPE4) { \
    PRINT_INFO_HEAD \
    print_info("iptype not ipv4.dobj[ip %s,type %d]", \
              pdobj->m_ipaddress, pdobj->m_iptype); \
    return; \
}

#define NOT_IPV6_RETURN(pdobj) \
if (pdobj->m_iptype!=IP_TYPE6) { \
    PRINT_INFO_HEAD \
    print_info("iptype not ipv6.dobj[ip %s,type %d]", \
              pdobj->m_ipaddress, pdobj->m_iptype); \
    return; \
}
//判断是否有指定出口IP
#define IS_SPEC_THE_EXPORT_IP(prule) (0 != prule->m_specsip[0])

//OPC需要自动开放的端口
static const OPC_PORT_T opc_port[] = {
    {"137:139", "udp"},
    {"1900", "udp"},
    //{"445", "tcp"}
};

/**
 * [CYWBS::StartArping 开启arping，更新邻居的arp缓存信息]
 */
void CYWBS::StartArping(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    if (m_arping_th == NULL) {
        m_arping_th = new CThread;
    }
    if (m_arping_th != NULL) {
        m_arping_th->ThCreate(ArpingProcess, (void *)this);
    } else {
        PRINT_ERR_HEAD;
        print_err("arping new thread fail");
    }
}

/**
 * [CYWBS::ArpingProcess arping线程函数]
 * @param  arg [CYWBS类型指针]
 * @return     [无特殊含义]
 */
void *CYWBS::ArpingProcess(void *arg)
{
    pthread_setname("arping");
    if (arg == NULL) {
        PRINT_ERR_HEAD;
        print_err("arping para null");
        return NULL;
    }

    CYWBS *pthis = (CYWBS *)arg;
    CDEVBS *pbs = pthis->m_devbs;

    if (s_b_inside) {
        for (int i = 0; i < pbs->m_innet.myipnum; i++) {
            if (pbs->m_innet.myip[i].TYPE != IP_TYPE6) {
                pthis->DoArping(pbs->m_innet.myip[i].ID, pbs->m_innet.myip[i].IP);
            }
        }
        sleep(5); //bond0协商需要几秒钟 执行太早没效果
        for (int i = 0; i < pthis->m_sysrulesbs->m_inbonding->ipnum; i++) {
            if (pthis->m_sysrulesbs->m_inbonding->iptype[i] != IP_TYPE6) {
                pthis->DoArping(ANMIT_BOND_NO, pthis->m_sysrulesbs->m_inbonding->ipaddr[i]);
            }
        }
    } else {
        for (int i = 0; i < pbs->m_outnet.myipnum; i++) {
            if (pbs->m_outnet.myip[i].TYPE != IP_TYPE6) {
                pthis->DoArping(pbs->m_outnet.myip[i].ID, pbs->m_outnet.myip[i].IP);
            }
        }
        sleep(5);
        for (int i = 0; i < pthis->m_sysrulesbs->m_outbonding->ipnum; i++) {
            if (pthis->m_sysrulesbs->m_outbonding->iptype[i] != IP_TYPE6) {
                pthis->DoArping(ANMIT_BOND_NO, pthis->m_sysrulesbs->m_outbonding->ipaddr[i]);
            }
        }
    }

    return NULL;
}

/**
 * [CYWBS::DoArping 根据输入的网卡号和IP，执行arping指令]
 * @param ethno [网卡号]
 * @param ip    [IP]
 */
void CYWBS::DoArping(int ethno, const char *ip)
{
    char chcmd[CMD_BUF_LEN] = {0};
    if (ANMIT_BOND_NO == ethno) {
        sprintf(chcmd, "arping -U '%s' -c 2 -I bond0 >/dev/null 2>&1", ip);
    } else {
        sprintf(chcmd, "arping -U '%s' -c 2 -I eth%d >/dev/null 2>&1", ip, ethno);
    }
    system_safe(chcmd);
}

/**
 * [CYWBS::GlobalAssign 全局变量赋值]
 */
void CYWBS::GlobalAssign(void)
{
    g_workflag = m_devbs->m_workflag;
    g_ckauth = m_devbs->m_ckauth;
    g_iflog = m_devbs->recordlog;
    g_syslog = (m_devbs->m_logtype == 1);
    g_linklan = m_devbs->m_linklan;
    g_linklanipseg = m_devbs->m_linklanipseg;
    g_linklanport = m_devbs->m_linklanport;
    g_noticeport = m_devbs->m_noticeport;
    strcpy(g_csip, m_devbs->m_csip);
}

/**
 * [CYWBS::CreateIptablesFile IPTABLES_RESTORE规则文件]
 * @return [成功返回0 失败返回负值]
 */
int CYWBS::CreateIptablesFile()
{
    m_rulemg_nat4.run();
    m_rulemg_nat6.run();
    m_rulemg_filter4.run();
    m_rulemg_filter6.run();
    m_rulemg_nat4.clear();
    m_rulemg_nat6.clear();
    m_rulemg_filter4.clear();
    m_rulemg_filter6.clear();
    return 0;
}

/**
 * [CYWBS::LicenseModInit 模块授权管理初始化]
 */
void CYWBS::LicenseModInit(void)
{
    m_plicensemod = new CLicenseMod(m_devbs->m_cslan);
    if (m_plicensemod->license_exist()) {
        //如果模块授权文件存在就读取之
        if (m_plicensemod->readfile()) {
            PRINT_DBG_HEAD;
            print_dbg("read file ok");
        } else {
            PRINT_ERR_HEAD;
            print_err("read file fail");
            m_plicensemod->set_right(MOD_TYPE_FILESYNC, 0);
            m_plicensemod->set_right(MOD_TYPE_DBSYNC, 0);
        }
        m_plicensemod->write_conf();

    } else {
        //如果模块授权文件不存在就创建之
        if (m_plicensemod->create_license()) {
            PRINT_DBG_HEAD;
            print_dbg("create license ok");
            m_plicensemod->write_conf();
        } else {
            PRINT_ERR_HEAD;
            print_err("create license fail");
        }
    }
}

/**
 * [CYWBS::TranAuthThread 启动向外网同步认证证书文件的线程]
 */
void CYWBS::TranAuthThread(void)
{
    char chsyslog[SYSLOG_BUF_LEN] = {0};

    int ret = StartTranAuth();
    if (ret < 0) {
        sprintf(chsyslog, "%s[%d]", LOG_CONTENT_CER_SYNC_ERR, ret);
        WriteSysLog(LOG_TYPE_CER_SYNC, D_FAIL, chsyslog);
        PRINT_ERR_HEAD;
        print_err("start tran auth thread fail");
    }
}

/**
 * [CYWBS::SysLogThread 启动Syslog发送线程]
 */
void CYWBS::SysLogThread(void)
{
#if 0
    char chsyslog[SYSLOG_BUF_LEN] = {0};

    if (m_devbs->m_logtype == 1) {
        int ret = StartSysLog(m_devbs->m_logserverport, m_devbs->m_logserver);
        if (ret < 0) {
            sprintf(chsyslog, "%s[%d]", LOG_CONTENT_SYSLOG_ERR, ret);
            WriteSysLog(LOG_TYPE_SYSLOG, D_FAIL, chsyslog);
            PRINT_ERR_HEAD;
            print_err("start syslog thread fail");
        }
    }
#endif
}

/**
 * [CYWBS::SMSThread 启动短信报警线程]
 */
void CYWBS::SMSThread(void)
{
    int ret = 0;
    char chsyslog[SYSLOG_BUF_LEN] = {0};

    if (m_devbs->m_smsalert == 1) {
        ret = StartSMS(m_devbs->m_smsserverip, m_devbs->m_smsserverport, m_devbs->m_smsalertphone);
        if (ret < 0) {
            sprintf(chsyslog, "%s[%d]", LOG_CONTENT_SMS_ERR, ret);
            WriteSysLog(LOG_TYPE_SMS, D_FAIL, chsyslog);
            PRINT_ERR_HEAD;
            print_err("start sms thread fail");
        }
    }
}

/**
 * [CYWBS::CreateBridge 创建网桥]
 */
void CYWBS::CreateBridge(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    SystemCMD("brctl addbr bb0");
    SystemCMD("brctl setfd bb0 0");
    sprintf(chcmd, "ifconfig eth%d up", m_devbs->m_linklan);
    SystemCMD(chcmd);
    sprintf(chcmd, "brctl addif bb0 eth%d", m_devbs->m_linklan);
    SystemCMD(chcmd);
}

/**
 * [CYWBS::BridgeAddif 把安全通道用到的网卡 添加到网桥上]
 */
void CYWBS::BridgeAddif(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int i = 0; i < g_cardmg.getTotal(); ++i) {
        MOD_CARD *pmod = g_cardmg.getMod(i);
        if (s_b_inside) {
            for (int j = 0; j < pmod->vec_in.size(); ++j) {
                if (ANMIT_BOND_NO == pmod->vec_in[j]) {
                    sprintf(chcmd, "brctl addif bb0 bond0");
                    SystemCMD(chcmd);
                } else {
                    sprintf(chcmd, "ifconfig eth%d up", pmod->vec_in[j]);
                    SystemCMD(chcmd);
                    sprintf(chcmd, "brctl addif bb0 eth%d", pmod->vec_in[j]);
                    SystemCMD(chcmd);
                }
            }
        } else {
            for (int j = 0; j < pmod->vec_out.size(); ++j) {
                if (ANMIT_BOND_NO == pmod->vec_out[j]) {
                    sprintf(chcmd, "brctl addif bb0 bond0");
                    SystemCMD(chcmd);
                } else {
                    sprintf(chcmd, "ifconfig eth%d up", pmod->vec_out[j]);
                    SystemCMD(chcmd);
                    sprintf(chcmd, "brctl addif bb0 eth%d", pmod->vec_out[j]);
                    SystemCMD(chcmd);
                }
            }
        }
    }
}

/**
 * [CYWBS::SetBridgeIP 给网桥bb0加地址]
 */
void CYWBS::SetBridgeIP(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpipv4[IP_STR_LEN] = {0};
    MakeV4NatIP(s_b_inside, g_linklanipseg, -1, tmpipv4, sizeof(tmpipv4));
    sprintf(chcmd, "ifconfig bb0 %s netmask %s up", tmpipv4, DEFAULT_LINK_MASK);
    SystemCMD(chcmd);
}

/**
 * [CYWBS::IsOPCServ 是否为OPC应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsOPCServ(CSERVICECONF *pserv)
{
    return (strcmp(pserv->m_asservice, "OPC") == 0);
}

/**
 * [CYWBS::IsTCPServ 是否为TCP应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsTCPServ(CSERVICECONF *pserv)
{
    return (strcasecmp(pserv->m_protocol, "TCP") == 0);
}

/**
 * [CYWBS::IsUDPServ 是否为UDP应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsUDPServ(CSERVICECONF *pserv)
{
    return (strcasecmp(pserv->m_protocol, "UDP") == 0);
}

/**
 * [CYWBS::IsICMPServ 是否为ICMP应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsICMPServ(CSERVICECONF *pserv)
{
    return (strcasecmp(pserv->m_protocol, "ICMP") == 0);
}

/**
 * [CYWBS::IsICMPV6Serv 是否为ICMPV6应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsICMPV6Serv(CSERVICECONF *pserv)
{
    return (strcasecmp(pserv->m_protocol, "ICMPV6") == 0);
}
/**
 * [CYWBS::SetTransparentTCPUDPSrcWhite 设置一条规则 透明模式 服务为TCP或UDP,靠近源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    AddIpPortMap("", "", pdobj->m_ipaddress, pserv->m_dport, "", pserv->m_name, pserv->m_protocol,
                 pdobj->m_iptype);

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        DIFF_IPTYPE_CONTINUE(pdobj, prule->m_sobject[j]);

        if ((!CreateApp(pserv)) && m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-A FORWARD %s %s %s %s --sport %s --dport %s %s %s -m state "
                    "--state NEW -j LOG --log-level 7 --log-prefix \"CALLLOG_%s \"\n",
                    BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), OccursString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, bipv6, false);
        }
        //----------------------------------源端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s %s --sport %s --dport %s %s %s -j %s\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol), tmpsport,
                tmpdport, TimeString(prule), OccursString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, bipv6, false);

        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s %s --dport %s "
                "--sport %s %s -j %s\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), ProtoString(pserv->m_protocol), tmpsport,
                tmpdport, TimeString(prule), MethodString(pserv, false));
        SystemIptablesRule(chcmd, bipv6, false);

        if (IsOPCServ(pserv)) {
            sprintf(chcmd, "-A FORWARD %s %s %s --sport %s --dport %s %s -j %s\n",
                    RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('s', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), MethodString(pserv, true));
            SystemIptablesRule(chcmd, bipv6, false);

            sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s %s --dport %s "
                    "--sport %s %s -j %s\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), MethodString(pserv, false));
            SystemIptablesRule(chcmd, bipv6, false);

            AddIpPortMap("", "", prule->m_sobject[j]->m_ipaddress, pserv->m_dport, "",
                         pserv->m_name, pserv->m_protocol, pdobj->m_iptype);
        }//IsOPCServ
    }//m_sobjectnum
    if (IsOPCServ(pserv)) {
        //OPC同时需要自动开放的端口
        for (int i = 0; i < (int)(sizeof(opc_port) / sizeof(opc_port[0])); i++) {
            //按目的端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, tmpsport, opc_port[i].port, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

            //按源端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, opc_port[i].port, tmpsport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

        }
    }//IsOPCServ
}

/**
 * [CYWBS::SetTransparentTCPUDPSrcBlack 设置一条规则 透明模式 服务为TCP或UDP,靠近源对象的一侧
 * 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        DIFF_IPTYPE_CONTINUE(pdobj, prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-I FORWARD %s %s %s %s --sport %s --dport %s %s -j DROP\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol), tmpsport,
                tmpdport, TimeString(prule));
        SystemIptablesRule(chcmd, bipv6, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD %s %s %s %s --sport %s --dport %s %s "
                    "-j LOG --log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                    BridgeString(prule),
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, bipv6, false);
        }
    }//m_sobjectnum
}

/**
 * [CYWBS::SetTransparentTCPUDPSrc 设置一条规则 透明模式 服务为TCP或UDP,靠近源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentTCPUDPSrcWhite(prule, pdobj, pserv);
    } else {
        SetTransparentTCPUDPSrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparentTCPUDPDstWhite 设置一条规则 透明模式 服务为TCP或UDP,远离源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDPDstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        DIFF_IPTYPE_CONTINUE(pdobj, prule->m_sobject[j]);
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s %s --sport %s --dport %s %s -j ACCEPT\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                tmpsport, tmpdport, TimeString(prule));
        SystemIptablesRule(chcmd, bipv6, false);
        //----------------------------------目的端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s %s --sport %s "
                "--dport %s %s -j ACCEPT\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                tmpdport, tmpsport, TimeString(prule));
        SystemIptablesRule(chcmd, bipv6, false);

        if (IsOPCServ(pserv)) {
            sprintf(chcmd, "-A FORWARD %s %s %s --sport %s --dport %s %s -j ACCEPT\n",
                    RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('s', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

            sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s %s --sport %s "
                    "--dport %s %s -j ACCEPT\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpdport, tmpsport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);
        }//IsOPCServ
    }//m_sobjectnum

    if (IsOPCServ(pserv)) {
        //OPC同时需要自动开放的端口
        for (int i = 0; i < (int)(sizeof(opc_port) / sizeof(opc_port[0])); i++) {
            //按目的端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, tmpsport, opc_port[i].port, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

            //按源端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, opc_port[i].port, tmpsport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);
        }
    }//IsOPCServ
}

/**
 * [CYWBS::SetTransparentTCPUDPDst 设置一条规则 透明模式 服务为TCP或UDP,远离源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentTCPUDPDstWhite(prule, pdobj, pserv);
    } else {
        //黑名单策略 则什么也不用做
    }
}

/**
 * [CYWBS::SetTransparentTCPUDP 设置一条规则 透明模式 服务为TCP或UDP]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentTCPUDP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetTransparentTCPUDPSrc(prule, pdobj, pserv);
    } else {
        SetTransparentTCPUDPDst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparentICMPSrcWhite 设置一条规则 透明模式 服务为ICMP,靠近源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV4_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s -p icmp --icmp-type 8 %s -j %s\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, false, false);
        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s -p icmp --icmp-type 0 %s "
                "-j %s\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, false));
        SystemIptablesRule(chcmd, false, false);
    }
}

/**
 * [CYWBS::SetTransparentICMPSrcBlack 设置一条规则 透明模式 服务为ICMP,靠近源对象的一侧
 * 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV4_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-I FORWARD %s %s %s -p icmp --icmp-type 8 %s -j DROP\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, false, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD %s %s %s -p icmp --icmp-type 8 %s -j LOG --log-level 7 "
                    "--log-prefix \"LINKLOG_%s \"\n",
                    BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, false, false);
        }
    }
}

/**
 * [CYWBS::SetTransparentICMPSrc 设置一条规则 透明模式 服务为ICMP,靠近源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentICMPSrcWhite(prule, pdobj, pserv);
    } else {
        SetTransparentICMPSrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparentICMPDstWhite 设置一条规则 透明模式 服务为ICMP,远离源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPDstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV4_CONTINUE(prule->m_sobject[j]);
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s -p icmp --icmp-type 8 %s -j ACCEPT\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, false, false);
        //----------------------------------目的端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s -p icmp --icmp-type 0 %s "
                "-j ACCEPT\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, false, false);
    }
}

/**
 * [CYWBS::SetTransparentICMPDst 设置一条规则 透明模式 服务为ICMP,远离源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentICMPDstWhite(prule, pdobj, pserv);
    } else {
        //黑名单策略 则什么也不用做
    }
}

/**
 * [CYWBS::SetTransparentICMP 设置一条规则 透明模式 服务为ICMP]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    NOT_IPV4_RETURN(pdobj);
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetTransparentICMPSrc(prule, pdobj, pserv);
    } else {
        SetTransparentICMPDst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparentICMPV6SrcWhite 设置一条规则 透明模式 服务为ICMPV6,靠近源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6SrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV6_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s -p icmpv6 --icmpv6-type echo-request %s -j %s\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, true, false);
        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s "
                "-p icmpv6 --icmpv6-type echo-reply %s -j %s\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, false));
        SystemIptablesRule(chcmd, true, false);
    }
}

/**
 * [CYWBS::SetTransparentICMPV6SrcBlack 设置一条规则 透明模式 服务为ICMPV6,靠近源对象的一侧
 * 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6SrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV6_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-I FORWARD %s %s %s -p icmpv6 --icmpv6-type echo-request %s -j DROP\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, true, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD %s %s %s -p icmpv6 --icmpv6-type echo-request %s "
                    "-j LOG --log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                    BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, true, false);
        }
    }
}

/**
 * [CYWBS::SetTransparentICMPV6Src 设置一条规则 透明模式 服务为ICMPV6,靠近源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6Src(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentICMPV6SrcWhite(prule, pdobj, pserv);
    } else {
        SetTransparentICMPV6SrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparentICMPV6DstWhite 设置一条规则 透明模式 服务为ICMPV6,远离源对象的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6DstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV6_CONTINUE(prule->m_sobject[j]);
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD %s %s %s -p icmpv6 --icmpv6-type echo-request %s -j ACCEPT\n",
                BridgeString(prule), RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, true, false);
        //----------------------------------目的端响应----
        sprintf(chcmd, "-A FORWARD -m state --state ESTABLISHED %s %s "
                "-p icmpv6 --icmpv6-type echo-reply %s -j ACCEPT\n",
                RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('s', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, true, false);
    }
}

/**
 * [CYWBS::SetTransparentICMPV6Dst 设置一条规则 透明模式 服务为ICMPV6,远离源对象的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6Dst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetTransparentICMPV6DstWhite(prule, pdobj, pserv);
    } else {
        //黑名单策略 则什么也不用做
    }
}

/**
 * [CYWBS::SetTransparentICMPV6 设置一条规则 透明模式 服务为ICMPV6]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetTransparentICMPV6(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    NOT_IPV6_RETURN(pdobj);
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetTransparentICMPV6Src(prule, pdobj, pserv);
    } else {
        SetTransparentICMPV6Dst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetTransparent 设置一条规则 透明模式]
 * @param prule [规则指针]
 */
void CYWBS::SetTransparent(CSYSRULES *prule)
{
    for (int k = 0; k < prule->m_dobjectnum; k++) {
        for (int n = 0; n < prule->m_servicenum; n++) {

            if (IsTCPServ(prule->m_service[n]) || IsUDPServ(prule->m_service[n])) {
                SetTransparentTCPUDP(prule, prule->m_dobject[k], prule->m_service[n]);
            } else if (IsICMPServ(prule->m_service[n])) {

                SetTransparentICMP(prule, prule->m_dobject[k], prule->m_service[n]);
            } else if (IsICMPV6Serv(prule->m_service[n])) {
#if (SUPPORT_IPV6==1)
                SetTransparentICMPV6(prule, prule->m_dobject[k], prule->m_service[n]);
#endif
            } else {
                PRINT_ERR_HEAD
                print_err("other protocol[%s]", prule->m_service[n]->m_protocol);
            }
        }
    }
}

/**
 * [CYWBS::TransparentPrepare 透明模式准备工作
 * 对于RELATED,ESTABLISHED状态之外的连接 先默认设置为拒绝
 * 为了防止设置规则过程中到来的新连接非法通过]
 * @param flag [为true表示 准备，为false表示 清除准备]
 */
void CYWBS::TransparentPrepare(bool flag)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char c = flag ? 'A' : 'D';

    sprintf(chcmd, "-%c FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n", c);
    SystemIptablesRule(chcmd, false, false);
    sprintf(chcmd, "-%c FORWARD -j DROP\n", c);
    SystemIptablesRule(chcmd, false, false);

#if (SUPPORT_IPV6==1)
    sprintf(chcmd, "-%c FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n", c);
    SystemIptablesRule(chcmd, true, false);
    sprintf(chcmd, "-%c FORWARD -j DROP\n", c);
    SystemIptablesRule(chcmd, true, false);
#endif
}

/**
 * [CYWBS::SetSTP 是否开启STP]
 */
void CYWBS::SetSTP(void)
{
    if (m_devbs->ck_stp) {
        SystemCMD("brctl stp bb0 on");
    } else {
        SystemCMD("brctl stp bb0 off");
    }
}

/**
 * [CYWBS::SetARPLimit 设置限制ARP广播
 * V6版本 不开启STP的时候才启用，否则会内核崩溃]
 */
void CYWBS::SetARPLimit(void)
{
#if (SUOS_V==6)
    if (m_devbs->ck_stp) {
    } else {
        ARPLimit();
    }
#else
    ARPLimit();
#endif
}

/**
 * [CYWBS::SetTransparentRule 设置透明模式规则]
 */
void CYWBS::SetTransparentRule(void)
{
    //char chcmd[CMD_BUF_LEN] = {0};

    PRINT_DBG_HEAD
    print_dbg("transparent mode");
    WriteSysLog(LOG_TYPE_WORK_MODE, D_SUCCESS, LOG_CONTENT_TRANSPARENT);
#if 0
#if (SUPPORT_DPDK==1)
    m_devbs->m_ckdpdk = false;//暂时不支持该功能 强制置为false
    if (JudgeDPDK()) {
        //do with dpdk
        return;
    }
#endif
#endif
    TransparentPrepare(true);
    CreateBridge();
    SetSTP();
    SetARPLimit();
    BridgeAddif();
    SetBridgeIP();
    SystemCMD("echo 1 >/sys/devices/virtual/net/bb0/bridge/multicast_querier");
    SystemCMD("echo 0 >/sys/devices/virtual/net/bb0/bridge/multicast_snooping");
    WriteSysLog(LOG_TYPE_SET_RULE, D_SUCCESS, LOG_CONTENT_SET_RULE);

    for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
        SetTransparent(m_sysrulesbs->m_sysrule[i]);
    }

    SystemIptablesRule("-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n", false, false);
    if (m_devbs->ck_otherprotocal) {
        //基于IP的协议中 除了TCP UDP ICMP之外的协议 允许通过.
        SystemIptablesRule("-A FORWARD -p tcp -j DROP\n", false, false);
        SystemIptablesRule("-A FORWARD -p udp -j DROP\n", false, false);
        SystemIptablesRule("-A FORWARD -p icmp -j DROP\n", false, false);
        SystemIptablesRule("-A FORWARD -j ACCEPT\n", false, false);
    } else {
        SystemIptablesRule("-A FORWARD -j DROP\n", false, false);
    }

#if (SUPPORT_IPV6==1)
    SystemIptablesRule("-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n", true, false);

    ICMPv6Ext();
    if (m_devbs->ck_otherprotocal) {
        //基于IPV6的协议中 除了TCP UDP ICMPV6之外的协议 允许通过.
        SystemIptablesRule("-A FORWARD -p tcp -j DROP\n", true, false);
        SystemIptablesRule("-A FORWARD -p udp -j DROP\n", true, false);
        SystemIptablesRule("-A FORWARD -p icmpv6 -j DROP\n", true, false);
        SystemIptablesRule("-A FORWARD -j ACCEPT\n", true, false);
    } else {
        SystemIptablesRule("-A FORWARD -j DROP\n", true, false);
    }
#endif
    TransparentPrepare(false);
}

/**
 * [CYWBS::AutoProxy 是否自动代理对应]
 * 1）代理模式，
 * 2）靠近客户端的一侧只有一个IP
 * 3）靠近客户端的一侧没有配置任何多IP对应信息
 * 4）规则的目的对象只有一个
 * 5）唯一的目的对象是单IP对象
 * 同时满足以上5个条件的时候，才会自动代理对应
 *
 * @param  prule [规则指针]
 * @return       [自动代理对应时返回true]
 */
bool CYWBS::AutoProxy(CSYSRULES *prule)
{
    bool bflag = false;
    if (prule->m_secway.getarea() == 0) {
        //规则方向是内到外的
        if ((prule->m_dobjectnum == 1) && (m_devbs->indipnum == 0) && (InIpNum() == 1)) {
            if (RangeIP(prule->m_dobject[0]->m_ipaddress)) {
                WriteSysLog(LOG_TYPE_AUTO_PROXY, D_FAIL, LOG_CONTENT_AUTO_PROXY_FAIL);
            } else {
                bflag = true;
            }
        }
    } else {
        //规则方向是外到内的
        if ((prule->m_dobjectnum == 1) && (m_devbs->outdipnum == 0) && (OutIpNum() == 1)) {
            if (RangeIP(prule->m_dobject[0]->m_ipaddress)) {
                WriteSysLog(LOG_TYPE_AUTO_PROXY, D_FAIL, LOG_CONTENT_AUTO_PROXY_FAIL);
            } else {
                bflag = true;
            }
        }
    }

    return bflag;
}

/**
 * [CYWBS::ProxyGetOnlyIP 代理模式 自动代理对应时 获取唯一的业务IP]
 * @param prule [规则指针]
 * @param ip [输出参数]
 * @param iptype [IP类型 出参]
 */
void CYWBS::ProxyGetOnlyIP(CSYSRULES *prule, char *ip, int &iptype)
{
    if (prule->m_secway.getarea() == 0) {
        if (m_devbs->m_innet.myipnum != 0) {
            strcpy(ip, m_devbs->m_innet.myip[0].IP);
            iptype = m_devbs->m_innet.myip[0].TYPE;
        } else {
            strcpy(ip, m_sysrulesbs->m_inbonding->ipaddr[0]);
            iptype = m_sysrulesbs->m_inbonding->iptype[0];
        }
    } else {
        if (m_devbs->m_outnet.myipnum != 0) {
            strcpy(ip, m_devbs->m_outnet.myip[0].IP);
            iptype = m_devbs->m_outnet.myip[0].TYPE;
        } else {
            strcpy(ip, m_sysrulesbs->m_outbonding->ipaddr[0]);
            iptype = m_sysrulesbs->m_outbonding->iptype[0];
        }
    }
}

/**
 * [CYWBS::ProxyGetMidIP 代理模式 自动代理对应时 获取内部跳转IP]
* @param prule [规则指针]
* @param ip [输出参数]
* @param len [缓冲区长度]
* @param iptype [IP类型]
*/
void CYWBS::ProxyGetMidIP(CSYSRULES *prule,  char *ip, int len, int iptype)
{
    if (iptype == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
        MakeV6NatIP((prule->m_secway.getarea() != 0), g_linklanipseg, 1, ip, len);
#endif
    } else {
        MakeV4NatIP((prule->m_secway.getarea() != 0), g_linklanipseg, 1, ip, len);
    }
}

/**
 * [CYWBS::SetProxySrcAutoWhite 设置一条规则 代理模式 靠近客户端的一侧 自动代理对应 白名单策略]
 * @param prule     [规则指针]
 * @param servnum   [应用编号下标]
 * @param srconlyip [靠近客户端的一侧网闸唯一的业务IP]
 * @param midip     [中部跳转IP]
 * @param iptype    [IP类型]
 */
void CYWBS::SetProxySrcAutoWhite(CSYSRULES *prule, int servnum, char *srconlyip, char *midip, int iptype)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    char *misip = NULL;

    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));

    //源端SNAT指定出口IP需求
    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundToLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    if (IsSocketServ(prule->m_service[servnum])) {
        if (NULL != misip) {
            sprintf(chcmd, "-A POSTROUTING -d %s %s --dport %s -j SNAT --to %s\n",
                    midip, ProtoString(prule->m_service[servnum]->m_protocol),
                    tmptport, misip);
            SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);
        }
        if (IsOracleServ(prule->m_service[servnum])) {
            StartOracleInst(prule, srconlyip, midip, prule->m_dobject[0]->m_ipaddress, servnum);
        } else if (IsRTSPServ(prule->m_service[servnum])) {
            StartRTSPInst(prule, srconlyip, midip, prule->m_dobject[0]->m_ipaddress, servnum);
        } else if (IsXMPPServ(prule->m_service[servnum])) {
            if (NULL != misip) {
                StartxmppInst(prule, srconlyip, midip, prule->m_dobject[0]->m_ipaddress, servnum);
            } else {
                PRINT_ERR_HEAD
                print_err("xmpp rule not specify out ip[%s],ignore rule", prule->m_specsip);
            }
        }
    } else {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (iptype != prule->m_sobject[j]->m_iptype) {continue;}
            if (m_devbs->recordlog
                && (prule->m_service[servnum]->m_cklog)
                && (!CreateApp(prule->m_service[servnum]))) {
                sprintf(chcmd, "-A CHAIN1 %s %s %s --sport %s --dport %s %s %s -m state "
                        "--state NEW -j LOG --log-level 7 --log-prefix \"CALLLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', srconlyip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), OccursString(prule),
                        prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);
            }

            sprintf(chcmd, "-A CHAIN1 %s %s %s --sport %s --dport %s %s %s -j DNAT --to %s\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', srconlyip),
                    ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                    TimeString(prule), OccursString(prule),
                    DnatString(midip, NULL));
            SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);

            if (NULL != misip) {
                sprintf(chcmd, "-A POSTROUTING %s -d %s %s --sport %s --dport %s -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress), midip,
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport, misip);
                SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);
            }

            AddIpPortMap(srconlyip, prule->m_service[servnum]->m_tport,
                         prule->m_dobject[0]->m_ipaddress, prule->m_service[servnum]->m_dport,
                         midip, prule->m_service[servnum]->m_name,
                         prule->m_service[servnum]->m_protocol, iptype);
        }

        //源端  请求放入队列
        sprintf(chcmd, "-A FORWARD -o eth%d -d %s %s --dport %s %s -j %s\n",
                m_devbs->m_linklan, midip, ProtoString(prule->m_service[servnum]->m_protocol),
                tmptport, TimeString(prule), MethodString(prule->m_service[servnum], true));
        SystemIptablesRule(chcmd, iptype == IP_TYPE6, false);

        //源端  响应放入队列
        sprintf(chcmd, "-A FORWARD -i eth%d -s %s %s --sport %s %s -j %s\n",
                m_devbs->m_linklan, midip,
                ProtoString(prule->m_service[servnum]->m_protocol), tmptport, TimeString(prule),
                MethodString(prule->m_service[servnum], false));
        SystemIptablesRule(chcmd, iptype == IP_TYPE6, false);
    }
}

/**
 * [CYWBS::SetProxySrcAutoBlack 设置一条规则 代理模式 靠近客户端的一侧 自动代理对应 黑名单策略]
 * @param prule     [规则指针]
 * @param servnum   [应用编号下标]
 * @param srconlyip [靠近客户端的一侧网闸唯一的业务IP]
 * @param midip     [中部跳转IP]
 * @param iptype    [IP类型]
 */
void CYWBS::SetProxySrcAutoBlack(CSYSRULES *prule, int servnum, char *srconlyip, char *midip, int iptype)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));

    if (IsSocketServ(prule->m_service[servnum])) {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (iptype != prule->m_sobject[j]->m_iptype) {continue;}
            if (m_devbs->recordlog && prule->m_service[servnum]->m_cklog) {
                sprintf(chcmd, "-A INPUT %s %s %s --sport %s --dport %s %s -j LOG --log-level 7 "
                        "--log-prefix \"LINKLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', srconlyip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, iptype == IP_TYPE6, false);
            }

            sprintf(chcmd, "-A INPUT %s %s %s --sport %s --dport %s %s -j DROP\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', srconlyip), ProtoString(prule->m_service[servnum]->m_protocol),
                    tmpsport, tmptport, TimeString(prule));
            SystemIptablesRule(chcmd, iptype == IP_TYPE6, false);
        }
    } else {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (iptype != prule->m_sobject[j]->m_iptype) {continue;}
            sprintf(chcmd, "-I CHAIN1 %s %s %s --sport %s --dport %s %s -j RETURN\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', srconlyip), ProtoString(prule->m_service[servnum]->m_protocol),
                    tmpsport, tmptport, TimeString(prule));
            SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);

            if (m_devbs->recordlog && prule->m_service[servnum]->m_cklog) {
                sprintf(chcmd, "-I CHAIN1 %s %s %s --sport %s --dport %s %s -j LOG "
                        "--log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', srconlyip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, iptype == IP_TYPE6, true);
            }
        }
    }
}

/**
 * [CYWBS::SetProxySrcAuto 设置一条规则 代理模式 靠近客户端的一侧 自动代理对应]
 * @param prule [规则指针]
 */
void CYWBS::SetProxySrcAuto(CSYSRULES *prule)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char srconlyip[IP_STR_LEN] = {0};
    char midip[IP_STR_LEN] = {0};
    int onlyiptype = IP_TYPE4;//默认设置为IPV4

    ProxyGetOnlyIP(prule, srconlyip, onlyiptype);
    ProxyGetMidIP(prule, midip, sizeof(midip), onlyiptype);

    for (int n = 0; n < prule->m_servicenum; n++) {
        if ((!IsTCPServ(prule->m_service[n])) && (!IsUDPServ(prule->m_service[n]))) {
            continue;
        }

        if (IsOPCServ(prule->m_service[n])) {
            WriteSysLog(LOG_TYPE_MODE_CK, D_FAIL, LOG_CONTENT_OPC_MODE_ERR);
            PRINT_ERR_HEAD
            print_err("use opc in proxy mode");
            continue;
        }

        //4&6交叉访问时 不允许代理端口 目的端口为范围端口
        if ((onlyiptype != prule->m_dobject[0]->m_iptype)
            && (IS_RANGE_PORTS(prule->m_service[n]->m_tport) || IS_RANGE_PORTS(prule->m_service[n]->m_dport))) {
            PRINT_ERR_HEAD
            print_err("range ports is not allowd in ipv4 & ipv6 Cross-access.[%s][%s][%s]",
                      prule->m_service[n]->m_name, prule->m_service[n]->m_tport, prule->m_service[n]->m_dport);
            sprintf(chcmd, "%s[%s]", LOG_CONTENT_46RANGE_PORT, prule->m_service[n]->m_name);
            WriteSysLog(LOG_TYPE_PORT_CK, D_FAIL, chcmd);
            continue;
        }

        if (prule->Action) {
            SetProxySrcAutoWhite(prule, n, srconlyip, midip, onlyiptype);
        } else {
            SetProxySrcAutoBlack(prule, n, srconlyip, midip, onlyiptype);
        }
    }
}

/**
 * [CYWBS::ProxyMatch 代理对应匹配]
 * @param  pserv    [应用指针]
 * @param  pdipinfo [多IP对应结构指针]
 * @param  pdobj    [目的对象指针]
 * @return          [匹配上返回true]
 */
bool CYWBS::ProxyMatch(CSERVICECONF *pserv, SDIPINFO *pdipinfo, COBJECT *pdobj)
{
    if ((pserv == NULL) || (pdipinfo == NULL) || (pdobj == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while proxy match.pserv %p, pdipinfo %p, pdobj %p", pserv, pdipinfo, pdobj);
        return false;
    }
    return ((strcmp(pserv->m_dport, pdipinfo->dport) == 0)
            && pserv->NameEq(pdipinfo->appname, pdipinfo->appnamemd5)
            && (pdobj->m_iptype == pdipinfo->diptype)
            && IsInRange(pdobj->m_ipaddress, pdipinfo->dip));
}

/**
 * [SetProxySrcManualMatchWhite 设置一条规则 代理模式 靠近客户端的一侧 手动代理对应
 * 代理对应已经匹配上了 白名单策略]
 * @param prule     [规则指针]
 * @param servnum   [应用编号下标]
 * @param tmptip    [NAT跳转IP]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetProxySrcManualMatchWhite(CSYSRULES *prule, int servnum,
                                        char *tmptip, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    bool isipv6 = (pdipinfo->myiptype == IP_TYPE6);
    char *misip = NULL;

    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));


    //源端SNAT指定出口IP需求
    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundToLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    if (IsSocketServ(prule->m_service[servnum])) {
        if (NULL != misip) {
            sprintf(chcmd, "-A POSTROUTING -d %s %s --dport %s -j SNAT --to %s\n",
                    tmptip, ProtoString(prule->m_service[servnum]->m_protocol),
                    tmptport, misip);
            SystemIptablesRule(chcmd, isipv6, true);
        }
        if (IsOracleServ(prule->m_service[servnum])) {
            StartOracleInst(prule, pdipinfo->myip, tmptip, pdipinfo->dip, servnum);
        } else if (IsRTSPServ(prule->m_service[servnum])) {
            StartRTSPInst(prule, pdipinfo->myip, tmptip, pdipinfo->dip, servnum);
        } else if (IsXMPPServ(prule->m_service[servnum])) {
            if (NULL != misip) {
                StartxmppInst(prule, pdipinfo->myip, tmptip, pdipinfo->dip, servnum);
            } else {
                PRINT_ERR_HEAD
                print_err("xmpp rule not specify out ip[%s],ignore rule", prule->m_specsip);
            }
        }
    } else {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (pdipinfo->myiptype != prule->m_sobject[j]->m_iptype) {continue;}

            if (m_devbs->recordlog
                && prule->m_service[servnum]->m_cklog
                && (!CreateApp(prule->m_service[servnum])) ) {
                sprintf(chcmd, "-A CHAIN1 %s %s %s --sport %s --dport %s %s %s -m state "
                        "--state NEW -j LOG --log-level 7 --log-prefix \"CALLLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdipinfo->myip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), OccursString(prule),
                        prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, isipv6, true);
            }

            sprintf(chcmd, "-A CHAIN1 %s %s %s --sport %s --dport %s %s %s -j DNAT --to %s\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdipinfo->myip),
                    ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                    TimeString(prule), OccursString(prule),
                    DnatString(tmptip, NULL));
            SystemIptablesRule(chcmd, isipv6, true);

            if (NULL != misip) {
                sprintf(chcmd, "-A POSTROUTING %s -d %s %s --sport %s --dport %s -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress), tmptip,
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport, misip);
                SystemIptablesRule(chcmd, isipv6, true);
            }
            AddIpPortMap(pdipinfo->myip, prule->m_service[servnum]->m_tport, pdipinfo->dip,
                         pdipinfo->dport, tmptip, prule->m_service[servnum]->m_name,
                         prule->m_service[servnum]->m_protocol, pdipinfo->myiptype);
        }

        //源端  请求放入队列
        sprintf(chcmd, "-A FORWARD -o eth%d -d %s %s --dport %s %s -j %s\n",
                m_devbs->m_linklan, tmptip,
                ProtoString(prule->m_service[servnum]->m_protocol), tmptport, TimeString(prule),
                MethodString(prule->m_service[servnum], true));
        SystemIptablesRule(chcmd, isipv6, false);

        //源端  响应放入队列
        sprintf(chcmd, "-A FORWARD -i eth%d -s %s %s --sport %s %s -j %s\n",
                m_devbs->m_linklan, tmptip,
                ProtoString(prule->m_service[servnum]->m_protocol), tmptport, TimeString(prule),
                MethodString(prule->m_service[servnum], false));
        SystemIptablesRule(chcmd, isipv6, false);
    }
}

/**
 * [SetProxySrcManualMatchBlack 设置一条规则 代理模式 靠近客户端的一侧 手动代理对应
 * 代理对应已经匹配了 黑名单策略]
 * @param prule     [规则指针]
 * @param servnum   [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetProxySrcManualMatchBlack(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    bool isipv6 = (pdipinfo->myiptype == IP_TYPE6);
    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));

    if (IsSocketServ(prule->m_service[servnum])) {

        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (m_devbs->recordlog && prule->m_service[servnum]->m_cklog) {
                sprintf(chcmd, "-A INPUT %s %s %s --sport %s --dport %s %s -j LOG --log-level 7 "
                        "--log-prefix \"LINKLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdipinfo->myip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, isipv6, false);
            }
            sprintf(chcmd, "-A INPUT %s %s %s --sport %s --dport %s %s -j DROP\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdipinfo->myip),
                    ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                    TimeString(prule));
            SystemIptablesRule(chcmd, isipv6, false);
        }
    } else {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            sprintf(chcmd, "-I CHAIN1 %s %s %s --sport %s --dport %s %s -j RETURN\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdipinfo->myip),
                    ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                    TimeString(prule));
            SystemIptablesRule(chcmd, isipv6, true);

            if (m_devbs->recordlog && prule->m_service[servnum]->m_cklog) {
                sprintf(chcmd, "-I CHAIN1 %s %s %s --sport %s --dport %s %s -j LOG "
                        "--log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdipinfo->myip),
                        ProtoString(prule->m_service[servnum]->m_protocol), tmpsport, tmptport,
                        TimeString(prule), prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, isipv6, true);
            }
        }
    }
}

/**
 * [SetProxySrcManualMatch 设置一条规则 代理模式 靠近客户端的一侧 手动代理对应
 * 代理对应已经匹配上了]
 * @param prule     [规则指针]
 * @param servnum   [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetProxySrcManualMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    char tmpptr[IP_STR_LEN] = {0};
    char *tmplinkip = FoundLinkIPAddress(pdipinfo->myip);
    if (NULL == tmplinkip) {
        PRINT_ERR_HEAD
        print_err("find link ip fail![%s]", pdipinfo->myip);
        return;
    }

    memcpy(tmpptr, tmplinkip , IP_STR_LEN);
    if (prule->Action) {
        SetProxySrcManualMatchWhite(prule, servnum, tmpptr, pdipinfo);
    } else {
        SetProxySrcManualMatchBlack(prule, servnum, pdipinfo);
    }
}

/**
 * [CYWBS::SetProxySrcManual 设置一条规则 代理模式 靠近客户端的一侧 手动代理对应]
 * @param prule [规则指针]
 */
void CYWBS::SetProxySrcManual(CSYSRULES *prule)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int n = 0; n < prule->m_servicenum; n++) {
        if ((!IsTCPServ(prule->m_service[n])) && (!IsUDPServ(prule->m_service[n]))) {
            continue;
        }

        if (IsOPCServ(prule->m_service[n])) {
            WriteSysLog(LOG_TYPE_MODE_CK, D_FAIL, LOG_CONTENT_OPC_MODE_ERR);
            PRINT_ERR_HEAD
            print_err("use opc in proxy mode");
            continue;
        }

        for (int k = 0; k < prule->m_dobjectnum; k++) {
            for (int p = 0; p < (s_b_inside ? m_devbs->indipnum : m_devbs->outdipnum); p++) {

                SDIPINFO *pdipinfo =
                    (s_b_inside ? & (m_devbs->indipinfo[p]) : & (m_devbs->outdipinfo[p]));

                if (ProxyMatch(prule->m_service[n], pdipinfo, prule->m_dobject[k])) {
                    //手动代理对应匹配上了

                    //4&6交叉访问时 不允许代理端口 目的端口为范围端口
                    if ((pdipinfo->myiptype != pdipinfo->diptype)
                        && (IS_RANGE_PORTS(pdipinfo->myser) || IS_RANGE_PORTS(pdipinfo->dport))) {
                        PRINT_ERR_HEAD
                        print_err("range ports is not allowd in ipv4 & ipv6 Cross-access.[%s][%s][%s]",
                                  pdipinfo->appname, pdipinfo->myser, pdipinfo->dport);
                        sprintf(chcmd, "%s[%s]", LOG_CONTENT_46RANGE_PORT, pdipinfo->appname);
                        WriteSysLog(LOG_TYPE_PORT_CK, D_FAIL, chcmd);
                        continue;
                    }
                    SetProxySrcManualMatch(prule, n, pdipinfo);
                }
            }
        }//m_dobjectnum
    }
}

/**
 * [CYWBS::SetProxySrc 设置一条规则 代理模式 靠近客户端的一侧]
 * @param prule [规则指针]
 */
void CYWBS::SetProxySrc(CSYSRULES *prule)
{
    if (AutoProxy(prule)) {
        SetProxySrcAuto(prule);
    } else {
        SetProxySrcManual(prule);
    }
}

/**
 * [CYWBS::SetProxyDstAuto 设置一条规则 代理模式 远离客户端的一侧 自动代理对应]
 * @param prule [规则指针]
 */
void CYWBS::SetProxyDstAuto(CSYSRULES *prule)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    char midip[IP_STR_LEN] = {0};
    char srconlyip[IP_STR_LEN] = {0};
    int onlyiptype = IP_TYPE4;
    char *misip = NULL;
    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    ProxyGetOnlyIP(prule, srconlyip, onlyiptype);
    ProxyGetMidIP(prule, midip, sizeof(midip), onlyiptype);

    for (int n = 0; n < prule->m_servicenum; n++) {
        strcpy(tmpsport, Replace(prule->m_service[n]->m_sport, '-', ':'));
        strcpy(tmptport, Replace(prule->m_service[n]->m_tport, '-', ':'));
        strcpy(tmpdport, Replace(prule->m_service[n]->m_dport, '-', ':'));

        if ((!IsTCPServ(prule->m_service[n])) && (!IsUDPServ(prule->m_service[n]))) {
            continue;
        }

        if (IsOPCServ(prule->m_service[n])) {
            PRINT_ERR_HEAD
            print_err("use opc in proxy mode");
            continue;
        }

        if (prule->Action) {
            if (onlyiptype == prule->m_dobject[0]->m_iptype) {
                if (IsSocketServ(prule->m_service[n])) {
                    sprintf(chcmd, "-I PREROUTING -d %s %s --dport %s %s -j DNAT --to %s\n",
                            midip, ProtoString(prule->m_service[n]->m_protocol), tmptport,
                            TimeString(prule),
                            DnatString(prule->m_dobject[0]->m_ipaddress, prule->m_service[n]->m_dport));
                    SystemIptablesRule(chcmd, onlyiptype == IP_TYPE6, true);
                    //目的端SNAT指定出口IP需求
                    if (NULL != misip) {
                        sprintf(chcmd, "-I POSTROUTING -s %s -d %s %s --dport %s -j SNAT --to %s\n",
                                misip, prule->m_dobject[0]->m_ipaddress,
                                ProtoString(prule->m_service[n]->m_protocol), tmpdport, prule->m_specsip);
                        SystemIptablesRule(chcmd, onlyiptype == IP_TYPE6, true);
                    }
                } else {
                    sprintf(chcmd, "-I PREROUTING -d %s %s --sport %s --dport %s %s -j DNAT --to %s\n",
                            midip, ProtoString(prule->m_service[n]->m_protocol),
                            tmpsport, tmptport, TimeString(prule),
                            DnatString(prule->m_dobject[0]->m_ipaddress, prule->m_service[n]->m_dport));
                    SystemIptablesRule(chcmd, onlyiptype == IP_TYPE6, true);
                    //目的端SNAT指定出口IP需求
                    if (NULL != misip) {
                        sprintf(chcmd, "-I POSTROUTING -s %s -d %s %s --sport %s --dport %s -j SNAT --to %s\n",
                                misip, prule->m_dobject[0]->m_ipaddress,
                                ProtoString(prule->m_service[n]->m_protocol), tmpsport,
                                tmpdport, prule->m_specsip);
                        SystemIptablesRule(chcmd, onlyiptype == IP_TYPE6, true);
                    }
                }
            } else {
                if (IS_RANGE_PORTS(tmptport) || IS_RANGE_PORTS(prule->m_service[n]->m_dport)) {
                    PRINT_ERR_HEAD
                    print_err("range ports is not allowd in ipv4 & ipv6 Cross-access.[%s][%s][%s]",
                              prule->m_service[n]->m_name, tmptport, prule->m_service[n]->m_dport);
                    sprintf(chcmd, "%s[%s]", LOG_CONTENT_46RANGE_PORT, prule->m_service[n]->m_name);
                    WriteSysLog(LOG_TYPE_PORT_CK, D_FAIL, chcmd);
                } else {
                    g_nginx.push_back(midip, atoi(tmptport), onlyiptype, prule->m_dobject[0]->m_ipaddress,
                                      atoi(prule->m_service[n]->m_dport), prule->m_dobject[0]->m_iptype,
                                      prule->m_service[n]->m_protocol);
                }
            }
        } else {
            //黑名单策略 就什么也不做
        }
    }
}

/**
 * [SetProxyDstManualMatch 设置一条规则 代理模式 远离客户端的一侧 手动代理对应
 * 已经匹配上了]
 * @param prule    [规则指针]
 * @param pserv    [应用指针]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetProxyDstManualMatch(CSYSRULES *prule, CSERVICECONF *pserv, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    char tmpptr[IP_STR_LEN] = {0};
    bool isipv6 = (pdipinfo->myiptype == IP_TYPE6);
    char *misip = NULL;

    char *tmplinkip = FoundToLinkIPAddress(pdipinfo->myip);
    if (NULL == tmplinkip) {
        PRINT_ERR_HEAD
        print_err("find link ip fail![%s]", prule->m_specsip);
        return;
    }
    memcpy(tmpptr, tmplinkip , IP_STR_LEN);

    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmptport, Replace(pserv->m_tport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    if (prule->Action) {
        if (pdipinfo->myiptype == pdipinfo->diptype) {//ipv4 ipv6没有交叉
            if (IsSocketServ(pserv)) {
                sprintf(chcmd, "-I PREROUTING -d %s %s --dport %s %s -j DNAT --to %s\n",
                        tmpptr, ProtoString(pserv->m_protocol), tmptport,
                        TimeString(prule), DnatString(pdipinfo->dip, pserv->m_dport));
                SystemIptablesRule(chcmd, isipv6, true);
                //目的端SNAT指定出口IP需求
                if (NULL != misip) {
                    sprintf(chcmd, "-I POSTROUTING -s %s -d %s %s --dport %s -j SNAT --to %s\n",
                            misip, pdipinfo->dip, ProtoString(pserv->m_protocol),
                            tmpdport, prule->m_specsip);
                    SystemIptablesRule(chcmd, isipv6, true);
                }
            } else {
                sprintf(chcmd, "-I PREROUTING -d %s %s --sport %s --dport %s %s -j DNAT --to %s\n",
                        tmpptr, ProtoString(pserv->m_protocol), tmpsport, tmptport,
                        TimeString(prule), DnatString(pdipinfo->dip, pserv->m_dport));
                SystemIptablesRule(chcmd, isipv6, true);
                //目的端SNAT指定出口IP需求
                if (NULL != misip) {
                    sprintf(chcmd, "-I POSTROUTING -s %s -d %s %s --sport %s --dport %s -j SNAT --to %s\n",
                            misip, pdipinfo->dip, ProtoString(pserv->m_protocol), tmpsport,
                            tmpdport, prule->m_specsip);
                    SystemIptablesRule(chcmd, isipv6, true);
                }
            }
        } else {
            if (IS_RANGE_PORTS(tmptport) || IS_RANGE_PORTS(pserv->m_dport)) {
                PRINT_ERR_HEAD
                print_err("range ports is not allowd in ipv4 & ipv6 Cross-access[%s][%s][%s]",
                          pserv->m_name, tmptport, pserv->m_dport);
                sprintf(chcmd, "%s[%s]", LOG_CONTENT_46RANGE_PORT, pserv->m_name);
                WriteSysLog(LOG_TYPE_PORT_CK, D_FAIL, chcmd);
            } else {
                g_nginx.push_back(tmpptr, atoi(tmptport), pdipinfo->myiptype, pdipinfo->dip,
                                  atoi(pserv->m_dport), pdipinfo->diptype, pserv->m_protocol);
            }
        }
    } else {
        //黑名单策略 则什么也不做
    }
}

/**
 * [CYWBS::SetProxyDstManual 设置一条规则 代理模式 远离客户端的一侧 手动代理对应]
 * @param prule [规则指针]
 */
void CYWBS::SetProxyDstManual(CSYSRULES *prule)
{
    for (int n = 0; n < prule->m_servicenum; n++) {
        if ((!IsTCPServ(prule->m_service[n])) && (!IsUDPServ(prule->m_service[n]))) {
            continue;
        }

        if (IsOPCServ(prule->m_service[n])) {
            PRINT_ERR_HEAD
            print_err("use opc in proxy mode");
            continue;
        }

        for (int k = 0; k < prule->m_dobjectnum; k++) {
            for (int p = 0; p < (s_b_inside ? m_devbs->outdipnum : m_devbs->indipnum); p++) {

                SDIPINFO *pdipinfo =
                    (s_b_inside ? & (m_devbs->outdipinfo[p]) : & (m_devbs->indipinfo[p]));

                if (ProxyMatch(prule->m_service[n], pdipinfo, prule->m_dobject[k])) {
                    //手动代理对应匹配上了
                    SetProxyDstManualMatch(prule, prule->m_service[n], pdipinfo);
                }
            }
        }
    }
}

/**
 * [CYWBS::SetProxyDst 设置一条规则 代理模式 远离客户端的一侧]
 * @param prule [规则指针]
 */
void CYWBS::SetProxyDst(CSYSRULES *prule)
{
    if (AutoProxy(prule)) {
        SetProxyDstAuto(prule);
    } else {
        SetProxyDstManual(prule);
    }
}

/**
 * [CYWBS::SetProxy 设置一条规则 代理模式]
 * @param prule [规则指针]
 */
void CYWBS::SetProxy(CSYSRULES *prule)
{
    //对象个数检查
    if (prule->m_sobjectnum <= 0) {
        WriteSysLog(LOG_TYPE_OBJ_CK, D_FAIL, LOG_CONTENT_SOBJ_ERR);
        PRINT_ERR_HEAD
        print_err("%s:%s", prule->m_name, LOG_CONTENT_SOBJ_ERR);
        return;
    }

    if (prule->m_dobjectnum <= 0) {
        WriteSysLog(LOG_TYPE_OBJ_CK, D_FAIL, LOG_CONTENT_DOBJ_ERR);
        PRINT_ERR_HEAD
        print_err("%s:%s", prule->m_name, LOG_CONTENT_DOBJ_ERR);
        return;
    }

    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetProxySrc(prule);
    } else {
        SetProxyDst(prule);
    }
}

/**
 * [CYWBS::SetProxyRule 设置代理模式规则]
 */
void CYWBS::SetProxyRule(void)
{
    PRINT_DBG_HEAD
    print_dbg("proxy mode");

    WriteSysLog(LOG_TYPE_WORK_MODE, D_SUCCESS, LOG_CONTENT_PROXY);

    //检查是否还没设置IP
    if ((InIpNum() <= 0) || (OutIpNum() <= 0)) {
        if (m_sysrulesbs->m_sysrulenum > 0) {
            WriteSysLog(LOG_TYPE_IP_CK, D_FAIL, LOG_CONTENT_NO_IP);
            PRINT_ERR_HEAD
            print_err("you should set up business IP first");
        }
        return;
    }

    WriteSysLog(LOG_TYPE_SET_RULE, D_SUCCESS, LOG_CONTENT_SET_RULE);
    for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
        SetProxy(m_sysrulesbs->m_sysrule[i]);
    }
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "-A FORWARD -j FILTER_WEBPROXY\n");
    SystemIptablesRule(chcmd, false, false);
    SystemIptablesRule(chcmd, true, false);
    ProxyHideSrc();
}

/**
 * [CYWBS::SetPortConnect 设置代理模式下 同侧网口是否可路由通]
 */
void CYWBS::SetPortConnect(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (m_devbs->m_portconnect == 1) {
        PRINT_DBG_HEAD
        print_dbg("port connect is open");
    } else {
        MAKE_TABLESTRING(chcmd, "-A FORWARD -i eth%d -j ACCEPT", false, m_devbs->m_linklan);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A FORWARD -i eth%d -j ACCEPT", true, m_devbs->m_linklan);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A FORWARD -o eth%d -j ACCEPT", false, m_devbs->m_linklan);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A FORWARD -o eth%d -j ACCEPT", true, m_devbs->m_linklan);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A FORWARD -j DROP", false);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A FORWARD -j DROP", true);
        SystemCMD(chcmd);
    }
}

/**
 * [CYWBS::ProxyHideSrc 代理模式 设置隐藏源地址]
 */
void CYWBS::ProxyHideSrc(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "-A POSTROUTING -j NAT_MULTICAST\n");
    SystemIptablesRule(chcmd, false, true);
    //内部DBsync 模块监听的是 127.0.0.1 63306
    sprintf(chcmd, "-A POSTROUTING ! -s 127.0.0.1 -j MASQUERADE\n");
    SystemIptablesRule(chcmd, false, true);

#if (SUPPORT_IPV6==1)
    sprintf(chcmd, "-A POSTROUTING -j NAT_MULTICAST\n");
    SystemIptablesRule(chcmd, true, true);
    sprintf(chcmd, "-A POSTROUTING -j MASQUERADE\n");
    SystemIptablesRule(chcmd, true, true);
#endif
}

/**
 * [CYWBS::RouteHideSrc 路由模式 隐藏源地址]
 */
void CYWBS::RouteHideSrc(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    sprintf(chcmd, "-A POSTROUTING -j NAT_MULTICAST\n");
    SystemIptablesRule(chcmd, false, true);
#if (SUPPORT_IPV6==1)
    sprintf(chcmd, "-A POSTROUTING -j NAT_MULTICAST\n");
    SystemIptablesRule(chcmd, true, true);
#endif

    if (m_devbs->hidesrc) {
        sprintf(chcmd, "-A POSTROUTING ! -s 127.0.0.1 ! -o eth%d -j MASQUERADE\n",
                m_devbs->m_linklan);
        SystemIptablesRule(chcmd, false, true);

#if (SUPPORT_IPV6==1)
        sprintf(chcmd, "-A POSTROUTING ! -o eth%d -j MASQUERADE\n", m_devbs->m_linklan);
        SystemIptablesRule(chcmd, true, true);
#endif
    }
}

/**
 * [CYWBS::SetRouteProxySrcMatchWhite 设置一条规则 路由模式 路由模式下的代理 靠近客户端的一侧
 * 代理对应已经匹配上了 白名单策略]
 * @param prule    [规则指针]
 * @param servnum  [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetRouteProxySrcMatchWhite(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    char tmpptr[IP_STR_LEN] = {0};
    char *misip = NULL;

    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));

    if (IsSocketServ(prule->m_service[servnum])) {

        char *tmpiptr = FoundLinkIPAddress(pdipinfo->myip);
        if (tmpiptr == NULL) {
            PRINT_ERR_HEAD
            print_err("cannot find myip %s", pdipinfo->myip);
            return;
        }
        memcpy(tmpptr, tmpiptr, IP_STR_LEN);

        //源端SNAT指定出口IP需求
        if (IS_SPEC_THE_EXPORT_IP(prule)) {
            misip = FoundToLinkIPAddress(prule->m_specsip);
            if (NULL != misip) {
                sprintf(chcmd, "-A POSTROUTING -d %s %s --dport %s -j SNAT --to %s\n",
                        tmpptr, ProtoString(prule->m_service[servnum]->m_protocol),
                        tmptport, misip);
                SystemIptablesRule(chcmd, (pdipinfo->myiptype == IP_TYPE6), true);
            } else {
                PRINT_INFO_HEAD
                print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
            }
        }

        if (IsOracleServ(prule->m_service[servnum])) {
            StartOracleInst(prule, pdipinfo->myip, tmpptr, pdipinfo->dip, servnum);
        } else if (IsRTSPServ(prule->m_service[servnum])) {
            StartRTSPInst(prule, pdipinfo->myip, tmpptr, pdipinfo->dip, servnum);
        } else if (IsXMPPServ(prule->m_service[servnum])) {
            if ((m_devbs->hidesrc) && (NULL != misip)) {
                StartxmppInst(prule, pdipinfo->myip, tmpptr, pdipinfo->dip, servnum);
            } else {
                PRINT_INFO_HEAD
                print_info("xmpp rule not specify out ip[%s] or not hidesrc,ignore rule",
                           prule->m_specsip);
            }
        }
    } else {

        for (int j = 0; j < prule->m_sobjectnum; j++) {
            if (prule->m_sobject[j]->m_iptype != pdipinfo->myiptype) {continue;}
            sprintf(chcmd, "-I CHAIN1 %s %s %s --dport %s %s -j DNAT --to %s\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdipinfo->myip),
                    ProtoString(prule->m_service[servnum]->m_protocol),
                    Replace(prule->m_service[servnum]->m_tport, '-', ':'),
                    TimeString(prule),
                    DnatString(pdipinfo->dip, prule->m_service[servnum]->m_dport));
            SystemIptablesRule(chcmd, (prule->m_sobject[j]->m_iptype == IP_TYPE6), true);
        }
    }
}

/**
 * [CYWBS::SetRouteProxySrcMatchBlack 设置一条规则 路由模式 路由模式下的代理 靠近客户端的一侧
 * 代理对应已经匹配上了 黑名单策略]
 * @param prule    [规则指针]
 * @param servnum  [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetRouteProxySrcMatchBlack(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (IsSocketServ(prule->m_service[servnum])) {
        for (int j = 0; j < prule->m_sobjectnum; j++) {
            sprintf(chcmd, "-I INPUT %s %s %s --dport %s %s -j DROP\n",
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdipinfo->myip),
                    ProtoString(prule->m_service[servnum]->m_protocol),
                    Replace(prule->m_service[servnum]->m_tport, '-', ':'), TimeString(prule));
            SystemIptablesRule(chcmd, false, false);

            if (m_devbs->recordlog && prule->m_service[servnum]->m_cklog) {
                sprintf(chcmd, "-I INPUT %s %s %s --dport %s %s -j LOG --log-level 7 "
                        "--log-prefix \"LINKLOG_%s \"\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdipinfo->myip),
                        ProtoString(prule->m_service[servnum]->m_protocol),
                        Replace(prule->m_service[servnum]->m_tport, '-', ':'),
                        TimeString(prule), prule->m_service[servnum]->m_asservice);
                SystemIptablesRule(chcmd, false, false);
            }
        }
    }
}

/**
 * [CYWBS::SetRouteProxySrcMatch 设置一条规则 路由模式 路由模式下的代理 靠近客户端的一侧
 * 代理对应已经匹配上了]
 * @param prule    [规则指针]
 * @param servnum  [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetRouteProxySrcMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    if (prule->Action) {
        SetRouteProxySrcMatchWhite(prule, servnum, pdipinfo);
    } else {
        SetRouteProxySrcMatchBlack(prule, servnum, pdipinfo);
    }
}

/**
 * [CYWBS::SetRouteProxySrc 设置一条规则 路由模式 路由模式下的代理 靠近客户端的一侧]
 * @param prule [规则指针]
 */
void CYWBS::SetRouteProxySrc(CSYSRULES *prule)
{
    for (int n = 0; n < prule->m_servicenum; n++) {
        for (int k = 0; k < prule->m_dobjectnum; k++) {
            for (int p = 0; p < (s_b_inside ? m_devbs->indipnum : m_devbs->outdipnum); p++) {

                SDIPINFO *pdipinfo =
                    (s_b_inside ? & (m_devbs->indipinfo[p]) : & (m_devbs->outdipinfo[p]));

                if (pdipinfo->myiptype != pdipinfo->diptype) {//路由模式下的代理 不处理IPV4 IPV6交叉访问的情况
                    PRINT_ERR_HEAD
                    print_err("iptype diff! myiptype %d,diptype %d", pdipinfo->myiptype, pdipinfo->diptype);
                    continue;
                }

                if (ProxyMatch(prule->m_service[n], pdipinfo, prule->m_dobject[k])) {
                    SetRouteProxySrcMatch(prule, n, pdipinfo);
                    break;
                }
            }
        }
    }
}

/**
 * [CYWBS::SetRouteProxyDstMatch 设置一条规则 路由模式 路由模式下的代理  远离客户端的一侧
 * 代理对应已经匹配上了]
 * @param prule    [规则指针]
 * @param servnum  [应用编号下标]
 * @param pdipinfo [多IP对应结构指针]
 */
void CYWBS::SetRouteProxyDstMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmptport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    char tmpptr[IP_STR_LEN] = {0};
    char *misip = NULL;

    strcpy(tmpsport, Replace(prule->m_service[servnum]->m_sport, '-', ':'));
    strcpy(tmptport, Replace(prule->m_service[servnum]->m_tport, '-', ':'));
    strcpy(tmpdport, Replace(prule->m_service[servnum]->m_dport, '-', ':'));

    if (prule->Action) {
        if (IS_SPEC_THE_EXPORT_IP(prule)) {
            misip = FoundLinkIPAddress(prule->m_specsip);
            if (NULL == misip) {
                PRINT_INFO_HEAD
                print_info("find link ip fail![%s]", prule->m_specsip);
            }
        }

        if (IsSocketServ(prule->m_service[servnum])) {
            char *tmpiptr = FoundToLinkIPAddress(pdipinfo->myip);
            if (tmpiptr == NULL) {
                PRINT_ERR_HEAD
                print_err("cannot find myip %s", pdipinfo->myip);
                return;
            }
            memcpy(tmpptr, tmpiptr, IP_STR_LEN);
            sprintf(chcmd, "-I PREROUTING %s %s --dport %s %s -j DNAT --to %s\n",
                    RangeIpString('d', tmpptr),
                    ProtoString(prule->m_service[servnum]->m_protocol),
                    tmptport, TimeString(prule),
                    DnatString(pdipinfo->dip, prule->m_service[servnum]->m_dport));
            SystemIptablesRule(chcmd, false, true);
            if ((m_devbs->hidesrc) && (NULL != misip)) {
                sprintf(chcmd, "-A POSTROUTING -s %s -d %s %s --dport %s -j SNAT --to %s\n",
                        misip, pdipinfo->dip,
                        ProtoString(prule->m_service[servnum]->m_protocol),
                        tmpdport, prule->m_specsip);
                SystemIptablesRule(chcmd, (pdipinfo->diptype == IP_TYPE6), true);
            }
        } else {
            //其他普通模块 如果未指定出口,且未勾选隐藏源地址,则什么也不做。
        }
        //指定出口IP
        if ((m_devbs->hidesrc) && (NULL != misip)) {
            for (int j = 0; j < prule->m_sobjectnum; j++) {
                if (prule->m_sobject[j]->m_iptype != pdipinfo->myiptype) {continue;}
                sprintf(chcmd, "-A POSTROUTING %s -d %s %s --sport %s --dport %s -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        pdipinfo->dip, ProtoString(prule->m_service[servnum]->m_protocol),
                        tmpsport, tmpdport, prule->m_specsip);
                SystemIptablesRule(chcmd, (prule->m_sobject[j]->m_iptype == IP_TYPE6), true);
            }
        }
    } else {
        //黑名单策略 则什么也不用做
    }
}

/**
 * [CYWBS::SetRouteProxyDst 设置一条规则 路由模式 路由模式下的代理 远离客户端的一侧]
 * @param prule [规则指针]
 */
void CYWBS::SetRouteProxyDst(CSYSRULES *prule)
{
    for (int n = 0; n < prule->m_servicenum; n++) {
        for (int k = 0; k < prule->m_dobjectnum; k++) {
            for (int p = 0; p < (s_b_inside ? m_devbs->outdipnum : m_devbs->indipnum); p++) {

                SDIPINFO *pdipinfo =
                    (s_b_inside ? & (m_devbs->outdipinfo[p]) : & (m_devbs->indipinfo[p]));

                if (pdipinfo->myiptype != pdipinfo->diptype) {//路由模式下的代理 不处理IPV4 IPV6交叉访问的情况
                    PRINT_ERR_HEAD
                    print_err("iptype diff! myiptype %d,diptype %d", pdipinfo->myiptype, pdipinfo->diptype);
                    continue;
                }

                if (ProxyMatch(prule->m_service[n], pdipinfo, prule->m_dobject[k])) {
                    SetRouteProxyDstMatch(prule, n, pdipinfo);
                    break;
                }
            }
        }
    }
}

/**
 * [CYWBS::SetRouteProxy 设置一条规则 路由模式 路由模式下的代理]
 * @param prule [规则指针]
 */
void CYWBS::SetRouteProxy(CSYSRULES *prule)
{
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetRouteProxySrc(prule);
    } else {
        SetRouteProxyDst(prule);
    }
}

/**
 * [CYWBS::SetRouteICMPSrcWhite 设置一条规则 路由模式 服务为ICMP 靠近客户端的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV4_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-A FORWARD -o eth%d %s %s -p icmp --icmp-type 8 %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, false, false);
        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -i eth%d %s -p icmp --icmp-type 0 %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                TimeString(prule), MethodString(pserv, false));
        SystemIptablesRule(chcmd, false, false);
    }
}

/**
 * [CYWBS::SetRouteICMPSrcBlack 设置一条规则 路由模式 服务为ICMP 靠近客户端的一侧
 * 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV4_CONTINUE(prule->m_sobject[j]);
        sprintf(chcmd, "-I FORWARD -o eth%d %s %s -p icmp --icmp-type 8 %s -j DROP\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, false, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD -o eth%d %s %s -p icmp --icmp-type 8 %s -j LOG "
                    "--log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                    m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, false, false);
        }
    }
}

/**
 * [CYWBS::SetRouteICMPSrc 设置一条规则 路由模式 服务为ICMP 靠近客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetRouteICMPSrcWhite(prule, pdobj, pserv);
    } else {
        SetRouteICMPSrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteICMPDst 设置一条规则 路由模式 服务为ICMP 远离客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char *misip = NULL;

    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    if (prule->Action) {
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD -i eth%d %s -p icmp --icmp-type 8 %s -j ACCEPT\n",
                m_devbs->m_linklan, RangeIpString('d', pdobj->m_ipaddress),
                TimeString(prule));
        SystemIptablesRule(chcmd, false, false);
        //----------------------------------目的端响应----
        //其他普通模块 如果未指定出口,且未勾选隐藏源地址,则什么也不做。
        if ((m_devbs->hidesrc) && (NULL != misip)) {
            for (int j = 0; j < prule->m_sobjectnum; j++) {
                sprintf(chcmd, "-A POSTROUTING %s %s -p icmp --icmp-type 8 -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdobj->m_ipaddress), prule->m_specsip);
                SystemIptablesRule(chcmd, false, true);
            }
        }
        //通过ESTABLISHED过去
    } else {
        //黑名单策略 则什么也不做
    }
}

/**
 * [CYWBS::SetRouteICMP 设置一条规则 路由模式 服务为ICMP]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    NOT_IPV4_RETURN(pdobj);
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetRouteICMPSrc(prule, pdobj, pserv);
    } else {
        SetRouteICMPDst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteICMPV6SrcWhite 设置一条规则 路由模式 服务为ICMPV6 靠近客户端的一侧
 * 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPV6SrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV6_CONTINUE(prule->m_sobject[j]);
        //----------------------------------源端请求----
        sprintf(chcmd, "-A FORWARD -o eth%d %s %s -p icmpv6 --icmpv6-type echo-request %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, true, false);
        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -i eth%d %s -p icmpv6 --icmpv6-type echo-reply %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                TimeString(prule), MethodString(pserv, false));
        SystemIptablesRule(chcmd, true, false);
    }
}

/**
 * [CYWBS::SetRouteICMPV6SrcBlack 设置一条规则 路由模式 服务为ICMPV6 靠近客户端的一侧
 * 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPV6SrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        NOT_IPV6_CONTINUE(prule->m_sobject[j]);
        sprintf(chcmd, "-I FORWARD -o eth%d %s %s -p icmpv6 --icmpv6-type echo-request %s -j DROP\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), TimeString(prule));
        SystemIptablesRule(chcmd, true, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD -o eth%d %s %s -p icmpv6 --icmpv6-type echo-request %s -j LOG "
                    "--log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                    m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, true, false);
        }
    }
}

/**
 * [CYWBS::SetRouteICMPV6Src 设置一条规则 路由模式 服务为ICMPV6 靠近客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPV6Src(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        SetRouteICMPV6SrcWhite(prule, pdobj, pserv);
    } else {
        SetRouteICMPV6SrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteICMPV6Dst 设置一条规则 路由模式 服务为ICMPV6 远离客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPV6Dst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char *misip = NULL;

    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    if (prule->Action) {
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD -i eth%d %s -p icmpv6 --icmpv6-type echo-request %s -j ACCEPT\n",
                m_devbs->m_linklan, RangeIpString('d', pdobj->m_ipaddress),
                TimeString(prule));
        SystemIptablesRule(chcmd, true, false);
        //其他普通模块 如果未指定出口,且未勾选隐藏源地址,则什么也不做。
        if ((m_devbs->hidesrc) && (NULL != misip)) {
            for (int j = 0; j < prule->m_sobjectnum; j++) {
                sprintf(chcmd, "-A POSTROUTING %s %s -p icmpv6 --icmpv6-type echo-request -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdobj->m_ipaddress), prule->m_specsip);
                SystemIptablesRule(chcmd, true, true);
            }
        }
        //----------------------------------目的端响应----
        //通过ESTABLISHED过去
    } else {
        //黑名单策略 则什么也不做
    }
}

/**
 * [CYWBS::SetRouteICMPV6 设置一条规则 路由模式 服务为ICMPV6]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteICMPV6(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    NOT_IPV6_RETURN(pdobj);
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetRouteICMPV6Src(prule, pdobj, pserv);
    } else {
        SetRouteICMPV6Dst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteTCPUDPSrcBlack 设置一条规则 路由模式 服务为TCP或UDP
 * 靠近客户端的一侧 黑名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteTCPUDPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        DIFF_IPTYPE_CONTINUE(pdobj, prule->m_sobject[j]);
        sprintf(chcmd, "-I FORWARD -o eth%d %s %s %s --sport %s --dport %s %s -j DROP\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol), tmpsport,
                tmpdport, TimeString(prule));
        SystemIptablesRule(chcmd, bipv6, false);

        if (m_devbs->recordlog && pserv->m_cklog) {
            sprintf(chcmd, "-I FORWARD -o eth%d %s %s %s --sport %s --dport %s %s -j LOG "
                    "--log-level 7 --log-prefix \"LINKLOG_%s \"\n",
                    m_devbs->m_linklan,
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, bipv6, false);
        }
    }//m_sobjectnum
}

/**
 * [CYWBS::SetRouteTCPUDPSrcWhite 设置一条规则 路由模式 服务为TCP或UDP
 * 靠近客户端的一侧 白名单策略]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteTCPUDPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    for (int j = 0; j < prule->m_sobjectnum; j++) {
        DIFF_IPTYPE_CONTINUE(pdobj, prule->m_sobject[j]);
        //----------------------------------源端请求----
        if (m_devbs->recordlog && pserv->m_cklog && (!CreateApp(pserv))) {
            sprintf(chcmd, "-A FORWARD -o eth%d %s %s %s --sport %s --dport %s %s %s "
                    "-m state --state NEW -j LOG --log-level 7 --log-prefix \"CALLLOG_%s \"\n",
                    m_devbs->m_linklan,
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), OccursString(prule), pserv->m_asservice);
            SystemIptablesRule(chcmd, bipv6, false);
        }
        sprintf(chcmd, "-A FORWARD -o eth%d %s %s %s --sport %s --dport %s %s %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol), tmpsport,
                tmpdport, TimeString(prule), OccursString(prule), MethodString(pserv, true));
        SystemIptablesRule(chcmd, bipv6, false);
        //----------------------------------源端响应----
        sprintf(chcmd, "-A FORWARD -i eth%d %s -m state --state ESTABLISHED %s --dport %s "
                "--sport %s %s -j %s\n",
                m_devbs->m_linklan, RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                ProtoString(pserv->m_protocol), tmpsport, tmpdport, TimeString(prule),
                MethodString(pserv, false));
        SystemIptablesRule(chcmd, bipv6, false);

        if (IsOPCServ(pserv)) {
            sprintf(chcmd, "-A FORWARD -i eth%d %s %s %s --sport %s --dport %s %s -j %s\n",
                    m_devbs->m_linklan,
                    RangeIpString('d', prule->m_sobject[j]->m_ipaddress),
                    RangeIpString('s', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                    tmpsport, tmpdport, TimeString(prule), MethodString(pserv, true));
            SystemIptablesRule(chcmd, bipv6, false);

            sprintf(chcmd, "-A FORWARD -o eth%d %s -m state --state ESTABLISHED %s --dport %s "
                    "--sport %s %s -j %s\n",
                    m_devbs->m_linklan,
                    RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                    ProtoString(pserv->m_protocol), tmpsport, tmpdport, TimeString(prule),
                    MethodString(pserv, false));
            SystemIptablesRule(chcmd, bipv6, false);

            AddIpPortMap("", "", prule->m_sobject[j]->m_ipaddress, pserv->m_dport, "",
                         pserv->m_name, pserv->m_protocol, prule->m_sobject[j]->m_iptype);
        }//OPC
    }//m_sobjectnum
    if (IsOPCServ(pserv)) {
        //OPC同时需要自动开放的端口
        for (int i = 0; i < (int)(sizeof(opc_port) / sizeof(opc_port[0])); i++) {
            //按目的端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, tmpsport, opc_port[i].port, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

            //按源端口开放
            sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                    opc_port[i].protocol, opc_port[i].port, tmpsport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);
        }
    }
}

/**
 * [CYWBS::SetRouteTCPUDPSrc 设置一条规则 路由模式 服务为TCP或UDP
 * 靠近客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteTCPUDPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (prule->Action) {
        AddIpPortMap("", "", pdobj->m_ipaddress, pserv->m_dport, "", pserv->m_name,
                     pserv->m_protocol, pdobj->m_iptype);
        SetRouteTCPUDPSrcWhite(prule, pdobj, pserv);
    } else {
        SetRouteTCPUDPSrcBlack(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteTCPUDPDst 设置一条规则 路由模式 服务为TCP或UDP
 * 远离客户端的一侧]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteTCPUDPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char tmpsport[PORT_STR_LEN] = {0};
    char tmpdport[PORT_STR_LEN] = {0};
    bool bipv6 = (pdobj->m_iptype == IP_TYPE6);
    strcpy(tmpsport, Replace(pserv->m_sport, '-', ':'));
    strcpy(tmpdport, Replace(pserv->m_dport, '-', ':'));

    char *misip = NULL;
    if (IS_SPEC_THE_EXPORT_IP(prule)) {
        misip = FoundLinkIPAddress(prule->m_specsip);
        if (NULL == misip) {
            PRINT_INFO_HEAD
            print_info("This Specify ip:[%s] is not exits!", prule->m_specsip);
        }
    }

    if (prule->Action) {
        //----------------------------------目的端请求----
        sprintf(chcmd, "-A FORWARD -i eth%d %s %s --sport %s --dport %s %s -j ACCEPT\n",
                m_devbs->m_linklan, RangeIpString('d', pdobj->m_ipaddress),
                ProtoString(pserv->m_protocol), tmpsport, tmpdport, TimeString(prule));
        SystemIptablesRule(chcmd, bipv6, false);

        if (IsOPCServ(pserv)) {
            sprintf(chcmd, "-A FORWARD -o eth%d %s %s --sport %s --dport %s %s -j ACCEPT\n",
                    m_devbs->m_linklan, RangeIpString('s', pdobj->m_ipaddress),
                    ProtoString(pserv->m_protocol), tmpsport, tmpdport, TimeString(prule));
            SystemIptablesRule(chcmd, bipv6, false);

            //OPC同时需要自动开放的端口
            for (int i = 0; i < (int)(sizeof(opc_port) / sizeof(opc_port[0])); i++) {
                //按目的端口开放
                sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                        opc_port[i].protocol, tmpsport, opc_port[i].port, TimeString(prule));
                SystemIptablesRule(chcmd, bipv6, false);
                //按源端口开放
                sprintf(chcmd, "-A FORWARD -p %s --sport %s --dport %s %s -j ACCEPT\n",
                        opc_port[i].protocol, opc_port[i].port, tmpsport, TimeString(prule));
                SystemIptablesRule(chcmd, bipv6, false);
            }
        }

        //其他普通模块 如果未指定出口,且未勾选隐藏源地址,则什么也不做。
        if ((m_devbs->hidesrc) && (misip)) {
            for (int j = 0; j < prule->m_sobjectnum; j++) {
                sprintf(chcmd, "-A POSTROUTING %s %s %s --sport %s --dport %s -j SNAT --to %s\n",
                        RangeIpString('s', prule->m_sobject[j]->m_ipaddress),
                        RangeIpString('d', pdobj->m_ipaddress), ProtoString(pserv->m_protocol),
                        tmpsport, tmpdport, prule->m_specsip);
                SystemIptablesRule(chcmd, bipv6, true);
            }
        }
        //----------------------------------目的端响应----
        //响应通过ESTABLISHED过去
    } else {
        //黑名单策略 则什么也不做
    }
}

/**
 * [CYWBS::SetRouteTCPUDP 设置一条规则 路由模式 服务为TCP或UDP]
 * @param prule [规则指针]
 * @param pdobj [目的对象指针]
 * @param pserv [应用指针]
 */
void CYWBS::SetRouteTCPUDP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv)
{
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        SetRouteTCPUDPSrc(prule, pdobj, pserv);
    } else {
        SetRouteTCPUDPDst(prule, pdobj, pserv);
    }
}

/**
 * [CYWBS::SetRouteARule 设置一条规则 路由模式]
 * @param prule [规则指针]
 */
void CYWBS::SetRouteARule(CSYSRULES *prule)
{
    //设置规则中的对象路由
    if (IsCloseToSRCObj(prule->m_secway.getarea())) {
        for (int k = 0; k < prule->m_dobjectnum; k++) {
            SetRoute(prule->m_dobject[k]);
        }
    } else {
        for (int k = 0; k < prule->m_sobjectnum; k++) {
            SetRoute(prule->m_sobject[k]);
        }
    }

    for (int n = 0; n < prule->m_servicenum; n++) {
        for (int k = 0; k < prule->m_dobjectnum; k++) {
            if (IsTCPServ(prule->m_service[n]) || IsUDPServ(prule->m_service[n])) {

                SetRouteTCPUDP(prule, prule->m_dobject[k], prule->m_service[n]);
            } else if (IsICMPServ(prule->m_service[n])) {

                SetRouteICMP(prule, prule->m_dobject[k], prule->m_service[n]);
            } else if (IsICMPV6Serv(prule->m_service[n])) {
#if (SUPPORT_IPV6==1)
                SetRouteICMPV6(prule, prule->m_dobject[k], prule->m_service[n]);
#endif
            } else {
                PRINT_ERR_HEAD
                print_err("other protocol[%s]", prule->m_service[n]->m_protocol);
            }
        }//m_dobjectnum
    }//m_servicenum
}

/**
 * [CYWBS::RoutePrepare 路由模式准备工作
 * 对于RELATED,ESTABLISHED状态之外的连接 先默认设置为拒绝
 * 为了防止设置规则过程中到来的新连接非法通过]
 * @param flag [为true表示 准备，为false表示 清除准备]
 */
void CYWBS::RoutePrepare(bool flag)
{
    TransparentPrepare(flag);//目前 路由模式准备工作 与 透明模式的相同 直接调用它
}

/**
 * [CYWBS::SetRouteRule 设置路由模式规则]
 */
void CYWBS::SetRouteRule(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    PRINT_DBG_HEAD
    print_dbg("route mode");

    WriteSysLog(LOG_TYPE_WORK_MODE, D_SUCCESS, LOG_CONTENT_ROUTE);

    //检查是否还没设置IP
    if ((InIpNum() <= 0) || (OutIpNum() <= 0)) {
        if (m_sysrulesbs->m_sysrulenum > 0) {
            WriteSysLog(LOG_TYPE_IP_CK, D_FAIL, LOG_CONTENT_NO_IP);
            PRINT_ERR_HEAD
            print_err("set up business IP first.InIpNum %d, OutIpNum %d", InIpNum(), OutIpNum());
        }
        return;
    }

    RoutePrepare(true);

    WriteSysLog(LOG_TYPE_SET_RULE, D_SUCCESS, LOG_CONTENT_SET_RULE);
    for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
        SetRouteARule(m_sysrulesbs->m_sysrule[i]);
    }
    //设置路由模式下使用代理
    for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
        SetRouteProxy(m_sysrulesbs->m_sysrule[i]);
    }

    //最后添加MASQUERADE
    RouteHideSrc();

    sprintf(chcmd, "-A FORWARD -i eth%d -j ACCEPT\n", g_linklan);
    SystemIptablesRule(chcmd, false, false);
    sprintf(chcmd, "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
    SystemIptablesRule(chcmd, false, false);
    sprintf(chcmd, "-A FORWARD -j DROP\n");
    SystemIptablesRule(chcmd, false, false);
#if (SUPPORT_IPV6==1)
    ICMPv6Ext();
    sprintf(chcmd, "-A FORWARD -i eth%d -j ACCEPT\n", g_linklan);
    SystemIptablesRule(chcmd, true, false);
    sprintf(chcmd, "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
    SystemIptablesRule(chcmd, true, false);
    sprintf(chcmd, "-A FORWARD -j DROP\n");
    SystemIptablesRule(chcmd, true, false);
#endif
    RoutePrepare(false);
}

/**
 * [CYWBS::Start 启动业务处理程序]
 * @return [启动成功返回true]
 */
bool CYWBS::Start(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    CCommon common;

    GlobalAssign();

    if (s_b_inside) {
        file_tran_auth();
        file_tran_rule();
        LicenseModInit();
    }

    if (AnalysisLan() != 0) {
        WriteSysLog(LOG_TYPE_SECWAY_CK, D_FAIL, LOG_CONTENT_SECWAY_ERR);
        return false;
    }

    ClearAppServices();
    ClearNetConfig();
    InitNetConfig();
    LoadAuthUser(IPAUTH_CONF);
    IPStatistics();
    MakeBSIPMap(); //必须在RecordIptablesLog之前调用
    SetSSHD();
    SetDDOS();
    SetIDS();
    SetFtpNat();
    SetSnmp();
    SetSysMaxConn();
    SetTrunk();
    SetFilterKey();
    SetCKFileType();

    SetBonding(s_b_inside ? m_sysrulesbs->m_inbonding : m_sysrulesbs->m_outbonding);
    if (!SetIPInfo()) {
        return false;
    }
    RecordIptablesLog();

    switch (m_devbs->m_workflag) {
    case WORK_MODE_TRANSPARENT:
        SetTransparentRule();
        break;
    case WORK_MODE_PROXY:
        SetProxyRule();
        break;
    case WORK_MODE_ROUTE:
        SetRouteRule();
        break;
    default:
        PRINT_ERR_HEAD
        print_err("work mode error[%d]", m_devbs->m_workflag);
        return false;
    }

    if (0 != CreateIptablesFile()) {
        PRINT_ERR_HEAD
        print_err("create iptables file error");
        return false;
    }

    BindMac();
    SetRouteList();
    StartMulticast();
    StartSipNorm();
    StartClientSipNorm();
    SetPing();
    SetDefGW();
    SetDNS();
    CreateAppServices();
#ifdef USE_IPQUEUE_NETLINK
    StartIPQueueNetLink();
#elif defined USE_NFQUEUE_NETLINK
    StartNFQueueNetLink(MIN(MAX_IPTABLES_QUEUE_NUM, m_sysrulesbs->m_servicenum));
#else
    PRINT_ERR_HEAD
    print_err("neither ipqueue netlink nor nfqueue netlink defined");
#endif
    StartNetTimeSync();
    StartArping();
    StartIRQ();
    if (s_b_inside) {
        TranAuthThread();
        StartSyncTime();
        //SysLogThread();
        SMSThread();
        //为了让外网同步启动
        sleep(2);
    } else {
    }

    StartFileSync();
    if (!common.FileExist(NEW_DBSYNC_INIT_SH)) {
        PRINT_INFO_HEAD
        print_info("start old dbsync");
        StartDBSync();
    }
    StartWebProxy();
    StartLinkVideo();
    StartPDT();
    StartSipInterConnect();
    StartRFC3261();
    StartPvtFileSync();
    StartNginxProcess(&g_nginx);
    if (m_devbs->m_workflag == WORK_MODE_PROXY) {
        SetPortConnect();
    }
    MAKE_TABLESTRING(chcmd, "-t nat -A CHAIN1 -j ACCEPT", false);
    SystemCMD(chcmd);

#if (SUPPORT_IPV6==1)
    MAKE_TABLESTRING(chcmd, "-t nat -A CHAIN1 -j ACCEPT", true);
    SystemCMD(chcmd);
#endif

    AddlCard();
    SetMTU(s_b_inside ? g_ethin : g_ethout);
    WriteSysLog(LOG_TYPE_WORK_STATUS, D_SUCCESS, LOG_CONTENT_RUN_NORMAL);
    SystemCMD(CLEAN_TRACK_FILE);
    PRINT_INFO_HEAD
    print_info("work normal");
    return true;
}

/**
 * [CYWBS::StartMulticast 启动组播策略]
 */
void CYWBS::StartMulticast(void)
{
    if (m_devbs->m_workflag == WORK_MODE_TRANSPARENT) {
        StartMulticastTransparent();
    } else {
        StartMulticastNoTransparent();
    }
}

/**
 * [CYWBS::StartMulticastTransparent 透明模式下启动组播策略]
 */
void CYWBS::StartMulticastTransparent(void)
{
    m_sysrulesbs->m_multicast_mg.setTransparentIptables();
}

/**
 * [CYWBS::StartMulticastNoTransparent 非透明模式下启动组播策略]
 */
void CYWBS::StartMulticastNoTransparent(void)
{
    if (!m_sysrulesbs->m_multicast_mg.setTmpIP(InIpNum(), OutIpNum())) {
        if (m_sysrulesbs->m_multicast_mg.taskNum() > 0) {
            WriteSysLog(LOG_TYPE_IP_CK, D_FAIL, LOG_CONTENT_NO_IP);
            PRINT_ERR_HEAD
            print_err("you should set up business IP first");
        }
        return;
    }
    m_sysrulesbs->m_multicast_mg.run();
}

/**
 * [CYWBS::StartLinkVideo 开启视频联动]
 */
void CYWBS::StartLinkVideo(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    StartLinkService();
    StartSipLink();
    StartClientSipLink();
}

/**
 * [CYWBS::StartLinkService 开启联动节点转发服务]
 */
void CYWBS::StartLinkService(void)
{
    char tmpip[IP_STR_LEN] = {0};
    MakeV4NatIP(!s_b_inside, g_linklanipseg, -1, tmpip, sizeof(tmpip));
    RunLinkService(s_b_inside, tmpip);
}

/**
 * [CYWBS::StartSipLink 开启平台级联联动]
 */
void CYWBS::StartSipLink(void)
{
    CSipLink *psip = NULL;

    for (int i = 0; i < m_sysrulesbs->m_siplinknum; i++) {
        psip = m_sysrulesbs->m_siplink[i];

        if (psip->isProtoSIP()) {
            if (psip->getArea() != 0) {
                psip->swapGapIp();
            }
            if (IsCloseToSRCObj(psip->getArea())) {
                if (psip->setTmpIp2(FoundLinkIPAddress(psip->getGapInIp()))
                    &&  psip->setTmpIp1(FoundToLinkIPAddress(psip->getGapOutIp()))) {
                    psip->srcStart();
                }
            } else {
                if (psip->setTmpIp2(FoundToLinkIPAddress(psip->getGapInIp()))
                    &&  psip->setTmpIp1(FoundLinkIPAddress(psip->getGapOutIp()))) {
                    psip->dstStart();
                }
            }
        }
    }
}

/**
 * [CYWBS::StartClientSipLink 开启视频代理联动]
 */
void CYWBS::StartClientSipLink(void)
{
    CClientSipLink *psip = NULL;

    for (int i = 0; i < m_sysrulesbs->m_clientsiplinknum; i++) {
        psip = m_sysrulesbs->m_clientsiplink[i];
        if (psip->isProtoSIP()) {
            if (IsCloseToSRCObj(psip->getArea())) {
                if (psip->setTmpIp2(FoundLinkIPAddress(psip->getGapInIp()))
                    && psip->setTmpIp1(FoundToLinkIPAddress(psip->getGapOutIp()))) {
                    psip->srcStart();
                }
            } else {
                if (psip->setTmpIp2(FoundToLinkIPAddress(psip->getGapInIp()))
                    && psip->setTmpIp1(FoundLinkIPAddress(psip->getGapOutIp()))) {
                    psip->dstStart();
                }
            }
        }
    }
}

/**
 * [CYWBS::StartIRQ 开启IRQ线程]
 */
void CYWBS::StartIRQ(void)
{
    if (m_irq_th == NULL) {
        m_irq_th = new CThread;
    }

    if (m_irq_th != NULL) {
        m_irq_th->ThCreate(IRQProcess, NULL);
    } else {
        PRINT_ERR_HEAD
        print_err("new irq thread fail");
    }
}

/**
 * [CYWBS::IRQProcess 执行irq脚本的线程函数]
 * @param  param [未使用]
 * @return       [无特殊含义]
 */
void *CYWBS::IRQProcess(void *param)
{
    pthread_setname("irqproc");
    sleep(10);
    system(IRQ_SH_PATH);
    return NULL;
}

#if 0
#if (SUPPORT_DPDK==1)
/**
 * [CYWBS::JudgeDPDK 判断是否符合启动DPDK的条件 如果不符合就还按桥来处理]
 * @return [符合开启DPDK的条件就返回true]
 */
bool CYWBS::JudgeDPDK(void)
{
    if (m_devbs->m_ckdpdk) {
        if (m_sysrulesbs->m_sysrulenum < 1) {
            m_devbs->m_ckdpdk = false;
            goto _out;
        }

        //查找有没有拒绝的规则 若有则存放第一个拒绝规则的下标
        int nindex = -1;
        for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
            if (!m_sysrulesbs->m_sysrule[i]->Action) {
                nindex = i;
                break;
            }
        }
        //全部都是允许的规则 则使用第一条规则的
        if (nindex == -1) {
            nindex = 0;
        }

        m_devbs->m_dpdk_dynamic_inlan = m_sysrulesbs->m_sysrule[nindex]->m_secway.getindev();
        m_devbs->m_dpdk_dynamic_outlan = m_sysrulesbs->m_sysrule[nindex]->m_secway.getoutdev();

        if ((m_devbs->m_dpdklan < 0)
            || (m_devbs->m_dpdklan == m_devbs->m_cslan)
            || (m_devbs->m_dpdklan == m_devbs->m_linklan)
            || (m_devbs->m_dpdklan == m_devbs->m_dpdk_dynamic_inlan)
            || (m_devbs->m_dpdklan == m_devbs->m_dpdk_dynamic_outlan)) {

            PRINT_ERR_HEAD
            print_err("m_dpdk_dynamic_inlan[%d],m_dpdk_dynamic_outlan[%d],"
                      "m_dpdklan[%d],m_linklan[%d],m_cslan[%d],check dpdk fail",
                      m_devbs->m_dpdk_dynamic_inlan, m_devbs->m_dpdk_dynamic_outlan,
                      m_devbs->m_dpdklan, m_devbs->m_linklan, m_devbs->m_cslan);
            m_devbs->m_ckdpdk = false;
            WriteSysLog(LOG_TYPE_FAST_TRAN, D_FAIL, LOG_CONTENT_FAST_TRAN_FAIL);
        }
    }

_out:
    return m_devbs->m_ckdpdk;
}
#endif
#endif
/**
 * [CYWBS::StartPDT 开启PDT相关任务]
 */
void CYWBS::StartPDT(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    StartPDTCommon();
}

/**
 * [CYWBS::StartPDTCommon 开启PDT互联普通任务]
 */
void CYWBS::StartPDTCommon(void)
{
    PRINT_DBG_HEAD
    print_dbg("start pdt common begin,common rulenum[%d]", m_sysrulesbs->m_pdt_com_num);

    CPDTCommon *pdt = NULL;

    for (int i = 0; i < m_sysrulesbs->m_pdt_com_num; i++) {
        pdt = m_sysrulesbs->m_pdtcom[i];
        if (pdt->isProtoPSIP()) {
            if (s_b_inside) {
                if (pdt->setInnerOutIp(FoundLinkIPAddress(pdt->getGapInIp()))
                    && pdt->setInnerInIp(FoundToLinkIPAddress(pdt->getGapOutIp()))) {
                    pdt->inStart();
                }
            } else {
                if (pdt->setInnerOutIp(FoundToLinkIPAddress(pdt->getGapInIp()))
                    && pdt->setInnerInIp(FoundLinkIPAddress(pdt->getGapOutIp()))) {
                    pdt->outStart();
                }
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("start pdt common over");
}

/**
 * [CYWBS::StartSipInterConnect 开启平台互联相关任务]
 */
void CYWBS::StartSipInterConnect(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    PRINT_DBG_HEAD
    print_dbg("start sip interconnect begin, rulenum[%d]", m_sysrulesbs->m_sipinterconnectnum);
    CSipInterConnect *sip_interconnect = NULL;
    for (int i = 0; i < m_sysrulesbs->m_sipinterconnectnum; i++) {
        sip_interconnect = m_sysrulesbs->m_sipinterconnect[i];
        if (sip_interconnect->isProtoSIP()) {
            StartSipInterConnectNorm(sip_interconnect);
        }
    }
}

/**
 * [CYWBS::StartSipInterConnectNorm 开启一个平台互联普通任务]
 */
void CYWBS::StartSipInterConnectNorm(CSipInterConnect *sip_interconnect)
{
    if (SIP_FUN_INTERCONNECT_MODE == sip_interconnect->getMode()) {
        if (s_b_inside) {
            if (sip_interconnect->setInnerOutIp(FoundLinkIPAddress(sip_interconnect->getGapInIp()))
                && sip_interconnect->setInnerInIp(FoundToLinkIPAddress(sip_interconnect->getGapOutIp()))) {
                sip_interconnect->inStart();
            } else {
                goto _err;
            }
        } else {
            if (sip_interconnect->setInnerOutIp(FoundToLinkIPAddress(sip_interconnect->getGapInIp()))
                && sip_interconnect->setInnerInIp(FoundLinkIPAddress(sip_interconnect->getGapOutIp()))) {
                sip_interconnect->outStart();
            } else {
                goto _err;
            }
        }
    } else {
        if (sip_interconnect->getArea() != 0) {
            sip_interconnect->swapInfo();
        }

        if (IsCloseToSRCObj(sip_interconnect->getArea())) {
            if (sip_interconnect->setInnerOutIp(FoundLinkIPAddress(sip_interconnect->getGapInIp()))
                && sip_interconnect->setInnerInIp(FoundToLinkIPAddress(sip_interconnect->getGapOutIp()))) {
                sip_interconnect->inStart();
            } else {
                goto _err;
            }
        } else {
            if (sip_interconnect->setInnerOutIp(FoundToLinkIPAddress(sip_interconnect->getGapInIp()))
                && sip_interconnect->setInnerInIp(FoundLinkIPAddress(sip_interconnect->getGapOutIp()))) {
                sip_interconnect->outStart();
            } else {
                goto _err;
            }
        }
    }
    PRINT_DBG_HEAD
    print_dbg("start sip interconnect over");
    return;

_err:
    PRINT_ERR_HEAD
    print_err("interconnect set inner IP fail");
}

void CYWBS::StartRFC3261(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    PRINT_DBG_HEAD
    print_dbg("start rfc3261 tasknum[%d]", m_sysrulesbs->m_rfc3261_tasknum);
    RFC3261SIP *psip = NULL;

    for (int i = 0; i < m_sysrulesbs->m_rfc3261_tasknum; i++) {
        psip = m_sysrulesbs->m_rfc3261[i];
        if (psip->checkProto()) {
            if (s_b_inside) {
                if (psip->setInnerOutIp(FoundLinkIPAddress(psip->getGapInIp()))
                    && psip->setInnerInIp(FoundToLinkIPAddress(psip->getGapOutIp()))) {
                    psip->inStart();
                } else {
                    PRINT_ERR_HEAD
                    print_err("set inner ip fail");
                    break;
                }
            } else {
                if (psip->setInnerOutIp(FoundToLinkIPAddress(psip->getGapInIp()))
                    && psip->setInnerInIp(FoundLinkIPAddress(psip->getGapOutIp()))) {
                    psip->outStart();
                } else {
                    PRINT_ERR_HEAD
                    print_err("set inner ip fail");
                    break;
                }
            }
        }
    }
}

/**
 * [CYWBS::StartPvtFileSync 开启私有协议文件同步任务]
 */
void CYWBS::StartPvtFileSync(void)
{
    char natip4[IP_STR_LEN] = {0};
    char natip6[IP_STR_LEN] = {0};
    int ipoffset = InIpNum();

    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    MakeV4NatIP(false, g_linklanipseg, ipoffset + 1, natip4, sizeof(natip4));
#if (SUPPORT_IPV6==1)
    MakeV6NatIP(false, g_linklanipseg, ipoffset + 2, natip6, sizeof(natip6));
#endif
    m_sysrulesbs->m_pvt_filesync_mg.setNatIP(natip4, natip6);
    m_sysrulesbs->m_pvt_filesync_mg.setNatIP();
    if (s_b_inside) {
        g_pvtf_num = m_sysrulesbs->m_pvt_filesync_mg.taskNum();
        if (LicenseModCK(MOD_TYPE_FILESYNC)) {
            if (g_pvtf_num > 0) {
                m_sysrulesbs->m_pvt_filesync_mg.writeConf();
            }
            PvtFileSyncProcess();
        }
    } else {
        m_sysrulesbs->m_pvt_filesync_mg.setOutIptables();
    }

    PRINT_DBG_HEAD
    print_dbg("start pvt filesync over");
    return ;
}

/**
 * [CYWBS::LicenseModCK 模块授权检查]
 * @param  modtype [模块类型]
 * @return         [有权限返回true]
 */
bool CYWBS::LicenseModCK(int modtype)
{
    bool bflag = false;
    if (m_plicensemod != NULL) {
        bflag = m_plicensemod->have_right(modtype);
    } else {
        PRINT_ERR_HEAD
        print_err("plicensemod null");
    }

    PRINT_DBG_HEAD
    print_dbg("mod type[%d] %s", modtype, bflag ? "OK" : "Unauthorized");
    return bflag;
}

/**
 * [CYWBS::SetSSHD 设置SSH管理]
 */
void CYWBS::SetSSHD(void)
{
    if (s_b_inside) {
        SystemCMD("killall -9 sshd >/dev/null 2>&1");

        PRINT_DBG_HEAD
        print_dbg("sshd is %s", m_devbs->m_cksshd ? "open" : "closed");

        if (m_devbs->m_cksshd) {
            SystemCMD("/sbin/sshd &");
        }
    }
}

/**
 * [CYWBS::IPStatistics 业务IP统计分类]
 */
void CYWBS::IPStatistics(void)
{
    for (int i = 0; i < m_devbs->m_innet.myipnum; ++i) {
        if (m_devbs->m_innet.myip[i].TYPE == IP_TYPE6) {
            m_in_ipv6num++;
        } else {
            m_in_ipv4num++;
        }
    }

    for (int i = 0; i < m_devbs->m_outnet.myipnum; ++i) {
        if (m_devbs->m_outnet.myip[i].TYPE == IP_TYPE6) {
            m_out_ipv6num++;
        } else {
            m_out_ipv4num++;
        }
    }

    for (int i = 0; i < m_sysrulesbs->m_inbonding->ipnum; ++i) {
        if (m_sysrulesbs->m_inbonding->iptype[i] == IP_TYPE6) {
            m_in_ipv6num++;
        } else {
            m_in_ipv4num++;
        }
    }

    for (int i = 0; i < m_sysrulesbs->m_outbonding->ipnum; ++i) {
        if (m_sysrulesbs->m_outbonding->iptype[i] == IP_TYPE6) {
            m_out_ipv6num++;
        } else {
            m_out_ipv4num++;
        }
    }

    PRINT_INFO_HEAD
    print_info("inipv4[%d] inipv6[%d] outipv4[%d] outipv6[%d]", m_in_ipv4num, m_in_ipv6num,
               m_out_ipv4num, m_out_ipv6num);

    RoutePeer();
}

/**
 * [CYWBS::DnatString 组装DNAT的跳转字符串]
 * @param  ip   [IP]
 * @param  port [端口 或 端口范围]
 * @return      [返回指向组装好的字符串的指针]
 */
const char *CYWBS::DnatString(const char *ip, const char *port)
{
    BZERO(m_tmpdnat);

    PRINT_DBG_HEAD
    print_dbg("make dnat string.ip[%s] port[%s]", ip, port);

    if (ip == NULL) {
        if (port == NULL) {
            PRINT_ERR_HEAD
            print_err("ip and port null.");
        } else {
            sprintf(m_tmpdnat, ":%s", port);
        }
    } else {
        if (port == NULL) {
            sprintf(m_tmpdnat, "%s", ip);
        } else {
            if (is_ip6addr(ip)) {
                sprintf(m_tmpdnat, "[%s]:%s", ip, port);
            } else {
                sprintf(m_tmpdnat, "%s:%s", ip, port);
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("make dnat string over. %s", m_tmpdnat);
    return m_tmpdnat;
}

/**
 * [CYWBS::RoutePeer 计算对端的内部通信IP 路由模式 把下一跳设置为网闸对端时 对端的IP]
 */
void CYWBS::RoutePeer(void)
{
    int ipv4 = -1;
    int ipv6 = -1;

    SDEVINFO &devinfo = s_b_inside ? m_devbs->m_innet : m_devbs->m_outnet;
    CBonding *bonding = s_b_inside ? m_sysrulesbs->m_inbonding : m_sysrulesbs->m_outbonding;

    for (int i = 0; i < devinfo.myipnum; ++i) {
        if (devinfo.myip[i].TYPE == IP_TYPE6) {
            if (ipv6 < 0) {ipv6 = i;}
        } else {
            if (ipv4 < 0) {ipv4 = i;}
        }
    }
    for (int i = 0; i < bonding->ipnum; ++i) {
        if (bonding->iptype[i] == IP_TYPE6) {
            if (ipv6 < 0) {ipv6 = i + devinfo.myipnum;}
        } else {
            if (ipv4 < 0) {ipv4 = i + devinfo.myipnum;}
        }
    }

    if (ipv4 >= 0) {
        MakeV4NatIP(!s_b_inside, g_linklanipseg, ipv4 + 1, m_route4_peer, sizeof(m_route4_peer));
    }

    if (ipv6 >= 0) {
#if (SUPPORT_IPV6==1)
        MakeV6NatIP(!s_b_inside, g_linklanipseg, ipv6 + 1, m_route6_peer, sizeof(m_route6_peer));
#endif
    }

    PRINT_DBG_HEAD
    print_dbg("ipv4 num  %d, ipv6 num %d. route4peer [%s], route6peer [%s]", ipv4, ipv6,
              m_route4_peer, m_route6_peer);
}

/**
 * [CYWBS::MakeBSIPMap 整理本侧业务IP与映射IP对应关系]
 */
void CYWBS::MakeBSIPMap(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);

    char tmpip[IP_STR_LEN] = {0};

    SDEVINFO &devinfo = s_b_inside ? m_devbs->m_innet : m_devbs->m_outnet;
    for (int i = 0; i < devinfo.myipnum; i++) {
        if (devinfo.myip[i].ID >= 0) {
            if (devinfo.myip[i].TYPE == IP_TYPE6) {
                MakeV6NatIP(!s_b_inside, g_linklanipseg, i + 1, tmpip, sizeof(tmpip));
            } else {
                MakeV4NatIP(!s_b_inside, g_linklanipseg, i + 1, tmpip, sizeof(tmpip));
            }
            g_bsipmap[tmpip] = devinfo.myip[i].IP;
        }
    }

    CBonding *binding = s_b_inside ? m_sysrulesbs->m_inbonding : m_sysrulesbs->m_outbonding;
    for (int i = 0; i < binding->ipnum; i++) {
        if (binding->iptype[i] == IP_TYPE6) {
            MakeV6NatIP(!s_b_inside, g_linklanipseg, devinfo.myipnum + i + 1, tmpip, sizeof(tmpip));
        } else {
            MakeV4NatIP(!s_b_inside, g_linklanipseg, devinfo.myipnum + i + 1, tmpip, sizeof(tmpip));
        }
        g_bsipmap[tmpip] = binding->ipaddr[i];
    }
#if 1
    map<string, string>::iterator iter = g_bsipmap.begin();
    for (; iter != g_bsipmap.end(); iter++) {
        PRINT_INFO_HEAD
        print_info("IP[%s]-->IP[%s]", iter->first.c_str(), iter->second.c_str());
    }
#endif
}
