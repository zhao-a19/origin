/*******************************************************************************************
*文件:  FCYWBS.cpp
*描述:  业务处理实现文件
*作者:  王君雷
*日期:  2015
*
*修改:
*        透明模式下只要出现范围端口,就不用ebtables控制方向了           ------> 2016-01-13
*        路由列表支持后台执行syscmdback                                ------> 2016-01-13
*        缩小Start函数体大小,封装多个函数,像
*        SetBonding、UpCards、AppendFTPPort、SetIPInfo、SetSnmp、
*        SetPing、SetDNS、WriteSysLog、CKRunLogSize等                  ------> 2016-01-20
*        封装函数_SetRouteList。
*        视频交换POSTROUTING中加规则,防止MASQUERADE意外的转换源地址    ------> 2016-01-22
*        修改了一个bug,当没有任何平台级联策略时,视频代理会段错误       ------> 2016-03-02
*        添加单独的IP MAC绑定策略功能                                  ------> 2016-03-10
*        移除处理触发消息的线程,减少重启、初始化等操作对sys6的依赖     ------> 2016-04-29
*        数据库同步程序集成到网闸内部                                  ------> 2016-05-27
*        添加CSM模块                                                   ------> 2016-06-01
*        负载均衡支持界面配置不同模式                                  ------> 2016-06-29
*        修改代理模式FORWARD加规则不严格的问题                         ------> 2016-08-24
*        添加RTP PDXP_UDP PDXP_TCP RECP FEP五个(航天军队)定制模块      ------> 2016-11-07
*        透明模式，使用iptables严格控制方向，不再使用ebtables控制      ------> 2017-06-01
*        添加S7、DNP3、IEC104、IEC61850_MMS、DDE、PROIFBUS、PROFINET等
*        多种工业模块支持，暂时只保证通过，不过滤命令参数              ------> 2017-10-09
*        添加模块授权管理功能                                          ------> 2018-01-08
*        改用UTF8编码,改用linux缩进格式                                ------> 2018-01-22
*        设置系统最大并发数时允许设置的值不应该小于SYS_MAX_CONN_LOW    ------> 2018-01-26
*        透明模式设置规则前先设置为DROP,防止规则还没设置完业务已过去   ------> 2018-01-30
*        读取模块授权文件失败，就把文件交换、数据库同步模块权限设置为0 ------> 2018-02-05
*        重写Start函数，缩减函数体                                     ------> 2018-02-05
*        当开启抗ddos时,规则中的并发数,按针对每一个客户端的连接数处理  ------> 2018-02-26
*        视频相关函数命名统一风格                                      ------> 2018-04-23
*        添加执行irq.sh脚本的线程                                      ------> 2018-05-18
*        添加调用ClearDPDK函数,为添加DPDK功能做准备,开发过程版         ------> 2018-05-21
*        视频联动支持多个节点转发                                      ------> 2018-07-14
*        加入PDT互联                                                   ------> 2018-07-31
*        完善zlog信息；完善函数注释信息                                ------> 2018-09-05
*        支持SSH管理设备                                               ------> 2018-11-01
*        修改inet_ntop返回值判断有误，180814引入的问题，路由模式会异常 ------> 2018-11-03
*        修改iptables只控制SYN包、不控制后续包导致管理者地址控制不住问
*        题；修改系统最大连接数范围判断                                ------> 2018-11-19
*        去除ICMPMAP相关内容，因为使用不到了                           ------> 2018-12-27
*        路由模式，根据规则产生的路由metric值设置为100                 ------> 2019-01-03
*        ipv6支持开发过程版                                            ------> 2019-01-30
*        通过宏控制是否启用IPV6支持,开发过程版                         ------> 2019-02-12
*        重新封装IP端口映射关系类                                      ------> 2019-02-14
*        关键字过滤、用户身份认证支持IPV6                              ------> 2019-02-18
*        关键字过滤，支持UTF8格式                                      ------> 2019-05-14
*        WEB代理可以支持ipv6                                           ------> 2019-05-21
*        文件交换支持IPV6                                              ------> 2019-06-08
*        SNMP告警支持IPV6                                              ------> 2019-06-14
*        通过配置项，可以选择是否使用nginx实现web代理功能              ------> 2019-06-19
*        修改基于SMB的文件交换模块，设置业务IP错误的BUG                ------> 2019-06-20
*        修改基于SMB的文件交换模块，外网备份目录设置错误的BUG          ------> 2019-06-22
*        解决IPV6路由模式重启策略没有清空上次的路由信息的BUG           ------> 2019-07-08
*        加入平台互联                                                  ------> 2019-07-31 -dzj
*        系统初始化时，UP所有网卡                                      ------> 2019-09-02
*        路由列表支持appproxy6用法                                     ------> 2019-09-09
*        加入OPCUA模块                                                 ------> 2019-10-08 -dzj
*        解决OPCUA端口改变不可解析的问题                               ------> 2019-10-10 -dzj
*        修改管理者IP控制BUG：当为掩码格式时组iptables有误控制不住访问，
*        190212引入的问题                                              ------> 2019-10-28
*        设置管理口路由                                                ------> 2019-11-19-dzj
*        添加DDOS拦截功能                                              ------> 2019-12-01-dzj
*        修改设置iptables规则为iptables-restore方式                    ------> 2019-12-01-dzj
*        函数接口名称拼写错误                                          ------> 2019-12-09-dzj
*        WEB代理支持双机热备拔线切换                                   ------> 2019-12-17 wjl
*        文件交换、数据库同步模块支持双机热备                          ------> 2019-12-19 wjl
*        管理口路由添加移动到添加路由接口里执行                        ------> 2019-12-13 dzj
*        设置IPTABLES，控制外部访问设备的SYSLOG服务                    ------> 2020-01-16 wjl
*        加入SNMP模块                                                  ------> 2020-01-17 -dzj
*        V6以外的版本使用系统自带的awk，不需要拷贝部署                 ------> 2020-04-27 wjl
*        解决关键字太多时iptables执行慢的问题                         ------> 2020-05-18
*        解决iptables关键字过滤有时过滤不住的问题                      ------> 2020-07-17
*        指令列表中的route语句过滤>&|符号                             ------> 2020-07-30
*        文件交换，外网侧设置iptables时不指定端口139 445              ------> 2020-08-25
*        启动snmpd时，添加-C参数，解决飞腾平台snmpd获取不到信息的问题  ------> 2020-09-20
*        文件类型过滤支持分模块生效、去除相关全局变量                  ------> 2020-11-03
*        私有文件交换支持分模块生效                                  ------> 2020-11-05
*        文件交换支持分模块生效                                      ------> 2020-11-10
*        组播支持分模块生效                                          ------> 2020-11-12
*        WEB代理支持分模块生效                                       ------> 2020-11-18
*        IPMAC绑定使用自定义链FILTER_MAC                             ------> 2020-11-25
*        优化程序，应用模块只在必要时才进iptables队列                  ------> 2020-12-10
*        修改文件交换、私有文件交换、web代理自定义链跳转位置错误          ------> 2020-12-17
*        透明模式不开启Trunk时，通过ebtables丢弃所有802.1q包          ------> 2021-04-28 wjl
*******************************************************************************************/
#include "FCYWBS.h"
#include "video_mod.h"
#include "industry_mod.h"
#include "database_mod.h"
#include "common_mod.h"
#include "user_mod.h"
#include "debugout.h"

vector<string> g_vec_FilterKey;
vector<string> g_vec_FilterKeyUTF8;
vector<int> g_ethin;//内网通信口
vector<int> g_ethout;//外网通信口
bool g_cardchange = true;
CardMG g_cardmg;
NGINX_MANAGER g_nginx;

bool g_ckauth = false;
bool g_iflog = false;
bool g_syslog = false;
bool g_ckkey = false;
int g_workflag = WORK_MODE_PROXY;
int g_linklan = 0;
int g_linklanipseg = 1; //网闸内部通信口IP网段
int g_linklanport = DEFAULT_LINK_PORT;
int g_noticeport = DEFAULT_NOTICE_PORT;
char g_csip[IP_STR_LEN] = {0};
map<string, string> g_bsipmap; //存放本侧业务IP与映射内联IP的对应关系

const bool s_b_inside = (DEVFLAG[0] == 'I');

CYWBS::CYWBS(void)
{
    m_sysrulesbs = new CSYSRULESBUSINESS;
    if (m_sysrulesbs == NULL) {
        PRINT_ERR_HEAD
        print_err("new sysrules business fail");
    }
    while (m_log.Init() != E_OK) {
        PRINT_ERR_HEAD
        print_err("log init fail, retry");
        sleep(1);
    }
    m_devbs = NULL;
    g_nginx.clear();
    m_plicensemod = NULL;
    m_arping_th = NULL;
    m_irq_th = NULL;
    m_in_ipv4num = m_in_ipv6num = m_out_ipv4num = m_out_ipv6num = 0;
    BZERO(m_route4_peer);
    BZERO(m_route6_peer);
    m_rulemg_nat4.init("nat", false);
    m_rulemg_nat6.init("nat", true);
    m_rulemg_filter4.init("filter", false);
    m_rulemg_filter6.init("filter", true);
}

CYWBS::~CYWBS(void)
{
    DELETE(m_sysrulesbs);
    m_log.DisConnect();
    DELETE(m_plicensemod);
    DELETE(m_arping_th);
    DELETE(m_irq_th);
}

/**
 * [CYWBS::LoadData 加载配置信息]
 * @return [成功返回true]
 */
bool CYWBS::LoadData(void)
{
    PRINT_DBG_HEAD
    print_dbg("begin load data");

    char chsyslog[SYSLOG_BUF_LEN] = {0};
    CCommon common;

    m_sysrulesbs->ClearAllData();

    if (m_sysrulesbs->ImportRules(RULE_CONF) != E_FILE_OK) {
        sprintf(chsyslog, "%s[%s]", LOG_CONTENT_OPEN_FILE_ERR, RULE_CONF);
        WriteSysLog(LOG_TYPE_CFG, D_FAIL, chsyslog);
        PRINT_ERR_HEAD
        print_err("read rules conf fail[%s]", RULE_CONF);
        goto _err;
    }
    m_sysrulesbs->m_multicast_mg.loadConf();
    if (m_sysrulesbs->ImportSipNorm(SIP_CONF) != E_FILE_OK) {
        sprintf(chsyslog, "%s[%s]", LOG_CONTENT_OPEN_FILE_ERR, SIP_CONF);
        WriteSysLog(LOG_TYPE_CFG, D_FAIL, chsyslog);
        PRINT_ERR_HEAD
        print_err("read sip norm conf fail[%s]", SIP_CONF);
    }

    m_sysrulesbs->ImportClientSipNorm(SIP_CONF);
    m_sysrulesbs->ImportSipLink(LINK_SIP_CONF);
    m_sysrulesbs->ImportClientSipLink(LINK_SIP_CONF);
    m_sysrulesbs->m_filesync_mg.loadConf();
    if (!common.FileExist(NEW_DBSYNC_INIT_SH)) {
        if (m_sysrulesbs->ImportDBSync(DBSYNC_CONF) != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("read dbsync conf fail[%s]", DBSYNC_CONF);
        }
    }

    if (m_sysrulesbs->ImportBonding(BONDING_CONF) != E_FILE_OK) {
        sprintf(chsyslog, "%s[%s]", LOG_CONTENT_OPEN_FILE_ERR, BONDING_CONF);
        WriteSysLog(LOG_TYPE_CFG, D_FAIL, chsyslog);
        PRINT_ERR_HEAD
        print_err("read bonding conf fail[%s]", BONDING_CONF);
        goto _err;
    }

    if ((m_devbs != NULL) && (m_devbs->m_workflag == WORK_MODE_PROXY)) {
        m_sysrulesbs->m_webproxy_mg.loadConf();
    }

    m_sysrulesbs->ImportPDTCommon(PDT_CONF);
    m_sysrulesbs->m_pvt_filesync_mg.loadConf();
    m_sysrulesbs->ImportSipInterConnect(SIP_INTER_CNT_CONF);
    m_sysrulesbs->ImportRFC3261(SIP_INTER_CNT_CONF);

    PRINT_DBG_HEAD
    print_dbg("load data over");
    return true;
_err:

    PRINT_ERR_HEAD
    print_err("load data fail");
    return false;
}

/**
 * [CYWBS::SetDevBS 设置DevBS指针对象]
 * @param p_devbs [description]
 */
void CYWBS::SetDevBS(CDEVBS *p_devbs)
{
    m_devbs = p_devbs;
}

/**
 * [CYWBS::BindMac 绑定MAC]
 * @param ip  [ip]
 * @param mac [mac]
 * @param iptype [IP类型]
 */
void CYWBS::BindMac(const char *ip, const char *mac, int iptype)
{
    if ((ip == NULL) || (mac == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while bind mac[ip %s, mac %s,type %d]", ip, mac, iptype);
        return ;
    }
    char chcmd[CMD_BUF_LEN] = {0};

    if (strcmp(mac, ALLMAC) != 0) {
        if (iptype == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
            struct sockaddr_in6 addr6 = {0};
            if ((!IPV6_ALL_OBJ(ip)) && (inet_pton(AF_INET6, ip, (void *)&addr6.sin6_addr) > 0)) {
                MAKE_TABLESTRING(chcmd, "-A FILTER_MAC -s %s -m mac ! --mac-source '%s' -j DROP", true, ip, mac);
                system_safe(chcmd);
            }
#endif
        } else {
            struct sockaddr_in addr = {0};
            if ((!ALL_OBJ(ip)) && (inet_pton(AF_INET, ip, (void *)&addr.sin_addr) > 0)) {
                MAKE_TABLESTRING(chcmd, "-A FILTER_MAC -s %s -m mac ! --mac-source '%s' -j DROP", false, ip, mac);
                system_safe(chcmd);
                sprintf(chcmd, "arp -s '%s' '%s'", ip, mac);
                system_safe(chcmd);
            }
        }
    }
}

/**
 * [CYWBS::BindMac 绑定MAC]
 */
void CYWBS::BindMac(void)
{
    //系统规则对象中定义的ipmac绑定信息
    for (int i = 0; i < m_sysrulesbs->m_objectnum; i++) {
        BindMac(m_sysrulesbs->m_object[i]->m_ipaddress,
                m_sysrulesbs->m_object[i]->m_mac,
                m_sysrulesbs->m_object[i]->m_iptype);
    }

    //以下为单独定义的ipmac绑定组
    if (m_devbs->m_ckmacbind) {
        PRINT_DBG_HEAD
        print_dbg("mac bind is true");

        if (s_b_inside) {
            for (int i = 0; i < m_devbs->m_macbindnum; i++) {
                if ((m_devbs->m_macbind[i].area == BINDMAC_AREA_ALL)
                    || (m_devbs->m_macbind[i].area == BINDMAC_AREA_INNET)) {
                    BindMac(m_devbs->m_macbind[i].ip,
                            m_devbs->m_macbind[i].mac,
                            m_devbs->m_macbind[i].iptype);
                }
            }
        } else {
            for (int i = 0; i < m_devbs->m_macbindnum; i++) {
                if ((m_devbs->m_macbind[i].area == BINDMAC_AREA_ALL)
                    || (m_devbs->m_macbind[i].area == BINDMAC_AREA_OUTNET)) {
                    BindMac(m_devbs->m_macbind[i].ip,
                            m_devbs->m_macbind[i].mac,
                            m_devbs->m_macbind[i].iptype);
                }
            }
        }
    }
}

/**
 * [CYWBS::Replace 替换字符]
 * @param  src [待处理的字符串]
 * @param  s   [被替换的源字符]
 * @param  d   [替换的目的字符]
 * @return     [指向替换后的字符串的指针]
 */
char *CYWBS::Replace(const char *src, char s, char d)
{
    BZERO(m_chres);
    strcpy(m_chres, src);
    for (int i = 0; i < (int)strlen(m_chres); i++) {
        if (m_chres[i] == s) {
            m_chres[i] = d;
        }
    }

    return m_chres;
}

/**
 * [CYWBS::CreateOneApp 把一个处理对象添加到全局变量中]
 * @param service [服务指针]
 * @param single  [处理对象指针]
 */
void CYWBS::CreateOneApp(CSERVICECONF *service, CSINGLE *single)
{
    if ((service == NULL) || (single == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null. service %p, single %p", service, single);
        return;
    }

    PRINT_DBG_HEAD
    print_dbg("create app begin[%s]", service->m_name);

    if (strcasecmp("TCP", service->m_protocol) == 0) {
        g_tcpapp[g_tcpappnum] = single;
        g_tcpapp[g_tcpappnum]->SetRecordFlag(service->m_cklog);
        g_tcpapp[g_tcpappnum]->SetService(service);
        //查找m_ipportmap_vec中是否有该应用
        for (int j = 0; j < (int)m_ipportmap_vec.size(); j++) {
            g_tcpapp[g_tcpappnum]->AddToMap(m_ipportmap_vec[j]);
        }
        g_tcpappnum++;
    } else if (strcasecmp("UDP", service->m_protocol) == 0) {
        g_udpapp[g_udpappnum] = single;
        g_udpapp[g_udpappnum]->SetRecordFlag(service->m_cklog);
        g_udpapp[g_udpappnum]->SetService(service);
        //查找m_ipportmap_vec中是否有该应用
        for (int j = 0; j < (int)m_ipportmap_vec.size(); j++) {
            g_udpapp[g_udpappnum]->AddToMap(m_ipportmap_vec[j]);
        }
        g_udpappnum++;
    } else if (strcasecmp("ICMP", service->m_protocol) == 0) {
        g_icmpapp = single;
        g_icmpapp->SetRecordFlag(service->m_cklog);
        g_icmpapp->SetService(service);
        g_icmpappnum++;
    } else if (strcasecmp("ICMPV6", service->m_protocol) == 0) {
        g_icmpv6app = single;
        g_icmpv6app->SetRecordFlag(service->m_cklog);
        g_icmpv6app->SetService(service);
        g_icmpv6appnum++;
    }

    PRINT_DBG_HEAD
    print_dbg("create app over[%s]", service->m_name);
}

/**
 * [CYWBS::CreateAppServices 创建服务处理对象]
 */
void CYWBS::CreateAppServices(void)
{
    g_tcpappnum = 0;
    g_udpappnum = 0;
    g_icmpappnum = 0;
    g_icmpv6appnum = 0;

    PRINT_DBG_HEAD
    print_dbg("create appservice begin, servnum[%d]", m_sysrulesbs->m_servicenum);

    for (int i = 0; i < m_sysrulesbs->m_servicenum; i++) {
        if (!CreateApp(m_sysrulesbs->m_service[i])) { continue; }

        if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "HTTP") == 0)
            || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "HSYT_WEBSERVICE") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CHTTPSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SMTP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSMTPSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "POP3") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CPOP3SINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "FTP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CFTPSINGLE);
        } else if ( (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SQLSERVER") == 0)
                    || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "HSYT_SQLSERVER") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSQLSERVER);
        } else if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "ORACLE") == 0)
                   || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "HSYT_ORACLE") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CORACLESINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "DM") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDM);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "DB2") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDB2);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SYBASE") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSYBASE);
        } else if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "MYSQL") == 0)
                   || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "HSYT_MYSQL") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CMYSQL);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SSL") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSSLSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "MEDIA") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CRTSP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "XMPP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CXMPP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "OPC") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDCSOPCSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "OPCUA") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new COPCUASINGLE(m_sysrulesbs->m_service[i]->m_dport));
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "DNS") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDNSSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "RTP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CRTP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "RECP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CRECP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SNMP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSNMP(m_sysrulesbs->m_service[i]->m_dport));
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "PDXP_UDP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CPDXP_UDP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "PDXP_TCP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CPDXP_TCP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "FEP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CFEP);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "DBSYNC") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDBSYNCSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "SMB") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CSMBSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "TCP_SINGLE") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CTCPSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "UDP_SINGLE") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CUDPSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "NULL_TCP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CTCPNULL);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "NULL_UDP") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CUDPNULL);
        } else if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "4BYTES") == 0)
                   || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "1bit") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new C4BYTESSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "PING") == 0) {
            if (g_icmpappnum == 0) { //只生成一个ICMP对象
                CreateOneApp(m_sysrulesbs->m_service[i], new CICMPSINGLE);
            }
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "PING6") == 0) {
            if (g_icmpv6appnum == 0) { //只生成一个ICMPv6对象
                CreateOneApp(m_sysrulesbs->m_service[i], new CICMPV6SINGLE);
            }
        } else if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "MODBUS") == 0)
                   || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "MODBUS_UDP") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CMODBUSSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "WINCC") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CWINCCSINGLE);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "DNP3") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CDNP3);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "IEC104") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CIEC104);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "IEC61850_MMS") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CMMS);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "S7") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CS7);
        } else if (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "CSM") == 0) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CCSM);
        } else if ((strcmp(m_sysrulesbs->m_service[i]->m_asservice, "CIP_TCP") == 0)
                   || (strcmp(m_sysrulesbs->m_service[i]->m_asservice, "CIP_UDP") == 0)) {
            CreateOneApp(m_sysrulesbs->m_service[i], new CCIP);
        } else {
            PRINT_ERR_HEAD
            print_err("Unknown service[%s]", m_sysrulesbs->m_service[i]->m_asservice);
        }

        PRINT_DBG_HEAD
        print_dbg("[%s]over", m_sysrulesbs->m_service[i]->m_asservice);
    }

    PRINT_DBG_HEAD
    print_dbg("create appservice over");
}

/**
 * [CYWBS::ClearAppServices 清理处理对象]
 */
void CYWBS::ClearAppServices(void)
{
    DELETE_N(g_tcpapp, C_APPSINGLE_MAXNUM);
    DELETE_N(g_udpapp, C_APPSINGLE_MAXNUM);
    DELETE(g_icmpapp);
    DELETE(g_icmpv6app);
    g_tcpappnum = 0;
    g_udpappnum = 0;
    g_icmpappnum = 0;
    g_icmpv6appnum = 0;
}

/**
 * [CYWBS::MGClientCtrl 管理者访问控制]
 * @param isipv6 [true表示ipv6 false表示ipv4]
 */
void CYWBS::MGClientCtrl(bool isipv6)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char *cliip = NULL;
    bool isallobj = false;

    if (!isipv6) {
        cliip = m_devbs->m_mgclientip;
        isallobj = ALL_OBJ(cliip);
    } else {
#if (SUPPORT_IPV6==1)
        cliip = m_devbs->m_mgclientipv6;
        isallobj = IPV6_ALL_OBJ(cliip);
#else
        PRINT_ERR_HEAD
        print_err("mgclient ctrl not support ipv6");
        return;
#endif
    }

    if (s_b_inside && (!IS_STR_EMPTY(cliip)) && (!isallobj)) {
        if ((strchr(cliip, '-') != NULL)) {
            MAKE_TABLESTRING(chcmd, "-A INPUT -m iprange ! --src-range '%s' -p tcp --dport %d -j DROP",
                             isipv6, cliip, m_devbs->m_csport);
            system_safe(chcmd);

            if (m_devbs->m_cksshd) {
                MAKE_TABLESTRING(chcmd, "-A INPUT -m iprange ! --src-range '%s' -p tcp --dport %d -j DROP",
                                 isipv6, cliip, m_devbs->m_sshdport);
                system_safe(chcmd);
            }
        } else {
            MAKE_TABLESTRING(chcmd, "-A INPUT ! -s '%s' -p tcp --dport %d -j DROP",
                             isipv6, cliip, m_devbs->m_csport);
            system_safe(chcmd);

            if (m_devbs->m_cksshd) {
                MAKE_TABLESTRING(chcmd, "-A INPUT ! -s '%s' -p tcp --dport %d -j DROP",
                                 isipv6, cliip, m_devbs->m_sshdport);
                system_safe(chcmd);
            }
        }

        if ((strchr(cliip, '-') == NULL)
            && (strchr(cliip, '/') == NULL)
            && (strcmp(m_devbs->m_mgclientmac, ALLMAC) != 0)
            && (!IS_STR_EMPTY(m_devbs->m_mgclientmac))) {

            //单IP 绑定MAC
            MAKE_TABLESTRING(chcmd, "-A INPUT -s '%s' -m mac ! --mac-source '%s' -j DROP", isipv6, cliip,
                             m_devbs->m_mgclientmac);
            system_safe(chcmd);

            PRINT_INFO_HEAD
            print_info("cliip[%s] bind mac[%s]", cliip, m_devbs->m_mgclientmac);
        }
    }
}

/**
 * [CYWBS::ARPLimit 限制内部接口arp广播]
 */
void CYWBS::ARPLimit(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char ipv4in[IP_STR_LEN] = {0};
    char ipv4out[IP_STR_LEN] = {0};
    MakeV4NatIP(true, m_devbs->m_linklanipseg, -1, ipv4in, sizeof(ipv4in));
    MakeV4NatIP(false, m_devbs->m_linklanipseg, -1, ipv4out, sizeof(ipv4out));
    //OUTPUT
    sprintf(chcmd, "ebtables -A OUTPUT -o ! eth%d -p 0x0806 --arp-ip-src %s -j DROP", m_devbs->m_linklan, ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A OUTPUT -o ! eth%d -p 0x0806 --arp-ip-dst %s -j DROP", m_devbs->m_linklan, ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A OUTPUT -o ! eth%d -p 0x0806 --arp-ip-src %s -j DROP", m_devbs->m_linklan, ipv4out);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A OUTPUT -o ! eth%d -p 0x0806 --arp-ip-dst %s -j DROP", m_devbs->m_linklan, ipv4out);
    SystemCMD(chcmd);
    //FORWARD
    sprintf(chcmd, "ebtables -A FORWARD -p 0x0806 --arp-ip-src %s -j DROP", ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A FORWARD -p 0x0806 --arp-ip-dst %s -j DROP", ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A FORWARD -p 0x0806 --arp-ip-src %s -j DROP", ipv4out);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A FORWARD -p 0x0806 --arp-ip-dst %s -j DROP", ipv4out);
    SystemCMD(chcmd);
    //INPUT
    sprintf(chcmd, "ebtables -A INPUT -i ! eth%d -p 0x0806 --arp-ip-src %s -j DROP", m_devbs->m_linklan, ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A INPUT -i ! eth%d -p 0x0806 --arp-ip-dst %s -j DROP", m_devbs->m_linklan, ipv4in);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A INPUT -i ! eth%d -p 0x0806 --arp-ip-src %s -j DROP", m_devbs->m_linklan, ipv4out);
    SystemCMD(chcmd);
    sprintf(chcmd, "ebtables -A INPUT -i ! eth%d -p 0x0806 --arp-ip-dst %s -j DROP", m_devbs->m_linklan, ipv4out);
    SystemCMD(chcmd);
}

/**
 * [CYWBS::ClearNetConfig 清理网络配置]
 */
void CYWBS::ClearNetConfig(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    //清空arp缓存
    sprintf(chcmd, "arp -n|%s '/^[1-9]/{system(\"arp -d \"$1)}'", AWK_PATH);
    SystemCMD(chcmd);

    //清空DNS
    SystemCMD("echo \"\">/etc/resolv.conf");

    //停掉snmp
    SystemCMD("killall -9 snmpd gapsip >/dev/null 2>&1 ");

    //停掉bond0
    SystemCMD("rmmod bonding >/dev/null 2>&1 ");

    SystemCMD("echo 1 > /proc/sys/vm/drop_caches");

    //清除webproxy相关临时文件
    SystemCMD("rm -rf  /tmp/webproxy*.*");

    SystemCMD("ebtables -F");
    SystemCMD("ebtables -t broute -F");
    SystemCMD("iptables -F");
    SystemCMD("iptables -t nat -F");
#if (SUPPORT_IPV6==1)
    SystemCMD("ip6tables -F");
    SystemCMD("ip6tables -t nat -F");
#endif

    //删除网桥
    SystemCMD("ifconfig bb0 down >/dev/null 2>&1");
    SystemCMD("brctl delbr bb0 >/dev/null 2>&1");

    //使所有地址失效
    SystemCMD("ip -4 addr flush label eth*:*");
    SystemCMD("ip -4 addr flush label eth*");
#if (SUPPORT_IPV6==1)
    //SystemCMD("ip -6 addr flush label eth*");
    SystemCMD("ip -6 addr flush scope global");
    SystemCMD("ip -6 addr flush scope site");
    SystemCMD(ROUTE6_DEL_SH);
#endif

    //重新设置被冲洗掉的管理IP
    if (s_b_inside) {
        SetCSIP();
    }

#if (SUPPORT_DPDK==1)
    ClearDPDK();
#endif
}

/**
 * [CYWBS::SetCSIP 设置管理口IP和路由]
 */
void CYWBS::SetCSIP(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    sprintf(chcmd, "ifconfig eth%d '%s' netmask '%s' up", m_devbs->m_cslan, m_devbs->m_csip, m_devbs->m_csmask);
    system_safe(chcmd);
#if (SUPPORT_IPV6==1)
    if (!IS_STR_EMPTY(m_devbs->m_csipv6)) {
        sprintf(chcmd, "ifconfig eth%d inet6 add '%s'/'%s' up", m_devbs->m_cslan, m_devbs->m_csipv6,
                m_devbs->m_csipv6mask);
        system_safe(chcmd);
    } else {
        PRINT_INFO_HEAD
        print_info("csipv6 not set[%s]", m_devbs->m_csipv6);
    }
#endif
}

/**
 * [CYWBS::InitNetTransparent 透明模式 初始化网络配置]
 * [@para isipv6: true表示ipv6 false表示ipv4]
 */
void CYWBS::InitNetTransparent(bool isipv6)
{
    char chcmd[CMD_BUF_LEN] = {0};
    //认证关掉
    MAKE_TABLESTRING(chcmd, "-A INPUT -p tcp --dport %d -j DROP", isipv6, m_devbs->m_authport);
    SystemCMD(chcmd);

    //SYSLOG端口关掉
    if ((!isipv6) && s_b_inside && (m_devbs->m_logtype == 1)) {
        MAKE_TABLESTRING(chcmd,
                         "-A INPUT -p udp --dport %d -m physdev --physdev-is-bridged ! --physdev-in eth%d -j DROP",
                         isipv6, DEFAULT_SYSLOG_PORT, m_devbs->m_linklan);
        SystemCMD(chcmd);
    }

    MAKE_TABLESTRING(chcmd, "-A FORWARD -j FILTER_MULTICAST", isipv6);
    SystemCMD(chcmd);
}

/**
 * [CYWBS::MGCtrl 管理口控制]
 * [@para isipv6: true表示ipv6 false表示ipv4]
 */
void CYWBS::MGCtrl(bool isipv6)
{
    char chcmd[CMD_BUF_LEN] = {0};

    //是否开启通信口管理功能
    if (m_devbs->m_ckweblogintx) {

        MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -p tcp --dport %d -j ACCEPT", isipv6,
                         m_devbs->m_csport);
        SystemCMD(chcmd);
        //SSH管理
        if (m_devbs->m_cksshd) {
            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -p tcp --dport %d -j ACCEPT", isipv6,
                             m_devbs->m_sshdport);
            SystemCMD(chcmd);
        }
    } else {
        MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -i eth%d -p tcp --dport %d -j ACCEPT", isipv6,
                         m_devbs->m_cslan, m_devbs->m_csport);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-A INPUT ! -i eth%d -p tcp --dport %d -j DROP", isipv6,
                         m_devbs->m_cslan, m_devbs->m_csport);
        SystemCMD(chcmd);
        //SSH管理
        if (m_devbs->m_cksshd) {
            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -i eth%d -p tcp --dport %d -j ACCEPT", isipv6,
                             m_devbs->m_cslan, m_devbs->m_sshdport);
            SystemCMD(chcmd);
            //限制通过管理口之外的网口进行SSH管理
            MAKE_TABLESTRING(chcmd, "-A INPUT ! -i eth%d -p tcp --dport %d -j DROP", isipv6,
                             m_devbs->m_cslan, m_devbs->m_sshdport);
            SystemCMD(chcmd);
        }
    }
}

/**
 * [CYWBS::InitNetProxy 代理模式 初始化网络配置  (路由模式也是调用的本函数)]
 * [@para isipv6: true表示ipv6 false表示ipv4]
 */
void CYWBS::InitNetProxy(bool isipv6)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (m_devbs->m_workflag == WORK_MODE_PROXY) {
        MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -p tcp -j NAT_WEBPROXY", isipv6);
        SystemCMD(chcmd);
    }
    if (!s_b_inside) {
        MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -j NAT_PRIV_FILE", isipv6);
        SystemCMD(chcmd);
        MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -j NAT_FILE", isipv6);
        SystemCMD(chcmd);
    }

    //网闸间通信使用
    MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -i eth%d -j ACCEPT", isipv6, m_devbs->m_linklan);
    SystemCMD(chcmd);
    MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -m state --state RELATED,ESTABLISHED -j ACCEPT", isipv6);
    SystemCMD(chcmd);

    if (s_b_inside) {
        MGCtrl(isipv6);
        //启用认证
        if (m_devbs->m_ckauth) {
            //来自管理口的认证包DROP掉
            MAKE_TABLESTRING(chcmd, "-A INPUT -i eth%d -p tcp --dport %d -j DROP", isipv6,
                             m_devbs->m_cslan, m_devbs->m_authport);
            SystemCMD(chcmd);

            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING ! -i eth%d -p tcp ! --dport %d --tcp-flags ALL SYN -j DNAT --to :%d",
                             isipv6, m_devbs->m_cslan, m_devbs->m_authport, m_devbs->m_authport);
            SystemCMD(chcmd);
        } else {
            //认证包drop掉
            MAKE_TABLESTRING(chcmd, "-A INPUT -p tcp --dport %d -j DROP", isipv6, m_devbs->m_authport);
            SystemCMD(chcmd);
            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING ! -i eth%d -j CHAIN1", isipv6, m_devbs->m_cslan);
            SystemCMD(chcmd);
        }
        //SYSLOG端口关掉
        if ((!isipv6) && (m_devbs->m_logtype == 1)) {
            MAKE_TABLESTRING(chcmd, "-A INPUT -p udp --dport %d ! -i eth%d -j DROP",
                             isipv6, DEFAULT_SYSLOG_PORT, m_devbs->m_linklan);
            SystemCMD(chcmd);
        }
    } else {
        //启用认证
        if (m_devbs->m_ckauth) {
            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -p tcp ! --dport %d -j DNAT --to :%d", isipv6,
                             m_devbs->m_authport, m_devbs->m_authport);
            SystemCMD(chcmd);
        } else {
            //认证包drop掉
            MAKE_TABLESTRING(chcmd, "-A INPUT -p tcp --dport %d -j DROP", isipv6, m_devbs->m_authport);
            SystemCMD(chcmd);
            MAKE_TABLESTRING(chcmd, "-t nat -A PREROUTING -j CHAIN1", isipv6);
            SystemCMD(chcmd);
        }
    }
}

/**
 * [CYWBS::UpAllCards 把本侧的所有网卡都UP起来]
 */
void CYWBS::UpAllCards(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    for (int i = 0; i < MAX_NIC_NUM; i++) {
        sprintf(chcmd, "ifconfig eth%d up >/dev/null 2>&1 ", i);
        SystemCMD(chcmd);
    }
}

/**
 * [CYWBS::InitNetConfig 初始化网络配置]
 */
void CYWBS::InitNetConfig(void)
{
    UpAllCards();

    SystemCMD("iptables -A INPUT -i lo -j ACCEPT");
    SystemCMD("iptables -A INPUT -j FILTER_MAC");
    SystemCMD("iptables -A INPUT -j FILTER_DDOS");  //目前只处理IPV4的 ddos攻击
    SystemCMD("iptables -A FORWARD -j FILTER_KEYWORD");
    SystemCMD("iptables -A FORWARD -j FILTER_MAC");
    SystemCMD("iptables -A FORWARD -j FILTER_DDOS");
    MGClientCtrl(false);
    switch (m_devbs->m_workflag) {
    case WORK_MODE_TRANSPARENT:
        InitNetTransparent(false);
        break;
    case WORK_MODE_PROXY:
    case WORK_MODE_ROUTE:
        InitNetProxy(false);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("unknown work mode[%d]", m_devbs->m_workflag);
        break;
    }

#if (SUPPORT_IPV6==1)
    SystemCMD("ip6tables -A INPUT -i lo -j ACCEPT");
    SystemCMD("ip6tables -A INPUT -j FILTER_MAC");
    SystemCMD("ip6tables -A FORWARD -j FILTER_KEYWORD");
    SystemCMD("ip6tables -A FORWARD -j FILTER_MAC");
    MGClientCtrl(true);
    switch (m_devbs->m_workflag) {
    case WORK_MODE_TRANSPARENT:
        InitNetTransparent(true);
        break;
    case WORK_MODE_PROXY:
    case WORK_MODE_ROUTE:
        InitNetProxy(true);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("ipv6 unknown work mode[%d]", m_devbs->m_workflag);
        break;
    }
#endif
}

/**
 * [CYWBS::SystemCMD system封装]
 * @param chcmd [待执行命令]
 */
void CYWBS::SystemCMD(const char *chcmd)
{
    if (g_debug) {
        printf("##%s\n", chcmd);
    }
    system(chcmd);
}

/**
 * [CYWBS::SystemIptablesRule system封装]
 * @param chcmd [待执行命令]
 * @param V6    [是否IPV6的iptables]
 * @param nat   [是否nat表]
 */
void CYWBS::SystemIptablesRule(const char *chcmd, bool v6, bool nat)
{
    if (v6) {
        if (nat) {
            m_rulemg_nat6.push_back(chcmd);
        } else {
            m_rulemg_filter6.push_back(chcmd);
        }
    } else {
        if (nat) {
            m_rulemg_nat4.push_back(chcmd);
        } else {
            m_rulemg_filter4.push_back(chcmd);
        }
    }
}

/**
 * [CYWBS::SetBonding 设置负载均衡绑定]
 * @param bonding [绑定对象指针]
 */
void CYWBS::SetBonding(CBonding *bonding)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (bonding->bond) {
        sprintf(chcmd, "insmod /lib/bonding.ko miimon=100 mode=%d lacp_rate=1", bonding->bondtype);
        SystemCMD(chcmd);
        SystemCMD("ifconfig bond0 up");

        for (int i = 0; i < bonding->devnum; i++) {
            sprintf(chcmd, "ifconfig eth%d up", bonding->dev[i]);
            SystemCMD(chcmd);
            sprintf(chcmd, "ifenslave bond0 eth%d", bonding->dev[i]);
            SystemCMD(chcmd);
        }

        TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);//透明模式时忽略地址

        for (int j = 0; j < bonding->ipnum; j++) {
            if (bonding->iptype[j] == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
                sprintf(chcmd, "ifconfig bond0 inet6 add '%s'/'%s' up", bonding->ipaddr[j], bonding->maskaddr[j]);
                system_safe(chcmd);
                PRINT_DBG_HEAD
                print_dbg("set ipv6[%s]", chcmd);
#endif
            } else {
                sprintf(chcmd, "ifconfig bond0:%d '%s' netmask '%s' up", j, bonding->ipaddr[j], bonding->maskaddr[j]);
                system_safe(chcmd);
                PRINT_DBG_HEAD
                print_dbg("set ip[%s]", chcmd);
            }
        }
    } else {
        PRINT_DBG_HEAD
        print_dbg("bonding is closed");
    }
}

/**
 * [CYWBS::FoundLinkIPAddress 查找业务IP对应的内部映射IP 参数为本侧IP时调用该函数
 * 得到的是设置在了对端上面的IP]
 * @param  bsip         [业务IP]
 * @return              [失败返回NULL]
 */
char *CYWBS::FoundLinkIPAddress(const char *bsip)
{
    BZERO(m_tmplinkip);

    int type = IP_TYPE4;
    int num = 0;

    if (s_b_inside) {
        for (int i = 0; i < m_devbs->m_innet.myipnum; i++) {
            if (strcmp(m_devbs->m_innet.myip[i].IP, bsip) == 0) {
                type = m_devbs->m_innet.myip[i].TYPE;
                num = i + 1;
                goto _ok;
            }
        }
        for (int i = 0; i < m_sysrulesbs->m_inbonding->ipnum; i++) {
            if (strcmp(m_sysrulesbs->m_inbonding->ipaddr[i], bsip) == 0) {
                type = m_sysrulesbs->m_inbonding->iptype[i];
                num = i + 1 + m_devbs->m_innet.myipnum;
                goto _ok;
            }
        }
    } else {
        for (int i = 0; i < m_devbs->m_outnet.myipnum; i++) {
            if (strcmp(m_devbs->m_outnet.myip[i].IP, bsip) == 0) {
                type = m_devbs->m_outnet.myip[i].TYPE;
                num = i + 1;
                goto _ok;
            }
        }
        for (int i = 0; i < m_sysrulesbs->m_outbonding->ipnum; i++) {
            if (strcmp(m_sysrulesbs->m_outbonding->ipaddr[i], bsip) == 0) {
                type = m_sysrulesbs->m_outbonding->iptype[i];
                num = i + 1 + m_devbs->m_outnet.myipnum;
                goto _ok;
            }
        }
    }
    PRINT_ERR_HEAD
    print_err("find link ip fail[%s]", bsip);
    return NULL;
_ok:
    if (type == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
        MakeV6NatIP(!s_b_inside, g_linklanipseg, num, m_tmplinkip, sizeof(m_tmplinkip));
#endif
    } else {
        MakeV4NatIP(!s_b_inside, g_linklanipseg, num, m_tmplinkip, sizeof(m_tmplinkip));
    }
    PRINT_INFO_HEAD
    print_info("find link ip ok[%s -> %s.num %d]", bsip, m_tmplinkip, num);
    return m_tmplinkip;
}

/**
 * [CYWBS::FoundToLinkIPAddress 查找业务IP对应的内部映射IP 参数为对侧IP时调用该函数
 * 得到的IP是设置在了本侧主机上的IP]
 * @param  bsip [业务IP]
 * @return      [失败返回NULL]
 */
char *CYWBS::FoundToLinkIPAddress(const char *bsip)
{
    BZERO(m_tmplinkip);

    int type = IP_TYPE4;
    int num = 0;

    if (s_b_inside) {
        for (int i = 0; i < m_devbs->m_outnet.myipnum; i++) {
            if (strcmp(m_devbs->m_outnet.myip[i].IP, bsip) == 0) {
                type = m_devbs->m_outnet.myip[i].TYPE;
                num = i + 1;
                goto _ok;
            }
        }
        for (int i = 0; i < m_sysrulesbs->m_outbonding->ipnum; i++) {
            if (strcmp(m_sysrulesbs->m_outbonding->ipaddr[i], bsip) == 0) {
                type = m_sysrulesbs->m_outbonding->iptype[i];
                num = i + 1 + m_devbs->m_outnet.myipnum;
                goto _ok;
            }
        }
    } else {
        for (int i = 0; i < m_devbs->m_innet.myipnum; i++) {
            if (strcmp(m_devbs->m_innet.myip[i].IP, bsip) == 0) {
                type = m_devbs->m_innet.myip[i].TYPE;
                num = i + 1;
                goto _ok;
            }
        }
        for (int i = 0; i < m_sysrulesbs->m_inbonding->ipnum; i++) {
            if (strcmp(m_sysrulesbs->m_inbonding->ipaddr[i], bsip) == 0) {
                type = m_sysrulesbs->m_inbonding->iptype[i];
                num = i + 1 + m_devbs->m_innet.myipnum;
                goto _ok;
            }
        }
    }
    PRINT_ERR_HEAD
    print_err("find to link ip fail[%s]", bsip);
    return NULL;
_ok:
    if (type == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
        MakeV6NatIP(s_b_inside, g_linklanipseg, num, m_tmplinkip, sizeof(m_tmplinkip));
#endif
    } else {
        MakeV4NatIP(s_b_inside, g_linklanipseg, num, m_tmplinkip, sizeof(m_tmplinkip));
    }
    PRINT_INFO_HEAD
    print_info("find to link ip ok[%s -> %s.num %d]", bsip, m_tmplinkip, num);
    return m_tmplinkip;
}

/**
 * [CYWBS::AddIpPortMap 添加IP端口映射规则]
 *
 * 对于代理模式:
 * (代理Ip,代理Port,协议)唯一确定一个映射关系
 * (midip,代理Port,协议)唯一确定一个映射关系
 * 代理IPI--->可以推导出 midip
 * 代理Ip 和 LINK ip是一一对应的
 *
 * @param  tip     [代理IP]
 * @param  tport   [代理端口]
 * @param  dip     [目的IP]
 * @param  dport   [目的端口]
 * @param  midip   [内部跳转IP]
 * @param  appname [应用名称]
 * @param  proto   [协议]
 * @param  iptype  [ip类型 ipv4？ ipv6？]
 * @return         [已经存在返回1 成功返回0 失败返回负值]
 */
int CYWBS::AddIpPortMap(const char *tip, const char *tport, const char *dip, const char *dport,
                        const char *midip, const char *appname, const char *proto, int iptype)
{
    IpPortMap ipportmap(tip, tport, dip, dport, midip, appname, proto, iptype);

    switch (m_devbs->m_workflag) {
    case WORK_MODE_PROXY:
        for (int i = 0; i < (int)m_ipportmap_vec.size(); i++) {
            if (m_ipportmap_vec[i].ProxyInfoEqual(ipportmap)) {
                if (m_ipportmap_vec[i].AppNameEqual(ipportmap)) {
                    return 1;
                } else {
                    //多个应用指定了相同的代理IP、代理端口 和协议,应检查错误
                    //命令过滤的时候,都会按第一个应用名规则设定,进行
                    PRINT_ERR_HEAD
                    print_err("multi apps set to the same proxy ip in proxy model,check it");
                    return -1;
                }
            }
        }
        ipportmap.MakeTmpPortProxyInfo();
        ipportmap.MakeTmpIPProxyInfo();
        m_ipportmap_vec.push_back(ipportmap);
        break;
    case WORK_MODE_ROUTE:
    case WORK_MODE_TRANSPARENT:
        for (int i = 0; i < (int)m_ipportmap_vec.size(); i++) {
            if (m_ipportmap_vec[i].DstInfoEqual(ipportmap)) {
                if (m_ipportmap_vec[i].AppNameEqual(ipportmap)) {
                    return 1;
                } else {
                    //多个应用指定了相同的目的对象ip port 和协议,应检查错误
                    //命令过滤的时候,都会按第一个应用名规则设定,进行
                    PRINT_ERR_HEAD
                    print_err("multi apps set to the same dobj in[%d model],check it", m_devbs->m_workflag);
                    return -1;
                }
            }
        }
        ipportmap.MakeTmpPortDstInfo();
        ipportmap.MakeTmpIPDstInfo();
        m_ipportmap_vec.push_back(ipportmap);
        break;
    default:
        PRINT_ERR_HEAD
        print_err("work mode error[%d]", m_devbs->m_workflag);
        return -1;
        break;
    }
    return 0;
}

/**
 * [CYWBS::LoadAuthUser 加载认证用户信息]
 * @param  filename [文件名称]
 * @return          [成功返回0 失败返回负值]
 */
int CYWBS::LoadAuthUser(const char *filename)
{
    CFILEOP myfile;
    char tmp[100] = {0};
    char ipitem[32] = {0};
    char chcmd[CMD_BUF_LEN] = {0};
    int ipnum = 0;

    //开启认证功能 并且 非透明模式的时候 才加载
    if ((m_devbs->m_ckauth) && (m_devbs->m_workflag != WORK_MODE_TRANSPARENT)) {
        if (myfile.OpenFile(filename, "r") != E_FILE_OK) {
            PRINT_ERR_HEAD
            print_err("OpenFile[%s] fail", filename);
            return -1;
        }

        READ_INT(myfile, "MAIN", "Num", ipnum, true, _out);
        for (int i = 0; i < ipnum; i++) {
            sprintf(ipitem, "IP%d", i);
            READ_STRING(myfile, ipitem, "IP", tmp, true, _out);

            MAKE_TABLESTRING(chcmd, "-t nat -I PREROUTING -s '%s' -j CHAIN1", is_ip6addr(tmp), tmp);
            system_safe(chcmd);
        }

        myfile.CloseFile();
    }
    return 0;

_out:
    myfile.CloseFile();
    return -1;
}

/**
 * [CYWBS::SetRoute 设置去往对象的路由]
 * @param obj [对象指针]
 */
void CYWBS::SetRoute(const COBJECT *obj)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char objip[IP_STR_LEN] = {0};
    char objmask[MASK_STR_LEN] = {0};

    //取IP mask
    const char *p = strchr(obj->m_ipaddress, '-');
    if (p != NULL) {
        //对于用'-'连接起来的范围对象，加路由时按'-'前的IP来处理
        memcpy(objip, obj->m_ipaddress, p - obj->m_ipaddress);
    } else {
        strcpy(objip, obj->m_ipaddress);
    }
    strcpy(objmask, obj->m_netmask);

    if (obj->m_iptype == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
        if ((m_in_ipv6num <= 0) || (m_out_ipv6num <= 0)) {
            PRINT_ERR_HEAD
            print_err("inipv6num[%d] outipv6num[%d]. set business ip first", m_in_ipv6num, m_out_ipv6num);
        } else {
            if (IPV6_ALL_OBJ(objip)) {
                strcpy(objmask, "0");
            }
            sprintf(chcmd, "route -A inet6 add '%s'/'%s' gw %s metric 100", objip, objmask, m_route6_peer);
            system_safe(chcmd);
        }
#endif
    } else {
        if ((m_in_ipv4num <= 0) || (m_out_ipv4num <= 0)) {
            PRINT_ERR_HEAD
            print_err("inipv4num[%d] outipv4num[%d]. set business ip first", m_in_ipv4num, m_out_ipv4num);
        } else {
            //是全对象
            if (ALL_OBJ(objip)) {
                strcpy(objip, "0.0.0.0");
                strcpy(objmask, "0.0.0.0");
            } else {
                //处理IP,避免在route调用时出错
                if (DoWithNetIP(objip, objmask) < 0) {
                    PRINT_ERR_HEAD
                    print_err("do with net ip fail[ip %s, mask %s]", objip, objmask);
                    return;
                }
            }
            sprintf(chcmd, "route add -net '%s' netmask '%s' gw '%s' metric 100", objip, objmask, m_route4_peer);
            system_safe(chcmd);
        }
    }
    return;
}

/**
 * [CYWBS::DoWithNetIP 处理IP,避免在route调用时出错]
 * @param  ip   [待处理的IP 既是入参 又是出参]
 * @param  mask [掩码]
 * @return      [成功返回0 失败返回负值]
 */
int CYWBS::DoWithNetIP(char *ip, const char *mask)
{
    struct in_addr addr1;
    struct in_addr addr2;
    inet_pton(AF_INET, ip, (void *)&addr1);
    inet_pton(AF_INET, mask, (void *)&addr2);

    unsigned long n1 = ntohl(addr1.s_addr);
    unsigned long n2 = ntohl(addr2.s_addr);
    unsigned long n3 = n1 & n2;
    unsigned long n4 = htonl(n3);

    char tmpip[IP_STR_LEN] = {0};

    if (inet_ntop(AF_INET, &n4, tmpip, sizeof(tmpip)) == NULL) {
        PRINT_ERR_HEAD
        print_err("inet_ntop fail[ip:%s, mask:%s, err:%s]", ip, mask, strerror(errno));
        return -1;
    } else {
        strcpy(ip, tmpip);
        return 0;
    }
}

/**
 * [CYWBS::AnalysisLan 把安全通道内外网口分析出来 存到全局变量中]
 * @return  [成功返回0  失败返回负值]
 */
int CYWBS::AnalysisLan(void)
{
    g_cardmg.analysis();
    g_ethin = g_cardmg.getInVec();
    g_ethout = g_cardmg.getOutVec();
    return 0;
}

/**
 * [CYWBS::FindDev 查找业务IP所在的网卡号]
 * @param  ip    [输入IP]
 * @param  isout [true为外网侧 false为内网侧]
 * @return       [成功返回网卡号 失败返回负值]
 */
int CYWBS::FindDev(const char *ip, bool isout)
{
    int dev = -1;
    SDEVINFO &devinfo = isout ? m_devbs->m_outnet : m_devbs->m_innet;
    CBonding *bonding = isout ? m_sysrulesbs->m_outbonding : m_sysrulesbs->m_inbonding;
    int iptype = is_ip6addr(ip) ? IP_TYPE6 : IP_TYPE4;

    for (int i = 0; i < devinfo.myipnum; ++i) {
        if ((strcmp(ip, devinfo.myip[i].IP) == 0)
            || ((iptype == IP_TYPE6) && (devinfo.myip[i].TYPE == IP_TYPE6) && (ip6strcmp((char *)ip, devinfo.myip[i].IP) == 0))) {
            dev = devinfo.myip[i].ID;
            break;
        }
    }

    if ((dev < 0) && (bonding->bond)) {
        for (int i = 0; i < bonding->ipnum; ++i) {
            if ((strcmp(ip, bonding->ipaddr[i]) == 0)
                || ((iptype == IP_TYPE6) && (bonding->iptype[i] == IP_TYPE6) && (ip6strcmp((char *)ip, bonding->ipaddr[i]) == 0))) {
                dev = ANMIT_BOND_NO;
                break;
            }
        }
    }

    PRINT_INFO_HEAD
    print_info("%s business ip[%s] ----> dev[%d]", isout ? "outnet" : "innet", ip, dev);
    return dev;
}

/**
 * [CYWBS::TimeString 组装时间模式字符串]
 * @param  rule [规则指针]
 * @return      [失败返回NULL]
 */
const char *CYWBS::TimeString(CSYSRULES *rule)
{
    if (rule == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make time string");
        return NULL;
    }
    return rule->m_timemod.tostring();
}

/**
 * [CYWBS::OccursString 组装并发数的字符串]
 * @param  rule [规则指针]
 * @return      [失败返回NULL]
 */
const char *CYWBS::OccursString(CSYSRULES *rule)
{
    if (rule == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make occurs string");
        return NULL;
    }

    BZERO(m_tmpoccurs);

    if (rule->m_occurs > 0) {
        if (m_devbs->ck_ddos) {
            //开启DDOS时，按每个IP处理
            sprintf(m_tmpoccurs, "-m connlimit ! --connlimit-above %d --connlimit-mask 32",
                    rule->m_occurs);
        } else {
            //不开启DDOS时，按所有IP处理
            sprintf(m_tmpoccurs, "-m connlimit ! --connlimit-above %d --connlimit-mask 0",
                    rule->m_occurs);
        }
    }

    return m_tmpoccurs;
}

/**
 * [CYWBS::BridgeString 组装透明桥iptables字符串]
 * @param  rule [规则指针]
 * @return      [失败返回NULL]
 */
const char *CYWBS::BridgeString(CSYSRULES *rule)
{
    if (rule == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make bridge string");
        return NULL;
    }
    return rule->m_secway.iptables_bridge(s_b_inside, m_devbs->m_linklan);
}

/**
 * [CYWBS::IsInRange 判断absip是否在rangeip内]
 * @param  rangeip [范围IP]
 * @param  absip   [具体IP]
 * @return         [是返回true]
 */
bool CYWBS::IsInRange(const char *rangeip, const char *absip)
{
    return IPInRange(rangeip, absip);
}

/**
 * [CYWBS::InIpNum 内网业务IP个数]
 * @return  [IP个数]
 */
int CYWBS::InIpNum(void)
{
    return (m_devbs->m_innet.myipnum + m_sysrulesbs->m_inbonding->ipnum);
}

/**
 * [CYWBS::OutIpNum 外网业务IP个数]
 * @return  [IP个数]
 */
int CYWBS::OutIpNum(void)
{
    return (m_devbs->m_outnet.myipnum + m_sysrulesbs->m_outbonding->ipnum);
}

/**
 * [CYWBS::StartFileSync 设置文件交换]
 */
void CYWBS::StartFileSync(void)
{
    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);

    m_sysrulesbs->m_filesync_mg.setOffset(InIpNum() + 2);
    m_sysrulesbs->m_filesync_mg.makeNatIP();
    m_sysrulesbs->m_filesync_mg.setNatIP();
    if (s_b_inside) {
        g_fsync_num = m_sysrulesbs->m_filesync_mg.taskNum();
        if (LicenseModCK(MOD_TYPE_FILESYNC)) {
            if (g_fsync_num > 0) {
                m_sysrulesbs->m_filesync_mg.writeConf();
            }
            StartMsync();
        }
    } else {
        m_sysrulesbs->m_filesync_mg.configNatIP();
        m_sysrulesbs->m_filesync_mg.setOutIptables();
    }
    return;
}

/**
 * [CYWBS::StartDBSync 运行数据库同步任务]
 */
void CYWBS::StartDBSync(void)
{
    char natip4[IP_STR_LEN] = {0};
    char natip6[IP_STR_LEN] = {0};
    int ipoffset = InIpNum();

    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    if (m_sysrulesbs->m_dbsync_tasknum <= 0) {
        return;
    }

    MakeV4NatIP(false, g_linklanipseg, ipoffset + 1, natip4, sizeof(natip4));
#if (SUPPORT_IPV6==1)
    MakeV6NatIP(false, g_linklanipseg, ipoffset + 2, natip6, sizeof(natip6));
#endif
    PRINT_DBG_HEAD
    print_dbg("dbsync natip4[%s] natip6[%s] rulnum[%d]", natip4, natip6, m_sysrulesbs->m_dbsync_tasknum);

    //修改配置文件 及 设置外网iptables
    for (int i = 0; i < m_sysrulesbs->m_dbsync_tasknum; i++) {
        if (m_sysrulesbs->m_dbsync[i]->setNatInfo(natip4, natip6)) {
            if (s_b_inside) {
                if (!m_sysrulesbs->m_dbsync[i]->writeConf()) {
                    return ;
                }
            } else {
                m_sysrulesbs->m_dbsync[i]->setOutIptables();
            }
        } else {
            PRINT_ERR_HEAD
            print_err("dbsync set nat info fail");
            return;
        }
    }

    //内网调用DB同步程序
    if (s_b_inside && LicenseModCK(MOD_TYPE_DBSYNC)) {
        WriteSysLog(LOG_TYPE_DBSYNC, D_SUCCESS, LOG_CONTENT_RUN_DBSYNC);
        StartDBsync();
    }

    PRINT_DBG_HEAD
    print_dbg("start dbsync over");
    return;
}

/**
 * [CYWBS::StartSipNorm 开启平台级联策略]
 */
void CYWBS::StartSipNorm(void)
{
    CSipNorm *psip = NULL;

    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    for (int i = 0; i < m_sysrulesbs->m_sipnormnum; i++) {
        psip = m_sysrulesbs->m_sipnorm[i];
        if (psip->isProtoSIP()) {
            if (psip->getArea() != 0) {
                psip->swapGapIp();
            }

            if (IsCloseToSRCObj(psip->getArea())) {
                psip->setTmpIp2(FoundLinkIPAddress(psip->getGapInIp()));
                psip->setTmpIp1(FoundToLinkIPAddress(psip->getGapOutIp()));
                psip->srcStart();
            } else {
                psip->setTmpIp2(FoundToLinkIPAddress(psip->getGapInIp()));
                psip->setTmpIp1(FoundLinkIPAddress(psip->getGapOutIp()));
                psip->dstStart();
            }
        }
    }
}

/**
 * [CYWBS::StartClientSipNorm 开启视频代理策略]
 */
void CYWBS::StartClientSipNorm(void)
{
    CClientSipNorm *psip = NULL;

    TRANSPARENT_MODE_RETURN(m_devbs->m_workflag);
    for (int i = 0; i < m_sysrulesbs->m_clientsipnormnum; i++) {
        psip = m_sysrulesbs->m_clientsipnorm[i];
        if (psip->isProtoSIP()) {
            if (psip->getArea() != 0) {
                psip->swapGapIp();
            }
            if (IsCloseToSRCObj(psip->getArea())) {
                psip->setTmpIp2(FoundLinkIPAddress(psip->getGapInIp()));
                psip->setTmpIp1(FoundToLinkIPAddress(psip->getGapOutIp()));
                psip->srcStart();
            } else {
                psip->setTmpIp2(FoundToLinkIPAddress(psip->getGapInIp()));
                psip->setTmpIp1(FoundLinkIPAddress(psip->getGapOutIp()));
                psip->dstStart();
            }
        }
    }
}

/**
 * [RangeIpStr 组装范围地址字符串]
 * @param  sORd   [是源还是目的地址]
 * @param  ip     [IP]
 * @param  output [输出缓冲区 需要在调用前自己初始化]
 * @return        [失败返回NULL 成功返回缓冲区指针]
 */
const char *RangeIpStr(char sORd, const char *ip, char *output)
{
    if (ip == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make range ip string. %c", sORd);
        return NULL;
    }

    if (sORd == 's') {
        if (ALL_OBJ(ip) || IPV6_ALL_OBJ(ip)) {
        } else {
            sprintf(output, "-m iprange --src-range %s", ip);
        }
        return output;
    } else if (sORd == 'd') {
        if (ALL_OBJ(ip) || IPV6_ALL_OBJ(ip)) {
        } else {
            sprintf(output, "-m iprange --dst-range %s", ip);
        }
        return output;
    } else {
        PRINT_ERR_HEAD
        print_err("input error[%d]", sORd);
        return NULL;
    }
}

/**
 * [CYWBS::RangeIpString 组装范围地址字符串]
 * @param  sORd [是源还是目的地址]
 * @param  ip   [IP]
 * @return      [失败返回NULL]
 */
const char *CYWBS::RangeIpString(char sORd, const char *ip)
{
    if (ip == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make range ip string. %c", sORd);
        return NULL;
    }
    if (sORd == 's') {
        BZERO(m_tmpranges);
        return RangeIpStr(sORd, ip, m_tmpranges);
    } else if (sORd == 'd') {
        BZERO(m_tmpranged);
        return RangeIpStr(sORd, ip, m_tmpranged);
    } else {
        PRINT_ERR_HEAD
        print_err("input error[%d]", sORd);
        return NULL;
    }
}

/**
 * [CYWBS::ProtoString 组装协议字符串]
 * @param  protocol [协议]
 * @param  iORe     [是iptables 还是ebtables]
 * @return          [返回字符串地址]
 */
const char *CYWBS::ProtoString(const char *protocol, char iORe)
{
    BZERO(m_tmpproto);

    if (iORe == 'i') { //iptables
        if (strcmp(protocol, "TCP") == 0) {
            sprintf(m_tmpproto, "-p tcp");
        } else if (strcmp(protocol, "UDP") == 0) {
            sprintf(m_tmpproto, "-p udp");
        } else if (strcmp(protocol, "ICMP") == 0) {
            sprintf(m_tmpproto, "-p icmp");
        }
    } else if (iORe == 'e') { //ebtables
        if (strcmp(protocol, "TCP") == 0) {
            sprintf(m_tmpproto, "--ip-proto 6");
        } else if (strcmp(protocol, "UDP") == 0) {
            sprintf(m_tmpproto, "--ip-proto 17");
        } else if (strcmp(protocol, "ICMP") == 0) {
            sprintf(m_tmpproto, "--ip-proto 1");
        }
    }

    return m_tmpproto;
}

/**
 * [CYWBS::CheckBondIP 配置界面已经能保证不在已经绑定到bond0的网卡上设置IP 为容错 在处理一下]
 * @return  [成功返回true]
 */
bool CYWBS::CheckBondIP(void)
{
    if (m_sysrulesbs->m_inbonding->bond) {
        for (int i = 0; i < m_sysrulesbs->m_inbonding->devnum; i++) {
            for (int j = 0; j < m_devbs->m_innet.myipnum; j++) {
                if (m_sysrulesbs->m_inbonding->dev[i] == m_devbs->m_innet.myip[j].ID) {
                    PRINT_ERR_HEAD
                    print_err("you cannot set ip[%s] to eth%d which belong to bond",
                              m_devbs->m_innet.myip[j].IP, m_devbs->m_innet.myip[j].ID);
                    return false;
                }
            }
        }
    }

    if (m_sysrulesbs->m_outbonding->bond) {
        for (int i = 0; i < m_sysrulesbs->m_outbonding->devnum; i++) {
            for (int j = 0; j < m_devbs->m_outnet.myipnum; j++) {
                if (m_sysrulesbs->m_outbonding->dev[i] == m_devbs->m_outnet.myip[j].ID) {
                    PRINT_ERR_HEAD
                    print_err("you cannot set ip[%s] to eth%d which belong to bond",
                              m_devbs->m_outnet.myip[j].IP, m_devbs->m_outnet.myip[j].ID);
                    return false;
                }
            }
        }
    }

    PRINT_DBG_HEAD
    print_dbg("check bond ip ok");
    return true;
}

/**
 * [CYWBS::SetMTU 设置业务口MTU]
 * @param cardvec [存放业务口信息的vector]
 */
void CYWBS::SetMTU(vector<int> &cardvec)
{
    char chcmd[CMD_BUF_LEN] = {0};

    for (int i = 0; i < (int)cardvec.size(); i++) {
        if (ANMIT_BOND_NO == cardvec[i]) {
            sprintf(chcmd, "ifconfig bond0 mtu %d", m_devbs->m_mtu);
            system(chcmd);
        } else {
            sprintf(chcmd, "ifconfig eth%d mtu %d", cardvec[i], m_devbs->m_mtu);
            system(chcmd);
        }
    }
}

/**
 * [CYWBS::AppendFTPPort 把传入的端口解析后追加到字符串后面]
 * @param port     [ftp使用的端口 可以是单个端口,也可以是范围端口]
 * @param buff     [存放端口的缓冲区]
 * @param buffsize [buff的总长度]
 * @param portmap  [是为了保证不重复加端口而使用的列表]
 */
void CYWBS::AppendFTPPort(const char *port, char *buff, int buffsize, map<string, int> &portmap)
{
    char *ptr = NULL;
    char portstart[PORT_STR_LEN] = {0};
    char portend[PORT_STR_LEN] = {0};

    PRINT_INFO_HEAD
    print_info("append port %s", port);

    if ((port == NULL) || (buff == NULL) || (strlen(port) == 0) || ((int)strlen(buff) > buffsize - 32)) {
        return;
    }

    if ((ptr = (char *)strchr(port, '-')) != NULL) {
        memcpy(portstart, port, ptr - port);
        strcpy(portend, ptr + 1);

        if (portmap.find(portstart) == portmap.end()) {
            strcat(buff, ",");
            strcat(buff, "'");
            strcat(buff, portstart);
            strcat(buff, "'");
            portmap[portstart] = 1;
        }

        if (portmap.find(portend) == portmap.end()) {
            strcat(buff, ",");
            strcat(buff, "'");
            strcat(buff, portend);
            strcat(buff, "'");
            portmap[portend] = 1;
        }
    } else {
        if (portmap.find(port) == portmap.end()) {
            strcat(buff, ",");
            strcat(buff, "'");
            strcat(buff, port);
            strcat(buff, "'");
            portmap[port] = 1;
        }
    }
    return;
}

/**
 * [CYWBS::SetFtpNat 设置FTP NAT表]
 */
void CYWBS::SetFtpNat(void)
{
    map<string, int> map_ports;
    map_ports["21"] = 1;
    char chcmd[CMD_BUF_LEN] = {0};
    strcpy(chcmd, "insmod /lib/nf_conntrack_ftp.ko ports=21");

    for (int i = 0; i < m_sysrulesbs->m_sysrulenum; i++) {
        for (int n = 0; n < m_sysrulesbs->m_sysrule[i]->m_servicenum; n++) {
            if (strcmp(m_sysrulesbs->m_sysrule[i]->m_service[n]->m_asservice, "FTP") == 0) {
                //把目的端口加进去
                AppendFTPPort(m_sysrulesbs->m_sysrule[i]->m_service[n]->m_dport,
                              chcmd, sizeof(chcmd), map_ports);

                //把代理端口加进去
                AppendFTPPort(m_sysrulesbs->m_sysrule[i]->m_service[n]->m_tport,
                              chcmd, sizeof(chcmd), map_ports);
            }
        }
    }
    for (int i = 0; i < m_sysrulesbs->m_filesync_mg.m_ftpport.size(); ++i) {
        AppendFTPPort(m_sysrulesbs->m_filesync_mg.m_ftpport[i].c_str(),
                      chcmd, sizeof(chcmd), map_ports);
    }

    SystemCMD("rmmod nf_nat_ftp");
    SystemCMD("rmmod nf_conntrack_ftp");
    SystemCMD(chcmd);
    PRINT_INFO_HEAD
    print_info(chcmd);
    SystemCMD("insmod /lib/nf_nat_ftp.ko");
    return ;
}

/**
 * [CYWBS::MethodString 组装处理方式字符串]
 * @param  service [服务指针]
 * @param  requst  [是否为请求]
 * @return         [失败返回NULL]
 */
const char *CYWBS::MethodString(CSERVICECONF *service, bool requst)
{
    if (service == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while make method string");
        return NULL;
    }

    BZERO(m_tmpmethod);
    if (PutQueue(service, requst)) {
        sprintf(m_tmpmethod, "NFQUEUE --queue-num %d", service->GetQueueNum());
    } else {
        strcpy(m_tmpmethod, "ACCEPT");
    }

    return m_tmpmethod;
}

/**
 * 各应用模块的请求和响应是否需要进QUEUE
 */
struct _put_queue_conf {
    bool request_put;//请求是否有必要进入队列
    bool response_put;//响应是否有必要进入队列
    char *mname;
} g_put_queue_conf[] = {
    {true, false, "HTTP"},
    {true, false, "HSYT_WEBSERVICE"},
    {true, false, "SMTP"},
    {true, true, "POP3"},
    {true, false, "FTP"},
    {true, false, "SQLSERVER"},
    {true, false, "HSYT_SQLSERVER"},
    {true, true, "ORACLE"},
    {true, true, "HSYT_ORACLE"},
    {true, false, "DM"},
    {true, false, "DB2"},
    {true, false, "SYBASE"},
    {true, false, "MYSQL"},
    {true, false, "HSYT_MYSQL"},
    {true, true, "SSL"},
    {true, false, "MEDIA"},
    {true, true, "XMPP"},
    {true, true, "OPC"},
    {true, false, "OPCUA"},
    {true, false, "DNS"},
    {true, true, "RTP"},
    {true, true, "RECP"},
    {true, true, "SNMP"},
    {true, true, "PDXP_TCP"},
    {true, true, "PDXP_UDP"},
    {true, true, "FEP"},
    {true, false, "DBSYNC"},
    {true, false, "SMB"},
    {true, true, "TCP_SINGLE"},
    {false, true, "UDP_SINGLE"},
    {false, true, "1bit"},
    {false, true, "4BYTES"},
    {true, true, "PING"},
    {true, true, "PING6"},
    {true, false, "MODBUS"},
    {true, false, "MODBUS_UDP"},
    {true, false, "WINCC"},
    {true, true, "DNP3"},
    {true, true, "IEC104"},
    {true, false, "IEC61850_MMS"},
    {true, true, "S7"},
    {true, true, "CSM"},
    {true, false, "CIP_TCP"},
    {true, false, "CIP_UDP"},
    {false, false, "FILEEXCHANGE"},//暂未实现
    {false, false, "H323"},//暂未实现
    {false, false, "DDE"},//暂未实现
    {false, false, "PROFIBUS"},//暂未实现
    {false, false, "PROFINET"},//暂未实现
};

/**
 * [CYWBS::PutQueue 判断是否需要放入队列]
 * @param  service [服务指针]
 * @param  requst  [是否为请求]
 * @return         [需要放入 返回true]
 */
bool CYWBS::PutQueue(CSERVICECONF *service, bool requst)
{
    if ((strcmp(service->m_asservice, "NULL_TCP") == 0)
        || (strcmp(service->m_asservice, "NULL_UDP") == 0)) {
        return requst ? (service->m_cmdnum > 0) : false; //自定义模块 响应信息不需要进队列
    }

    for (int i = 0; i < ARRAY_SIZE(g_put_queue_conf); ++i) {
        if (strcmp(service->m_asservice, g_put_queue_conf[i].mname) == 0) {
            return (requst ? g_put_queue_conf[i].request_put : g_put_queue_conf[i].response_put);
        }
    }

    PRINT_ERR_HEAD
    print_err("unknown appmode[%s]", service->m_asservice);
    return false;
}

/**
 * [CYWBS::CreateApp 是否需要为该应用创建处理对象]
 * @param  service [服务指针]
 * @return         [需要创建处理对象返回true]
 */
bool CYWBS::CreateApp(CSERVICECONF *service)
{
    if ((strcmp(service->m_asservice, "NULL_TCP") == 0)
        || (strcmp(service->m_asservice, "NULL_UDP") == 0)) {
        return (service->m_cmdnum > 0);
    }
    if ((strcmp(service->m_asservice, "FILEEXCHANGE") == 0)
        || (strcmp(service->m_asservice, "H323") == 0)
        || (strcmp(service->m_asservice, "DDE") == 0)
        || (strcmp(service->m_asservice, "PROFIBUS") == 0)
        || (strcmp(service->m_asservice, "PROFINET") == 0)) {
        return false;
    }
    return true;
}

/**
 * [CYWBS::IsSocketServ 是否为自己写socket处理的服务]
 * @param  service [服务指针]
 * @return         [是 返回true]
 */
bool CYWBS::IsSocketServ(CSERVICECONF *service)
{
    if (service == NULL) { return false; }

    return IsOracleServ(service)
           || IsRTSPServ(service)
           || IsXMPPServ(service);
}

/**
 * [CYWBS::IsOracleServ 是否为ORACLE服务]
 * @param  service [服务指针]
 * @return         [是 返回true]
 */
bool CYWBS::IsOracleServ(CSERVICECONF *service)
{
    if (service == NULL) { return false; }

    return ((strcmp(service->m_asservice, "ORACLE") == 0)
            || (strcmp(service->m_asservice, "HSYT_ORACLE") == 0));
}

/**
 * [CYWBS::IsRTSPServ 是否为RTSP服务]
 * @param  service [服务指针]
 * @return         [是 返回true]
 */
bool CYWBS::IsRTSPServ(CSERVICECONF *service)
{
    if (service == NULL) { return false; }

    return (strcmp(service->m_asservice, "MEDIA") == 0);
}

/**
 * [CYWBS::IsXMPPServ 是否为XMPP应用]
 * @param  pserv [应用指针]
 * @return       [是则返回true]
 */
bool CYWBS::IsXMPPServ(CSERVICECONF *pserv)
{
    return (strcmp(pserv->m_asservice, "XMPP") == 0);
}

/**
 * [CYWBS::SetDefGW 设置默认网关]
 * @return  [成功返回0]
 */
int CYWBS::SetDefGW(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (strcmp(m_devbs->m_defgw, "") != 0) {
        sprintf(chcmd, "route add default gw '%s'", m_devbs->m_defgw);
        system_safe(chcmd);
    }
    if (!IS_STR_EMPTY(m_devbs->m_csgw)) {
        sprintf(chcmd, "route add default gw '%s' metric 200", m_devbs->m_csgw);
        system_safe(chcmd);
    }
#if (SUPPORT_IPV6==1)
    if (strcmp(m_devbs->m_defgwipv6, "") != 0) {
        sprintf(chcmd, "route -A inet6 add default gw '%s'", m_devbs->m_defgwipv6);
        system_safe(chcmd);
    }

    if (!IS_STR_EMPTY(m_devbs->m_csgwipv6)) {
        sprintf(chcmd, "route -A inet6 add default gw '%s' metric 200", m_devbs->m_csgwipv6);
        system_safe(chcmd);
    }
#endif
    return 0;
}

/**
 * [CYWBS::CheckRouteString 检查一个路由语句是否合法]
 * @param  rtlist [路由预计]
 * @return        [合法返回true]
 */
bool CYWBS::CheckRouteString(const char *rtlist)
{
    return (strpbrk(rtlist, ">&|") == NULL);
}

/**
 * [CYWBS::SetRouteList 设置路由列表]
 * @param  flag [flag为0 表示执行所有列表 (默认);非0,表示只执行route开头的列表]
 * @return      [成功返回0]
 */
int CYWBS::SetRouteList(int flag)
{
    SDEVINFO &devinfo = s_b_inside ? m_devbs->m_innet : m_devbs->m_outnet;

    if (flag == 0) {
        for (int i = 0; i < devinfo.rtnum; i++) {
            SetOneRouteInfo(devinfo.rtlist[i]);
        }
    } else {
        for (int i = 0; i < devinfo.rtnum; i++) {
            if ((memcmp(devinfo.rtlist[i], "route", 5) == 0)
                && CheckRouteString(devinfo.rtlist[i])) {
                SystemCMD(devinfo.rtlist[i]);
            }
        }
    }
#if (SUPPORT_IPV6==1)
    SetSpinnerRouteList();
#endif
    return 0;
}

/**
 * [CYWBS::SetOneRouteInfo 设置一条路由信息 (不一定是路由，也有可能是不对外开放的其他用法)]
 * @param rtlist [路由信息]
 */
void CYWBS::SetOneRouteInfo(const char *rtlist)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (rtlist != NULL) {
        if (memcmp(rtlist, "route", 5) == 0) {
            if (CheckRouteString(rtlist)) {
                SystemCMD(rtlist);
            } else {
                PRINT_ERR_HEAD
                print_err("invalid route[%s]", rtlist);
            }
        } else if (memcmp(rtlist, "appproxy6", 9) == 0) {
            strcpy(chcmd, IP6TABLES);
            strcat(chcmd, rtlist + 9);
            SystemCMD(chcmd);
        } else if (memcmp(rtlist, "appproxy", 8) == 0) {
            strcpy(chcmd, IPTABLES);
            strcat(chcmd, rtlist + 8);
            SystemCMD(chcmd);
        } else if (memcmp(rtlist, "syscmdback", 10) == 0) {
            strcpy(chcmd, rtlist + 10 + 1);
            strcat(chcmd, "&");
            SystemCMD(chcmd);
        } else if (memcmp(rtlist, "syscmd", 6) == 0) {
            strcpy(chcmd, rtlist + 6 + 1);
            SystemCMD(chcmd);
        } else {
            PRINT_ERR_HEAD
            print_err("invalid route list[%s]", rtlist);
        }
    }
}

/**
 * [CYWBS::StartWebProxy 运行WEB代理]
 */
void CYWBS::StartWebProxy(void)
{
    if (sem_init(&g_weblock, 0, 1) == -1) {
        PRINT_ERR_HEAD
        print_err("init lock fail");
        return;
    }
    if (m_devbs->m_workflag != WORK_MODE_PROXY) {
        return;
    }
    if (!m_sysrulesbs->m_webproxy_mg.setTmpIP(InIpNum(), OutIpNum())) {
        if (m_sysrulesbs->m_webproxy_mg.taskNum() > 0) {
            WriteSysLog(LOG_TYPE_IP_CK, D_FAIL, LOG_CONTENT_NO_IP);
            PRINT_ERR_HEAD
            print_err("you should set up business IP first");
        }
        return;
    }
    m_sysrulesbs->m_webproxy_mg.setDns(m_devbs->m_defdns, m_devbs->m_defdnsipv6);
    m_sysrulesbs->m_webproxy_mg.run();
}

/**
 * [CYWBS::SetSnmp 设置SNMP]
 */
void CYWBS::SetSnmp(void)
{
    char chsyslog[SYSLOG_BUF_LEN] = {0};
    char chcmd[CMD_BUF_LEN] = {0};

    if (m_devbs->ck_snmp) {
        if (IS_STR_EMPTY(m_devbs->m_snmpctrlip) || IS_STR_EMPTY(m_devbs->m_snmpcomm)) {
            sprintf(chsyslog, "%s[%s][%s]", LOG_CONTENT_SNMP_CONF_NULL, m_devbs->m_snmpctrlip,
                    m_devbs->m_snmpcomm);
            WriteSysLog(LOG_TYPE_SNMP, D_FAIL, chsyslog);

            PRINT_ERR_HEAD
            print_err("snmp set error.ip[%s] comm[%s]", m_devbs->m_snmpctrlip, m_devbs->m_snmpcomm);
        } else {
            //修改配置文件
            sprintf(chcmd, "rm -f %s", SNMPD_CONF);
            SystemCMD(chcmd);
            sprintf(chcmd, "cp %s %s", SNMPD_CONF_BAK, SNMPD_CONF);
            SystemCMD(chcmd);
#if (SUPPORT_IPV6==1)
            sprintf(chcmd, "echo agentAddress udp:161,udp6:161 >>%s", SNMPD_CONF);
            SystemCMD(chcmd);
            sprintf(chcmd, "echo rwcommunity6 public >>%s", SNMPD_CONF);
            SystemCMD(chcmd);
            sprintf(chcmd, "echo com2sec6 notConfigUser '%s' public >>%s", m_devbs->m_snmpctrlipv6, SNMPD_CONF);
            system_safe(chcmd);
#endif
            sprintf(chcmd, "echo com2sec notConfigUser  '%s'      '%s'>>%s",
                    ALL_OBJ(m_devbs->m_snmpctrlip) ? "default" : m_devbs->m_snmpctrlip,
                    m_devbs->m_snmpcomm, SNMPD_CONF);
            system_safe(chcmd);
            SystemCMD("sync");
            //启动
            sprintf(chcmd, "snmpd -c %s -C &", SNMPD_CONF);
            SystemCMD(chcmd);

            if (m_devbs->m_workflag != WORK_MODE_TRANSPARENT) {
                sprintf(chcmd, "%s -t nat -I PREROUTING -p udp --dport 161 -j ACCEPT", IPTABLES);
                SystemCMD(chcmd);
#if (SUPPORT_IPV6==1)
                sprintf(chcmd, "%s -t nat -I PREROUTING -p udp --dport 161 -j ACCEPT", IP6TABLES);
                SystemCMD(chcmd);
#endif
            }
        }
    }
}

/**
 * [CYWBS::SetTrunk 设置TRUNK]
 */
void CYWBS::SetTrunk(void)
{
    SystemCMD("echo 1 >/proc/sys/net/bridge/bridge-nf-call-iptables");

    if (m_devbs->ck_otherprotocal) {
        SystemCMD("echo 1 >/proc/sys/net/bridge/bridge-nf-filter-vlan-tagged");
    } else {
        SystemCMD("echo 0 >/proc/sys/net/bridge/bridge-nf-filter-vlan-tagged");
        //SystemCMD("ebtables -t broute -A BROUTING -p 0x8100 --vlan-encap 0x0800 -j DROP");
        SystemCMD("ebtables -t broute -A BROUTING -p 0x8100 -j DROP");
    }
}

#if (SUPPORT_IPV6==1)
/**
 * [CYWBS::ICMPv6Ext ICMPV6相对于ICMP扩展的功能 支持放过]
 */
void CYWBS::ICMPv6Ext(void)
{
    int ICMPV6_TYPE_EXT[] = {
        1,//目标不可达
        2,//数据报文超长
        3,//超时
        4,//参数出错
        133,//邻居发现 RS 路由器请求
        134,//邻居发现 RA 路由器公告 (RS、RA主要用于无状态地址自动配置)
        135,//邻居发现 NS 邻居请求
        136,//邻居发现 NA 邻居公告  (NS、NA主要用于地址解析)
        137//邻居发现 Redirect 重定向报文 （用于路由器重定向）
    };
    char chcmd[CMD_BUF_LEN] = {0};

    for (uint32 i = 0; i < ARRAY_SIZE(ICMPV6_TYPE_EXT); ++i) {
        sprintf(chcmd, "-A FORWARD -p icmpv6 --icmpv6-type %d -j ACCEPT\n", ICMPV6_TYPE_EXT[i]);
        SystemIptablesRule(chcmd, true, false);
    }
}

/**
 * [CYWBS::SetSpinnerRouteList 设置路由列表信息（通过WEB下拉框方式添加的路由）]
 * route add -net 192.168.180.0 netmask 255.255.255.0 gw 192.168.2.253 metric 199 dev eth1
 * route -A inet6 add 2002::1/64 gw 2001::100 metric 100 dev eth0
 */
void CYWBS::SetSpinnerRouteList(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    SDEVINFO &dinfo = s_b_inside ? m_devbs->m_innet : m_devbs->m_outnet;

    for (int i = 0; i < dinfo.srtnum; ++i) {
        dinfo.srtlist[i].combineRoute(chcmd);
        system_safe(chcmd);
    }
}
#endif

/**
 * [CYWBS::SetIPInfo 代理模式或路由模式根据界面配置设置IP及映射IP]
 * @return  [成功返回true]
 */
bool CYWBS::SetIPInfo(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char natip[IP_STR_LEN] = {0};

    if (m_devbs->m_workflag == WORK_MODE_TRANSPARENT) {
        return true;
    }
    //设置内部通信IP
    char tmpipv4[IP_STR_LEN] = {0};
    MakeV4NatIP(s_b_inside, g_linklanipseg, -1, tmpipv4, sizeof(tmpipv4));
    sprintf(chcmd, "ifconfig eth%d %s netmask %s up", m_devbs->m_linklan, tmpipv4, DEFAULT_LINK_MASK);
    SystemCMD(chcmd);

    //支持IPv6时 内部强制设置一个IP
#if (SUPPORT_IPV6==1)
    char tmpipv6[IP_STR_LEN] = {0};
    MakeV6NatIP(s_b_inside, g_linklanipseg, -1, tmpipv6, sizeof(tmpipv6));
    sprintf(chcmd, "ifconfig eth%d inet6 add %s/64 up", m_devbs->m_linklan, tmpipv6);
    SystemCMD(chcmd);
#endif

    //检查管理界面配置的网卡IP跟负载均衡IP有无冲突
    if (!CheckBondIP()) {
        return false;
    }

    //设置业务IP
    SDEVINFO &devinfo = s_b_inside ? m_devbs->m_innet : m_devbs->m_outnet;
    for (int i = 0; i < devinfo.myipnum; i++) {
        if (devinfo.myip[i].ID >= 0) {
            sprintf(chcmd, "ifconfig eth%d up", devinfo.myip[i].ID);
            SystemCMD(chcmd);
            if (devinfo.myip[i].TYPE == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
                sprintf(chcmd, "ifconfig eth%d inet6 add '%s'/'%s' up",
                        devinfo.myip[i].ID, devinfo.myip[i].IP, devinfo.myip[i].MASK);
                system_safe(chcmd);
#endif
            } else {
                sprintf(chcmd, "ifconfig eth%d:%d '%s' netmask '%s' up",
                        devinfo.myip[i].ID, i, devinfo.myip[i].IP, devinfo.myip[i].MASK);
                system_safe(chcmd);
            }
        }
    }

    //设置内部跳转IP
    SDEVINFO &peerinfo = s_b_inside ? m_devbs->m_outnet : m_devbs->m_innet;
    CBonding *peerbinding = s_b_inside ? m_sysrulesbs->m_outbonding : m_sysrulesbs->m_inbonding;
    for (int i = 0; i < peerinfo.myipnum; i++) {
        if (peerinfo.myip[i].ID >= 0) {
            if (peerinfo.myip[i].TYPE == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
                sprintf(chcmd, "ifconfig eth%d inet6 add %s/64 up", m_devbs->m_linklan,
                        MakeV6NatIP(s_b_inside, g_linklanipseg, i + 1, natip, sizeof(natip)));
                SystemCMD(chcmd);
#endif
            } else {
                sprintf(chcmd, "ifconfig eth%d:%d %s netmask %s up", m_devbs->m_linklan, i,
                        MakeV4NatIP(s_b_inside, g_linklanipseg, i + 1, natip, sizeof(natip)),
                        DEFAULT_LINK_MASK);
                SystemCMD(chcmd);
            }
        }
    }
    for (int i = 0; i < peerbinding->ipnum; i++) {
        if (peerbinding->iptype[i] == IP_TYPE6) {
#if (SUPPORT_IPV6==1)
            sprintf(chcmd, "ifconfig eth%d inet6 add %s/64 up", m_devbs->m_linklan,
                    MakeV6NatIP(s_b_inside, g_linklanipseg, i + 1 + peerinfo.myipnum, natip, sizeof(natip)));
            SystemCMD(chcmd);
#endif
        } else {
            sprintf(chcmd, "ifconfig eth%d:%d %s netmask %s up", m_devbs->m_linklan,
                    i + peerinfo.myipnum,
                    MakeV4NatIP(s_b_inside, g_linklanipseg, i + 1 + peerinfo.myipnum, natip, sizeof(natip)),
                    DEFAULT_LINK_MASK);
            SystemCMD(chcmd);
        }
    }
    return SetAdditionalNatIP();
}

/**
 * [CYWBS::SetAdditionalNatIP 设置2个额外的内部跳转IP
 * 目前用于私有文件交换、数据库同步、组播跳转使用]
 * @return  [成功返回0]
 */
bool CYWBS::SetAdditionalNatIP(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    char natip4[IP_STR_LEN] = {0};
    char natip6[IP_STR_LEN] = {0};

    int ipoffset = s_b_inside ? OutIpNum() : InIpNum();
    MakeV4NatIP(s_b_inside, g_linklanipseg, ipoffset + 1, natip4, sizeof(natip4));
#if (SUPPORT_IPV6==1)
    MakeV6NatIP(s_b_inside, g_linklanipseg, ipoffset + 2, natip6, sizeof(natip6));
#endif
    sprintf(chcmd, "ifconfig eth%d:%d %s netmask %s up", m_devbs->m_linklan,
            ipoffset, natip4, DEFAULT_LINK_MASK);
    SystemCMD(chcmd);

#if (SUPPORT_IPV6==1)
    sprintf(chcmd, "ifconfig eth%d inet6 add %s/64 up", m_devbs->m_linklan, natip6);
    SystemCMD(chcmd);
#endif
    return true;
}

/**
 * [CYWBS::SetPing 设置是否允许ping]
 */
void CYWBS::SetPing(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    MAKE_TABLESTRING(chcmd, "-A INPUT -p icmp --icmp-type 8 -j %s", false,
                     m_devbs->ck_ping ? "ACCEPT" : "DROP");
    SystemCMD(chcmd);
#if (SUPPORT_IPV6==1)
    MAKE_TABLESTRING(chcmd, "-A INPUT -p icmpv6 --icmpv6-type echo-request -j %s", true,
                     m_devbs->ck_ping ? "ACCEPT" : "DROP");
    SystemCMD(chcmd);
#endif
}

/**
 * [CYWBS::SetDNS 设置DNS]
 */
void CYWBS::SetDNS(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (!IS_STR_EMPTY(m_devbs->m_defdns)) {
        sprintf(chcmd, "echo nameserver '%s'>>/etc/resolv.conf", m_devbs->m_defdns);
        system_safe(chcmd);
    }
#if (SUPPORT_IPV6==1)
    if (!IS_STR_EMPTY(m_devbs->m_defdnsipv6)) {
        sprintf(chcmd, "echo nameserver '%s'>>/etc/resolv.conf", m_devbs->m_defdnsipv6);
        system_safe(chcmd);
    }
#endif
}

/**
 * [CYWBS::WriteSysLog 写系统日志]
 * @param logtype [日志类型]
 * @param result  [结果 成功 or 失败]
 * @param remark  [备注信息]
 */
void CYWBS::WriteSysLog(const char *logtype, const char *result, const char *remark)
{
    if ((logtype != NULL) && (result != NULL) && (remark != NULL)) {
        if (m_log.WriteSysLog(logtype, result, remark) != E_OK) {
            m_log.DisConnect();
            m_log.Init();

            PRINT_ERR_HEAD
            print_err("write syslog to db fail[%s][%s][%s]", logtype, result, remark);
        }
    }
}

/**
 * [CYWBS::SetDDOS 设置抗DDOS]
 */
void CYWBS::SetDDOS(void)
{
    if (m_devbs->ck_ddos) {
        SystemCMD("echo 1 >/proc/sys/net/ipv4/tcp_syncookies");
    } else {
        SystemCMD("echo 0 >/proc/sys/net/ipv4/tcp_syncookies");
    }
    do_ddos_protection();
}

/**
 * [CYWBS::SetIDS 设置IDS]
 */
void CYWBS::SetIDS(void)
{
    if (m_devbs->ck_ids) {
    } else {
    }
}

/**
 * [CYWBS::SetFilterKey 关键字过滤设置]
 */
void CYWBS::SetFilterKey(void)
{
    KeywordMG keymg;
    keymg.readConf();
    if (s_b_inside) { //只在内网过滤
        keymg.setRule();
    }
}

/**
 * [CYWBS::SetCKFileType 设置文件类型过滤信息]
 */
void CYWBS::SetCKFileType(void)
{
    FileTypeMG &s1 = FileTypeMG::GetInstance();
    s1.ReadConf();
}

/**
 * [CYWBS::AddlCard 除了安全通道引用的网卡，把其他额外分析出来的网卡也添加进来]
 * @return  [成功返回0]
 */
int CYWBS::AddlCard(void)
{
    if (s_b_inside) {
        AddlCardWebProxy();
        AddlCardDBSync();
        AddlCardFileSync();
        g_cardmg.analysis();
        g_ethin = g_cardmg.getInVec();
        g_ethout = g_cardmg.getOutVec();
        g_cardmg.show();
    }
    return 0;
}

/**
 * [CYWBS::AddlCardWebProxy WEB代理 把其他额外分析出来的网卡也添加进来]
 * @return  [成功返回0]
 */
int CYWBS::AddlCardWebProxy(void)
{
    g_cardmg.clear(WEBPROXY_MOD);
    int cardno = 0;
    bool isout = false;

    for (int i = 0; i < m_sysrulesbs->m_webproxy_mg.taskNum(); ++i) {
        isout = (m_sysrulesbs->m_webproxy_mg.getAreaway(i) != 0);
        cardno = FindDev(m_sysrulesbs->m_webproxy_mg.getListenIP(i), isout);
        if (cardno >= 0) {
            g_cardmg.add(WEBPROXY_MOD, cardno, isout);
        } else {
            PRINT_ERR_HEAD
            print_err("listenip[%s] find dev fail", m_sysrulesbs->m_webproxy_mg.getListenIP(i));
            return -1;
        }
    }

    PRINT_INFO_HEAD
    print_info("webproxy add card over");
    return 0;
}

/**
 * [CYWBS::AddlCardDBSync DB同步 把其他额外分析出来的网卡也添加进来]
 * @return  [成功返回0]
 */
int CYWBS::AddlCardDBSync(void)
{
    char localip[IP_STR_LEN] = {0};
    int cardno = -1;

    for (int i = 0; i < m_sysrulesbs->m_dbsync_tasknum; ++i) {
        if (get_localip(m_sysrulesbs->m_dbsync[i]->getInSvr(), localip, sizeof(localip), 3) == 0) {
            cardno = FindDev(localip, false);
            g_cardmg.add(DBSYNC_MOD, cardno, false);
        }

        if (get_peer_localip(m_sysrulesbs->m_dbsync[i]->getOutSvr(), localip, sizeof(localip), 3) == 0) {
            cardno = FindDev(localip, true);
            g_cardmg.add(DBSYNC_MOD, cardno, true);
        }
    }
    return 0;
}

/**
 * [CYWBS::AddlCardFileSync 文件同步 把其他额外分析出来的网卡也添加进来]
 * @return  [成功返回0]
 */
int CYWBS::AddlCardFileSync(void)
{
    char localip[IP_STR_LEN] = {0};
    g_cardmg.clear(FILESYNC_MOD);
    for (int i = 0; i < m_sysrulesbs->m_filesync_mg.m_indstip.size(); ++i) {
        if (get_localip(m_sysrulesbs->m_filesync_mg.m_indstip[i].c_str(), localip, sizeof(localip), 3) == 0) {
            g_cardmg.add(FILESYNC_MOD, FindDev(localip, false), false);
        }
    }
    for (int i = 0; i < m_sysrulesbs->m_filesync_mg.m_outdstip.size(); ++i) {
        if (get_peer_localip(m_sysrulesbs->m_filesync_mg.m_outdstip[i].c_str(), localip, sizeof(localip), 3) == 0) {
            g_cardmg.add(FILESYNC_MOD, FindDev(localip, true), true);
        }
    }
    return 0;
}

/**
 * [MakeV4NatIP 组装IPV4内部跳转IP]
 * @param  binnet   [是否为内网侧]
 * @param  seg      [内部使用的网段]
 * @param  num      [第几个]
 * @param  ipbuff   [存放IP缓冲区 出参]
 * @param  buffsize [缓冲区大小]
 * @return          [成功返回指向缓冲区的指针 失败返回NULL]
 */
const char *MakeV4NatIP(bool binnet, int seg, int num, char *ipbuff, int buffsize)
{
    if ((ipbuff == NULL) || (buffsize <= 0)) {
        PRINT_ERR_HEAD
        print_err("buff null or size[%d] error while make v4 nat ip", buffsize);
        return NULL;
    }

    memset(ipbuff, 0, buffsize);
    if (binnet) {
        if (num > 0) {
            snprintf(ipbuff, buffsize, "%d.0.%d.%d", seg, GETNUM1(num), GETNUM2(num));
        } else if (num < 0) {
            snprintf(ipbuff, buffsize, "%d.0.0.%d", seg, 254);
        }
    } else {
        if (num > 0) {
            snprintf(ipbuff, buffsize, "%d.0.%d.%d", seg, GETNUM1(num), GETNUM3(num));
        } else if (num < 0) {
            snprintf(ipbuff, buffsize, "%d.0.0.%d", seg, 253);
        }
    }

    PRINT_DBG_HEAD
    print_dbg("%s seg=%d num=%d ----> result[%s]", binnet ? "innet" : "outnet", seg, num, ipbuff);
    return ipbuff;
}

/**
 * [MakeV6NatIP 组装IPV6内部跳转IP]
 * @param  binnet   [是否为内网侧]
 * @param  seg      [内部使用的网段]
 * @param  num      [对端的第几个IP 从1开始的]
 * @param  ipbuff   [存放IP缓冲区 出参]
 * @param  buffsize [缓冲区大小]
 * @return          [成功返回指向缓冲区的指针 失败返回NULL]
 */
const char *MakeV6NatIP(bool binnet, int seg, int num, char *ipbuff, int buffsize)
{
    if ((ipbuff == NULL) || (buffsize <= 0)) {
        PRINT_ERR_HEAD
        print_err("buff null or size[%d] error while make v6 nat ip", buffsize);
        return NULL;
    }
    memset(ipbuff, 0, buffsize);
    if (binnet) {
        snprintf(ipbuff, buffsize, "1000:%d::a:%x", seg, num >= 0 ? num : 0x8888);
    } else {
        snprintf(ipbuff, buffsize, "1000:%d::b:%x", seg, num >= 0 ? num : 0x8888);
    }
    return ipbuff;
}

/**
 * [IsCloseToSRCObj 根据规则方向判断本端是不是靠近客户端源对象的一侧]
 * @param  areaway [规则方向 0表示内到外  1表示外到内]
 * @return         [是靠近客户端对象的一侧则返回true]
 */
bool IsCloseToSRCObj(int areaway)
{
    return ((s_b_inside && (areaway == 0)) || ((!s_b_inside) && (areaway != 0)));
}
