/*******************************************************************************************
*文件:  FCYWBS.h
*描述:  业务处理类
*作者:  王君雷
*日期:  2016-03
*修改:
*        添加模块授权管理功能                                          ------> 2018-01-08
*        添加arping相关函数                                            ------> 2018-01-22
*        重写Start函数，缩减函数体                                     ------> 2018-02-05
*        把IsCloseToSRCObj修改为public static函数,可被其他地方直接调用 ------> 2018-03-14
*        添加执行irq.sh脚本的线程                                      ------> 2018-05-18
*        添加JudgeDPDK函数，为添加DPDK功能做准备                       ------> 2018-05-21
*        加入PDT互联                                                   ------> 2018-07-31
*        添加私有协议文件同步功能                                      ------> 2018-08-31
*        添加时间模式、授权模块枚举类型、统一函数参数命名风格          ------> 2018-09-05
*        支持SSH管理设备                                               ------> 2018-11-01
*        时间模式，封装为单独的类                                      ------> 2018-11-03
*        磁盘空间告警与检测线程移动到recvmain中                        ------> 2018-12-07
*        去除ICMPMAP相关内容，因为使用不到了                           ------> 2018-12-27
*        通过宏控制是否启用IPV6支持,开发过程版                         ------> 2019-02-12
*        添加RoutePeer函数，解决支持IPV6时路由计算错误                 ------> 2019-03-02
*        文件交换支持IPV6                                              ------> 2019-06-08
*        使用nginx实现ipv4&ipv6交叉访问                                ------> 2019-06-13
*        加入平台互联                                                  ------> 2019-07-31 -dzj
*        修改平台互联接口的入参                                        ------> 2019-08-07 -dzj
*        系统初始化时，UP所有网卡                                      ------> 2019-09-02
*        获取系统状态线程移动到recvmain                                ------> 2019-11-19-dzj
*        修改设置iptables规则为iptables-restore方式                    ------> 2019-12-01-dzj
*        函数接口名称拼写错误                                          ------> 2019-12-09-dzj
*        添加OPC需要开放的端口结构                                     ------> 2019-12-18-dzj
*        文件交换、数据库同步模块支持双机热备                          ------> 2019-12-19 wjl
*        添加函数SetPortConnect，可设置代理模式同侧网口是否联通         ------> 2020-06-11 wjl
*        设置系统并发数函数移动到其他文件                              ------> 2020-10-28
*        WEB代理支持分模块生效，nignx管理对象设置为全局变量             ------> 2020-11-18
*        优化程序，应用模块只在必要时才进iptables队列                  ------> 2020-12-10
*        添加MakeBSIPMap函数                                         ------> 2021-03-04
*******************************************************************************************/
#ifndef __FC_YWBS_H__
#define __FC_YWBS_H__

#include "FCSYSBS.h"
#include "FCSysRulesBS.h"
#include "FCDevBS.h"
#include "FCSingle.h"
#include "FCLicenseMod.h"
#include "nginx_manager.h"
#include "rule_restore.h"
#include "FCBonding.h"

//授权模块类型
enum LICENSE_MOD_TYPE {
    MOD_TYPE_FILESYNC = 0, //文件交换模块
    MOD_TYPE_DBSYNC        //数据库同步模块
};

//IP MAC绑定的区域
enum BINDMAC_AREA {
    BINDMAC_AREA_ALL = 0,
    BINDMAC_AREA_INNET,
    BINDMAC_AREA_OUTNET
};

//配置OPC时需要开放的端口
typedef struct {
    const char *port;
    const char *protocol;
} OPC_PORT_T;

#define TRANSPARENT_MODE_RETURN(flag) \
if ((flag) == WORK_MODE_TRANSPARENT) {return;}

//规则业务处理类
class CYWBS: public CSYSBS
{
public:
    CSYSRULESBUSINESS *m_sysrulesbs;   //规则结构业务
    CDEVBS *m_devbs;                   //设备业务类

private:
    CLOGMANAGE m_log;
    char m_chres[1024];
    char m_tmplinkip[IP_STR_LEN];
    char m_tmpranges[128];
    char m_tmpranged[128];
    char m_tmpproto[32];
    char m_tmpmethod[32];
    char m_tmpoccurs[128];
    char m_tmpdnat[128];

    vector<IpPortMap> m_ipportmap_vec;

    CLicenseMod *m_plicensemod;
    CThread *m_arping_th;
    CThread *m_irq_th;
    int m_in_ipv4num;
    int m_in_ipv6num;
    int m_out_ipv4num;
    int m_out_ipv6num;

    char m_route4_peer[IP_STR_LEN];//路由模式 把下一跳设置为网闸对端时 对端的IP v4
    char m_route6_peer[IP_STR_LEN];//路由模式 把下一跳设置为网闸对端时 对端的IP v6

    RuleRestoreMG m_rulemg_nat4;
    RuleRestoreMG m_rulemg_filter4;
    RuleRestoreMG m_rulemg_nat6;
    RuleRestoreMG m_rulemg_filter6;

public:
    CYWBS(void);
    virtual ~CYWBS(void);
    bool LoadData(void);
    bool Start(void);
    void SetDevBS(CDEVBS *p_devbs);
    int SetDefGW(void);
    int SetRouteList(int flag = 0);
    bool CheckRouteString(const char *rtlist);
    void SetFtpNat(void);
    int AddlCardFileSync(void);
    int AddlCardWebProxy(void);

private:
    void CreateAppServices(void);
    void CreateOneApp(CSERVICECONF *service, CSINGLE *single);
    void ClearAppServices(void);
    void SystemCMD(const char *chcmd);
    void SystemIptablesRule(const char *chcmd, bool type, bool nat);
    char *Replace(const char *src, char s, char d);
    char *FoundLinkIPAddress(const char *bsip);
    char *FoundToLinkIPAddress(const char *bsip);
    void BindMac(void);
    void BindMac(const char *ip, const char *mac, int iptype);
    void InitNetConfig(void);
    void InitNetTransparent(bool isipv6);
    void InitNetProxy(bool isipv6);
    void ClearNetConfig(void);
    void UpAllCards(void);
    void SetCSIP(void);
    void WriteSysLog(const char *logtype, const char *result, const char *remark);
    void SetOneRouteInfo(const char *rtlist);
    const char *DnatString(const char *ip, const char *port);

    int LoadAuthUser(const char *filename);

    //内网 外网IP个数
    int InIpNum(void);
    int OutIpNum(void);
    void IPStatistics(void);
    void RoutePeer(void);
    void MakeBSIPMap(void);

    //添加IP PORT 映射关系到vector
    int AddIpPortMap(const char *tip, const char *tport, const char *dip, const char *dport,
                     const char *midip, const char *appname, const char *proto, int iptype);
    void SetDDOS(void);
    void SetIDS(void);
    void SetRoute(const COBJECT *obj);

    void SetMTU(vector<int> &cardvec);

    //设置负载均衡
    void SetBonding(CBonding *bonding);
    void AppendFTPPort(const char *port, char *buff, int buffsize, map<string, int> &portmap);

    //根据界面配置设置IP及映射IP
    bool SetIPInfo(void);
    bool SetAdditionalNatIP(void);

    void SetSnmp(void);
    void SetPing(void);
    void SetDNS(void);
    void SetTrunk(void);
    void SetSSHD(void);

    //设置过滤关键字
    void SetFilterKey(void);

    //设置过滤文件类型
    void SetCKFileType(void);

    //把安全通道内外网口分析出来 存到全局变量中
    int AnalysisLan(void);
    int FindDev(const char *ip, bool isout);
    int AddlCard(void);
    int AddlCardDBSync(void);

    //创建IPTABES-RESTORE规则文件
    int CreateIptablesFile(void);

    //判断具体的IP absip是否在范围IP rangeip内
    static bool IsInRange(const char *rangeip, const char *absip);

    //处理IP,避免在route调用时出错
    static int DoWithNetIP(char *ip, const char *mask);
    bool CheckBondIP(void);

    //管理者客户端IP控制,需要的时候绑定MAC
    void MGClientCtrl(bool isipv6);
    void MGCtrl(bool isipv6);

    //运行文件同步任务
    void StartFileSync(void);
    void StartPvtFileSync(void);

    //运行数据库同步任务
    void StartDBSync(void);

    //运行组播任务
    void StartMulticast(void);
    void StartMulticastTransparent(void);
    void StartMulticastNoTransparent(void);

    void StartLinkVideo(void);
    void StartLinkService(void);
    void StartSipNorm(void);
    void StartSipLink(void);
    void StartClientSipNorm(void);
    void StartClientSipLink(void);
    void StartPDT(void);
    void StartPDTCommon(void);
    void StartSipInterConnect(void);
    void StartSipInterConnectNorm(CSipInterConnect *sip_interconnect);
    void StartWebProxy(void);
    void StartRFC3261(void);

    const char *RangeIpString(char sORd, const char *ip);
    const char *TimeString(CSYSRULES *rule);
    const char *OccursString(CSYSRULES *rule);
    const char *BridgeString(CSYSRULES *rule);
    const char *ProtoString(const char *protocol, char iORe = 'i');
    const char *MethodString(CSERVICECONF *service, bool request);
    //模块是否进加进队列
    bool PutQueue(CSERVICECONF *service, bool request);
    bool CreateApp(CSERVICECONF *service);
    void ARPLimit(void);

    //开启ARPING 更新邻居的arp信息
    void StartArping(void);
    static void *ArpingProcess(void *param);
    void DoArping(int ethno, const char *ip);
    void StartIRQ(void);
    static void *IRQProcess(void *param);

    static bool IsSocketServ(CSERVICECONF *service);
    static bool IsOracleServ(CSERVICECONF *service);
    static bool IsRTSPServ(CSERVICECONF *service);
    static bool IsXMPPServ(CSERVICECONF *pserv);

    static bool IsOPCServ(CSERVICECONF *pserv);
    static bool IsTCPServ(CSERVICECONF *pserv);
    static bool IsUDPServ(CSERVICECONF *pserv);
    static bool IsICMPServ(CSERVICECONF *pserv);
    static bool IsICMPV6Serv(CSERVICECONF *pserv);
#if (SUPPORT_IPV6==1)
    void ICMPv6Ext(void);
    void SetSpinnerRouteList(void);
#endif

    void GlobalAssign(void);
    void LicenseModInit(void);
    void TranAuthThread(void);
    void SysLogThread(void);
    void SMSThread(void);
    void CreateBridge(void);
    void BridgeAddif(void);
    void SetBridgeIP(void);
    void SetSTP(void);
    void SetARPLimit(void);
    bool LicenseModCK(int modtype);

    void SetTransparentRule(void);
    void TransparentPrepare(bool flag);
    void SetTransparent(CSYSRULES *prule);
    void SetTransparentTCPUDP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentTCPUDPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentTCPUDPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentTCPUDPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentTCPUDPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentTCPUDPDstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPDstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);

    void SetTransparentICMPV6(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPV6Src(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPV6Dst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPV6SrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPV6SrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetTransparentICMPV6DstWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
#if 0
#if (SUPPORT_DPDK==1)
    bool JudgeDPDK(void);
#endif
#endif

    void SetProxyRule(void);
    void SetPortConnect(void);
    void ProxyHideSrc(void);
    void SetProxy(CSYSRULES *prule);
    void SetProxySrc(CSYSRULES *prule);
    void SetProxyDst(CSYSRULES *prule);
    bool AutoProxy(CSYSRULES *prule);
    void SetProxySrcAuto(CSYSRULES *prule);
    void SetProxySrcManual(CSYSRULES *prule);
    void SetProxyDstAuto(CSYSRULES *prule);
    void SetProxyDstManual(CSYSRULES *prule);
    bool ProxyMatch(CSERVICECONF *pserv, SDIPINFO *pdipinfo, COBJECT *pdobj);
    void ProxyGetOnlyIP(CSYSRULES *prule, char *ip, int &iptype);
    void ProxyGetMidIP(CSYSRULES *prule, char *ip, int len, int iptype);
    void SetProxySrcAutoWhite(CSYSRULES *prule, int servnum, char *srconlyip, char *midip, int iptype);
    void SetProxySrcAutoBlack(CSYSRULES *prule, int servnum, char *srconlyip, char *midip, int iptype);
    void SetProxySrcManualMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
    void SetProxySrcManualMatchWhite(CSYSRULES *prule, int servnum, char *tmptip, SDIPINFO *pdipinfo);
    void SetProxySrcManualMatchBlack(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
    void SetProxyDstManualMatch(CSYSRULES *prule, CSERVICECONF *pserv, SDIPINFO *pdipinfo);

    void SetRouteRule(void);
    void RouteHideSrc(void);
    void SetRouteARule(CSYSRULES *prule);
    void SetRouteProxy(CSYSRULES *prule);
    void RoutePrepare(bool flag);
    void SetRouteTCPUDP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMP(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteTCPUDPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteTCPUDPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteTCPUDPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteTCPUDPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPSrc(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPDst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPSrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPSrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);

    void SetRouteICMPV6(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPV6Src(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPV6Dst(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPV6SrcWhite(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);
    void SetRouteICMPV6SrcBlack(CSYSRULES *prule, COBJECT *pdobj, CSERVICECONF *pserv);

    void SetRouteProxySrc(CSYSRULES *prule);
    void SetRouteProxyDst(CSYSRULES *prule);
    void SetRouteProxySrcMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
    void SetRouteProxySrcMatchWhite(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
    void SetRouteProxySrcMatchBlack(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
    void SetRouteProxyDstMatch(CSYSRULES *prule, int servnum, SDIPINFO *pdipinfo);
};

const char *MakeV4NatIP(bool binnet, int seg, int num, char *ipbuff, int buffsize);
const char *MakeV6NatIP(bool binnet, int seg, int num, char *ipbuff, int buffsize);
bool IsCloseToSRCObj(int areaway);
const char *RangeIpStr(char sORd, const char *ip, char *output);
extern const bool s_b_inside;//我是否为内网侧
extern NGINX_MANAGER g_nginx;

#endif
