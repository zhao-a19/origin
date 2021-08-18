/*******************************************************************************************
*文件:  FCDevBS.cpp
*描述:  设备业务类
*作者:  王君雷
*日期:  2016-03
*修改:
*       添加是否开启STP选项支持,路由列表兼容带双引号的情况     ------> 2017-12-04 王君雷
*       使用UTF8编码，linux风格，引入zlog,加入DPDK相关选项     ------> 2018-05-16
*       支持SSH管理设备                                        ------> 2018-11-01
*       磁盘告警阈值，小于等于0或大于等于100时，按默认值10处理 ------> 2018-11-19
*       磁盘空间告警与检测线程移动到recvmain中                 ------> 2018-12-07
*       通过宏控制是否启用IPV6支持                             ------> 2019-02-12
*       添加SNMP告警IP对IPV6的支持                             ------> 2019-06-14
*       添加配置项WebProxyUseNginx,可以选择是否使用nginx实现web代理  ------> 2019-06-19
*       尽量兼容配置文件错误的情况，使用默认值，而不阻塞循环去读     ------> 2019-06-27
*       通信口检查时，根据选项UpDownCard决定是否需要周期性up down网卡------> 2019-11-08
*       读取管理口路由配置信息                                       ------> 2019-11-19-dzj
*       添加读取代理模式下、同侧网口是否路由通选项，默认不联通           ------> 2020-06-11 wjl
*       使用新的读取配置文件接口                                     ------> 2020-07-03
*       本业务类不再负责读取文件类型过滤相关配置                      ------> 2020-11-03
*       WEB代理支持分模块生效，废弃WebProxyUseNginx选项，强制使用nginx实现
*                                                                  ------> 2020-11-18
*       读取多IP对应应用名称后计算其md5值保存备用                     ------> 2021-05-07
*******************************************************************************************/
#include "FCDevBS.h"
#include "debugout.h"
#include "readcfg.h"
#include "common.h"
#include <string.h>

CDEVBS::CDEVBS(void)
{
    recordlog = false;
    m_workflag = WORK_MODE_TRANSPARENT;
    m_logtype = 0;
    BZERO(m_innet);
    BZERO(m_outnet);

    m_linklan = 0;
    m_linklanipseg = 1;
    m_linklanport = -1;
    m_noticeport = -1;

    m_cslan = 0;
    m_csport = 0;
    BZERO(m_csip);
    BZERO(m_csmask);

    m_cksshd = false;
    m_sshdport = -1;

    m_smsalert = 0;
    BZERO(m_smsserverip);
    m_smsserverport = 0;
    BZERO(m_smsalertphone);

    m_ckvirus = false;
    BZERO(m_mgclientip);
    BZERO(m_mgclientmac);
    BZERO(m_defgw);
    BZERO(m_defdns);

    m_sysmaxflow = 0;
    m_cklineswitch = 0;
    m_updowncard = 0;

    indipnum = 0;
    outdipnum = 0;
    ck_ids = false;
    ck_ddos = false;
    ck_otherprotocal = false;
    ck_stp = false;
    ck_ping = true;
    hidesrc = true;
    m_mtu = 1500;
    m_ckauth = true;
    m_authport = DEFAULT_LINK_PORT;

    m_ckweblogintx = false;
    m_ckmacbind = false;
    m_macbindnum = 0;
    //m_cktrunk = false;
    ck_snmp = false;
    m_portconnect = 0;
    BZERO(m_snmpctrlip);
    BZERO(m_snmpcomm);
#if (SUPPORT_IPV6==1)
    BZERO(m_snmpctrlipv6);
#endif

    interfacenum = 0;
    outerfacenum = 0;
    BZERO(interface);
    BZERO(outerface);
    BZERO(m_macbind);
    //BZERO(indipinfo);
    //BZERO(outdipinfo);
    indipinfo = outdipinfo = NULL;
#if 0
#if (SUPPORT_DPDK==1)
    m_ckdpdk = false;
    m_dpdklan = -1;
    m_dpdk_dynamic_inlan = -1;
    m_dpdk_dynamic_outlan = -1;
#endif
#endif

#if (SUPPORT_IPV6==1)
    BZERO(m_defgwipv6);
    BZERO(m_defdnsipv6);
    BZERO(m_csipv6);
    BZERO(m_csipv6mask);
    BZERO(m_mgclientipv6);
#endif
}

CDEVBS::~CDEVBS(void)
{
}

/**
 * [CDEVBS::LoadDevConfig 加载设备配置信息]
 * @return [成功返回true]
 */
bool CDEVBS::LoadDevConfig(void)
{
    char optval[500] = {0};
    char subitem[500] = {0};
    int tmpint = 0;
    const char *netrtarea = NULL;
    CCommon common;

    if (m_file.OpenFile(DEV_CONF, "r", true) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", DEV_CONF);
        return false;
    }

    const char *netarea = (DEVFLAG[0] == 'I') ? "INNET" : "OUTNET";

    READ_INT(m_file, netarea, "CKPing", tmpint, false, _out);
    ck_ping = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, netarea, "CKHideSrcIP", tmpint, false, _out);
    hidesrc = (tmpint == 1);
    READ_STRING(m_file, netarea, "DefGW", m_defgw, false, _out);
    READ_STRING(m_file, netarea, "DefDNS", m_defdns, false, _out);
#if (SUPPORT_IPV6==1)
    READ_STRING(m_file, netarea, "DefGWIPv6", m_defgwipv6, false, _out);
    READ_STRING(m_file, netarea, "DefDNSIPv6", m_defdnsipv6, false, _out);
#endif
    tmpint = 0;
    READ_INT(m_file, netarea, "CKSNMP", tmpint, false, _out);
    ck_snmp = (tmpint == 1);
    if (ck_snmp) {
        READ_STRING(m_file, netarea, "SNMPCtrIP", m_snmpctrlip, false, _out);
        READ_STRING(m_file, netarea, "SNMPComm", m_snmpcomm, false, _out);
#if (SUPPORT_IPV6==1)
        strcpy(m_snmpctrlipv6, "::");
        READ_STRING(m_file, netarea, "SNMPCtrIPv6", m_snmpctrlipv6, false, _out);
#endif
    }

    READ_INT(m_file, "DEV", "INNET_IPNum", m_innet.myipnum, false, _out);
    if (m_innet.myipnum > MAX_IPNUM) {
        PRINT_ERR_HEAD
        print_err("too many ip[%d],max support[%d]", m_innet.myipnum, MAX_IPNUM);
        m_innet.myipnum = MAX_IPNUM;
    }

    READ_INT(m_file, "DEV", "OUTNET_IPNum", m_outnet.myipnum, false, _out);
    if (m_outnet.myipnum > MAX_IPNUM) {
        PRINT_ERR_HEAD
        print_err("too many ip[%d],max support[%d]", m_outnet.myipnum, MAX_IPNUM);
        m_outnet.myipnum = MAX_IPNUM;
    }

    READ_INT(m_file, "DEV", "INNET_RTNum", m_innet.rtnum, false, _out);
    if (m_innet.rtnum > MAX_RTNUM) {
        PRINT_ERR_HEAD
        print_err("too many rtlist[%d],max support[%d]", m_innet.rtnum, MAX_RTNUM);
        m_innet.rtnum = MAX_RTNUM;
    }

    READ_INT(m_file, "DEV", "OUTNET_RTNum", m_outnet.rtnum, false, _out);
    if (m_outnet.rtnum > MAX_RTNUM) {
        PRINT_ERR_HEAD
        print_err("too many rtlist[%d],max support[%d]", m_outnet.rtnum, MAX_RTNUM);
        m_outnet.rtnum = MAX_RTNUM;
    }

    READ_INT(m_file, "DEV", "InDIPNum", indipnum, false, _out);
    READ_INT(m_file, "DEV", "OutDIPNum", outdipnum, false, _out);
    if (indipnum > 0) {
        if (indipinfo != NULL) {
            free(indipinfo);
            indipinfo = NULL;
        }
        indipinfo = (SDIPINFO *)malloc(sizeof(SDIPINFO) * indipnum);
        if (indipinfo == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc in SDIPINFO fail[%d]", indipnum);
            goto _out;
        }
        memset(indipinfo, 0, sizeof(SDIPINFO) * indipnum);
    }

    if (outdipnum > 0) {
        if (outdipinfo != NULL) {
            free(outdipinfo);
            outdipinfo = NULL;
        }
        outdipinfo = (SDIPINFO *)malloc(sizeof(SDIPINFO) * outdipnum);
        if (outdipinfo == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc out SDIPINFO fail[%d]", outdipnum);
            goto _out;
        }
        memset(outdipinfo, 0, sizeof(SDIPINFO) * outdipnum);
    }

#if (SUPPORT_IPV6==1)
    READ_INT(m_file, "INNETRT", "RTNUM", m_innet.srtnum, false, _out);
    if (m_innet.srtnum >= MAX_SPINNER_ROUTE_LIST) {
        PRINT_ERR_HEAD
        print_err("too many spinner route list[%d],max support[%d]",
                  m_innet.srtnum, MAX_SPINNER_ROUTE_LIST);
        m_innet.srtnum = MAX_SPINNER_ROUTE_LIST;
    }
    READ_INT(m_file, "OUTNETRT", "RTNUM", m_outnet.srtnum, false, _out);
    if (m_outnet.srtnum >= MAX_SPINNER_ROUTE_LIST) {
        PRINT_ERR_HEAD
        print_err("too many spinner route list[%d],max support[%d]",
                  m_outnet.srtnum, MAX_SPINNER_ROUTE_LIST);
        m_outnet.srtnum = MAX_SPINNER_ROUTE_LIST;
    }

    for (int i = 0; i < m_innet.srtnum; ++i) {
        sprintf(subitem, "DSTNETIP%d", i);
        READ_STRING(m_file, "INNETRT", subitem, m_innet.srtlist[i].dstip, false, _out);
        sprintf(subitem, "DSTMASK%d", i);
        READ_STRING(m_file, "INNETRT", subitem, m_innet.srtlist[i].dstmask, false, _out);
        sprintf(subitem, "GW%d", i);
        READ_STRING(m_file, "INNETRT", subitem, m_innet.srtlist[i].gw, false, _out);
        sprintf(subitem, "DEV%d", i);
        READ_STRING(m_file, "INNETRT", subitem, m_innet.srtlist[i].dev, false, _out);
        sprintf(subitem, "METRIC%d", i);
        READ_INT(m_file, "INNETRT", subitem, m_innet.srtlist[i].metric, false, _out);
        sprintf(subitem, "IPTYPE%d", i);
        READ_INT(m_file, "INNETRT", subitem, m_innet.srtlist[i].iptype, false, _out);
        PRINT_DBG_HEAD
        print_dbg("spinnerlist%d:sdtip[%s]dstmask[%s]gw[%s]dev[%s]metric[%d]iptype[%d]", i,
                  m_innet.srtlist[i].dstip, m_innet.srtlist[i].dstmask,
                  m_innet.srtlist[i].gw, m_innet.srtlist[i].dev,
                  m_innet.srtlist[i].metric, m_innet.srtlist[i].iptype);
    }

    for (int i = 0; i < m_outnet.srtnum; ++i) {
        sprintf(subitem, "DSTNETIP%d", i);
        READ_STRING(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].dstip, false, _out);
        sprintf(subitem, "DSTMASK%d", i);
        READ_STRING(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].dstmask, false, _out);
        sprintf(subitem, "GW%d", i);
        READ_STRING(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].gw, false, _out);
        sprintf(subitem, "DEV%d", i);
        READ_STRING(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].dev, false, _out);
        sprintf(subitem, "METRIC%d", i);
        READ_INT(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].metric, false, _out);
        sprintf(subitem, "IPTYPE%d", i);
        READ_INT(m_file, "OUTNETRT", subitem, m_outnet.srtlist[i].iptype, false, _out);
        PRINT_DBG_HEAD
        print_dbg("spinnerlist%d:sdtip[%s]dstmask[%s]gw[%s]dev[%s]metric[%d]iptype[%d]", i,
                  m_outnet.srtlist[i].dstip, m_outnet.srtlist[i].dstmask,
                  m_outnet.srtlist[i].gw, m_outnet.srtlist[i].dev,
                  m_outnet.srtlist[i].metric, m_outnet.srtlist[i].iptype);
    }
#endif
    //内网IP详细信息
    for (int i = 0; i < m_innet.myipnum; i++) {
        sprintf(subitem, "ID%d", i);
        READ_INT(m_file, "INNET", subitem, m_innet.myip[i].ID, false, _out);
#if (SUPPORT_IPV6==1)
        sprintf(subitem, "MYIPTYPE%d", i);
        READ_INT(m_file, "INNET", subitem, m_innet.myip[i].TYPE, false, _out);
#endif
        sprintf(subitem, "MYIP%d", i);
        READ_STRING(m_file, "INNET", subitem, m_innet.myip[i].IP, false, _out);
        sprintf(subitem, "MYMASK%d", i);
        READ_STRING(m_file, "INNET", subitem, m_innet.myip[i].MASK, false, _out);
    }

    //内网路由详细信息
    for (int i = 0; i < m_innet.rtnum; i++) {
        sprintf(subitem, "MYRT%d", i);
        memset(optval, 0, sizeof(optval));
        READ_STRING(m_file, "INNET", subitem, optval, false, _out);

        if (optval[0] == '\"') {
            int vallen = strlen(optval);
            if (optval[vallen - 1] == '\"') {
                optval[vallen - 1] = '\0';
                strncpy(m_innet.rtlist[i], optval + 1, sizeof(m_innet.rtlist[i]) - 1);
            } else {
                PRINT_ERR_HEAD
                print_err("[%s]rtlist start with double quotes and not end with double quotes", subitem);
                //goto _out;
            }
        } else {
            strncpy(m_innet.rtlist[i], optval, sizeof(m_innet.rtlist[i]) - 1);
        }
    }

    //外网IP详细信息
    for (int i = 0; i < m_outnet.myipnum; i++) {
        sprintf(subitem, "ID%d", i);
        READ_INT(m_file, "OUTNET", subitem, m_outnet.myip[i].ID, false, _out);
#if (SUPPORT_IPV6==1)
        sprintf(subitem, "MYIPTYPE%d", i);
        READ_INT(m_file, "OUTNET", subitem, m_outnet.myip[i].TYPE, false, _out);
#endif
        sprintf(subitem, "MYIP%d", i);
        READ_STRING(m_file, "OUTNET", subitem, m_outnet.myip[i].IP, false, _out);
        sprintf(subitem, "MYMASK%d", i);
        READ_STRING(m_file, "OUTNET", subitem, m_outnet.myip[i].MASK, false, _out);
    }

    //外网路由详细信息
    for (int i = 0; i < m_outnet.rtnum; i++) {
        sprintf(subitem, "MYRT%d", i);
        memset(optval, 0, sizeof(optval));
        READ_STRING(m_file, "OUTNET", subitem, optval, false, _out);

        if (optval[0] == '\"') {
            int vallen = strlen(optval);
            if (optval[vallen - 1] == '\"') {
                optval[vallen - 1] = '\0';
                strncpy(m_outnet.rtlist[i], optval + 1, sizeof(m_outnet.rtlist[i]) - 1);
            } else {
                PRINT_ERR_HEAD
                print_err("[%s]rtlist start with double quotes and not end with double quotes", subitem);
                //goto _out;
            }
        } else {
            strncpy(m_outnet.rtlist[i], optval, sizeof(m_outnet.rtlist[i]) - 1);
        }
    }

    //内网多IP对应详细信息
    for (int i = 0; i < indipnum; i++) {
        sprintf(subitem, "INDIP%d", i);
        READ_STRING(m_file, subitem, "App", indipinfo[i].appname, false, _out);
        common.DelChar(indipinfo[i].appname, '\"');
        common.DelChar(indipinfo[i].appname, '\'');
        common.GetStrMd5(indipinfo[i].appname, indipinfo[i].appnamemd5, sizeof(indipinfo[i].appnamemd5));
        READ_STRING(m_file, subitem, "SrcIpAddr", indipinfo[i].myip, false, _out);
        READ_STRING(m_file, subitem, "DPort", indipinfo[i].dport, false, _out);
        READ_STRING(m_file, subitem, "DestIpAddr", indipinfo[i].dip, false, _out);
        READ_STRING(m_file, subitem, "TPort", indipinfo[i].myser, false, _out);
#if (SUPPORT_IPV6==1)
        READ_INT(m_file, subitem, "SrcIpType", indipinfo[i].myiptype, false, _out);
        READ_INT(m_file, subitem, "DestIpType", indipinfo[i].diptype, false, _out);
#endif
    }

    //外网多IP对应详细信息
    for (int i = 0; i < outdipnum; i++) {
        sprintf(subitem, "OUTDIP%d", i);
        READ_STRING(m_file, subitem, "App", outdipinfo[i].appname, false, _out);
        common.DelChar(outdipinfo[i].appname, '\"');
        common.DelChar(outdipinfo[i].appname, '\'');
        common.GetStrMd5(outdipinfo[i].appname, outdipinfo[i].appnamemd5, sizeof(outdipinfo[i].appnamemd5));
        READ_STRING(m_file, subitem, "SrcIpAddr", outdipinfo[i].myip, false, _out);
        READ_STRING(m_file, subitem, "DPort", outdipinfo[i].dport, false, _out);
        READ_STRING(m_file, subitem, "DestIpAddr", outdipinfo[i].dip, false, _out);
        READ_STRING(m_file, subitem, "TPort", outdipinfo[i].myser, false, _out);
#if (SUPPORT_IPV6==1)
        READ_INT(m_file, subitem, "SrcIpType", outdipinfo[i].myiptype, false, _out);
        READ_INT(m_file, subitem, "DestIpType", outdipinfo[i].diptype, false, _out);
#endif
    }

    m_file.CloseFile();
    return true;

_out:
    m_file.CloseFile();
    return false;
}


/**
 * [CDEVBS::LoadSysInfo 读取系统信息 这些信息都是不可以通过界面改动的]
 * @return [成功返回true]
 */
bool CDEVBS::LoadSysInfo(void)
{
    char subitem[32] = {0};
    int tmpint = 1;

    if (m_file.OpenFile(SYSINFO_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSINFO_CONF);
        return false;
    }

    READ_INT(m_file, "SYSTEM", "CSLan", m_cslan, true, _out);
    READ_INT(m_file, "SYSTEM", "LinkLan", m_linklan, true, _out);
    READ_INT(m_file, "SYSTEM", "LinkLanIPSeg", m_linklanipseg, false, _out);
    if (m_linklanipseg < 1 || m_linklanipseg > 255) {
        PRINT_ERR_HEAD
        print_err("LinkLanIPSeg err[%d], use default 1", m_linklanipseg);
        m_linklanipseg = 1;
    }
    READ_INT(m_file, "SYSTEM", "LinkLanPort", m_linklanport, false, _out);
    if (m_linklanport < 1 || m_linklanport > 65535) {
        PRINT_ERR_HEAD
        print_err("LinkLanPort err[%d], use default %d", m_linklanport, DEFAULT_LINK_PORT);
        m_linklanport = DEFAULT_LINK_PORT;
    }
    READ_INT(m_file, "SYSTEM", "RuleNoticePort", m_noticeport, false, _out);
    if (m_noticeport < 1 || m_noticeport > 65535) {
        PRINT_INFO_HEAD
        print_info("notice port err[%d], use default %d", m_noticeport, DEFAULT_NOTICE_PORT);
        m_noticeport = DEFAULT_NOTICE_PORT;
    }
    READ_INT(m_file, "SYSTEM", "ClientAuthPort", m_linklanport, false, _out);
    if (m_authport < 1 || m_authport > 65535) {
        PRINT_ERR_HEAD
        print_err("ClientAuthPort err[%d], use default %d", m_authport, DEFAULT_LINK_PORT);
        m_authport = DEFAULT_LINK_PORT;
    }
    READ_INT(m_file, "SYSTEM", "InterfaceNum", interfacenum, false, _out);
    if (interfacenum > MAX_NIC_NUM) {
        PRINT_ERR_HEAD
        print_err("InterfaceNum err[%d], use default %d", interfacenum, MAX_NIC_NUM);
        interfacenum = MAX_NIC_NUM;
    }
    READ_INT(m_file, "SYSTEM", "OuterfaceNum", outerfacenum, false, _out);
    if (outerfacenum > MAX_NIC_NUM) {
        PRINT_ERR_HEAD
        print_err("OuterfaceNum err[%d], use default %d", outerfacenum, MAX_NIC_NUM);
        outerfacenum = MAX_NIC_NUM;
    }

    //网口显示名称
    for (int i = 0; i < interfacenum; i++) {
        sprintf(subitem, "INTERFACE%d", i);
        READ_STRING(m_file, subitem, "NetworkName", interface[i], false, _out);
    }
    for (int i = 0; i < outerfacenum; i++) {
        sprintf(subitem, "OUTERFACE%d", i);
        READ_STRING(m_file, subitem, "NetworkName", outerface[i], false, _out);
    }

#if 0
#if (SUPPORT_DPDK==1)
    READ_INT(m_file, "SYSTEM", "DPDKLan", m_dpdklan, false, _out);
#endif
#endif
#if 0
    tmpint = 1;
    READ_INT(m_file, "SYSTEM", "WebProxyUseNginx", tmpint, false, _out);
    m_webproxyusenginx = (tmpint == 1);
#endif

    READ_INT(m_file, "SYSTEM", "PortConnect", m_portconnect, false, _out);

    m_file.CloseFile();
    return true;

_out:
    m_file.CloseFile();
    return false;
}

/**
 * [CDEVBS::LoadData 加载配置信息]
 * @return [成功返回true]
 */
bool CDEVBS::LoadData(void)
{
    int tmpint = 0;

    if (m_file.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSSET_CONF);
        return false;
    }

    READ_INT(m_file, "SYSTEM", "RecordLog", tmpint, false, _out);
    recordlog = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKIDS", tmpint, false, _out);
    ck_ids = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKDDOS", tmpint, false, _out);
    ck_ddos = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKOtherProtocol", tmpint, false, _out);
    ck_otherprotocal = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKSTP", tmpint, false, _out);
    ck_stp = (tmpint == 1);
    READ_INT(m_file, "SYSTEM", "MTU", m_mtu, false, _out);
    if (m_mtu < DEFAULT_MTU || m_mtu > MAX_MTU) {
        PRINT_ERR_HEAD
        print_err("m_mtu err[%d], use default %d", m_mtu, DEFAULT_MTU);
        m_mtu = DEFAULT_MTU;
    }

    READ_INT(m_file, "SYSTEM", "LogType", m_logtype, false, _out);
    if (m_logtype == 1) {
        READ_STRING(m_file, "SYSTEM", "LogServer", m_logserver, false, _out);
        READ_INT(m_file, "SYSTEM", "LogServerPort", m_logserverport, false, _out);
        if (m_logserverport <= 0) {
            PRINT_ERR_HEAD
            print_err("LogServerPort err[%d], use default %d", m_logserverport, DEFAULT_SYSLOG_PORT);
            m_logserverport = DEFAULT_SYSLOG_PORT;
        }
    }

    READ_INT(m_file, "SYSTEM", "WorkFlag", m_workflag, false, _out);
    READ_STRING(m_file, "SYSTEM", "CSIP", m_csip, true, _out);
    READ_INT(m_file, "SYSTEM", "CSPort", m_csport, false, _out);
    if (m_csport <= 0) {
        PRINT_ERR_HEAD
        print_err("CSPort err[%d], use default %d", m_csport, DEFAULT_CSPORT);
        m_csport = DEFAULT_CSPORT;
    }
    READ_STRING(m_file, "SYSTEM", "CSMask", m_csmask, false, _out);
    if (strcmp(m_csmask, "") == 0) {
        PRINT_ERR_HEAD
        print_err("CSMask err[%s], use default %s", m_csmask, DEFAULT_CSMASK);
        strcpy(m_csmask, DEFAULT_CSMASK);
    }
    READ_STRING(m_file, "SYSTEM", "CSGW", m_csgw, false, _out);
    READ_STRING(m_file, "SYSTEM", "MGClientIP", m_mgclientip, false, _out);

#if (SUPPORT_IPV6==1)
    READ_STRING(m_file, "SYSTEM", "CSIPv6", m_csipv6, false, _out);
    READ_STRING(m_file, "SYSTEM", "CSIPv6Mask", m_csipv6mask, false, _out);
    READ_STRING(m_file, "SYSTEM", "CSGWIPv6", m_csgwipv6, false, _out);
    READ_STRING(m_file, "SYSTEM", "MGClientIPv6", m_mgclientipv6, false, _out);
#endif

    READ_STRING(m_file, "SYSTEM", "MGClientMac", m_mgclientmac, false, _out);
    READ_INT(m_file, "SYSTEM", "SMSAlert", m_smsalert, false, _out);

    if (m_smsalert == 1) {
        READ_STRING(m_file, "SYSTEM", "SMSServerIP", m_smsserverip, false, _out);
        READ_INT(m_file, "SYSTEM", "SMSServerPort", m_smsserverport, false, _out);
        READ_STRING(m_file, "SYSTEM", "AlertPhone", m_smsalertphone, false, _out);
    }

    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKVirus", tmpint, false, _out);
    m_ckvirus = (tmpint == 1);

    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKClientAuth", tmpint, false, _out);
    m_ckauth = (tmpint == 1);

    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKSSHD", tmpint, false, _out);
    m_cksshd = (tmpint == 1);
    if (m_cksshd) {
        READ_INT(m_file, "SYSTEM", "SSHDPORT", m_sshdport, false, _out);
    }

    READ_INT(m_file, "SYSTEM", "SYSMaxFlow", m_sysmaxflow, false, _out);

    //主机是否主动检查使用中网卡的状态,并在网络连通异常时停止业务
    READ_INT(m_file, "SYSTEM", "CKLineSwitch", m_cklineswitch, false, _out);
    READ_INT(m_file, "SYSTEM", "UpDownCard", m_updowncard, false, _out);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKWebLoginTX", tmpint, false, _out);
    m_ckweblogintx = (tmpint == 1);
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKMacBind", tmpint, false, _out);
    m_ckmacbind = (tmpint == 1);
    if (m_ckmacbind) {
        READ_INT(m_file, "SYSTEM", "MacBindNum", m_macbindnum, false, _out);
        if (m_macbindnum > MAX_BIND_MAC) {
            PRINT_ERR_HEAD
            print_err("m_macbindnum err[%d], use default %d", m_macbindnum, MAX_BIND_MAC);
            m_macbindnum = MAX_BIND_MAC;
        }

        char subitem[20] = {0};
        for (int i = 0; i < m_macbindnum; i++) {
            sprintf(subitem, "MacBindIP%d", i);
            READ_STRING(m_file, "SYSTEM", subitem, m_macbind[i].ip, false, _out);
            sprintf(subitem, "MacBindMac%d", i);
            READ_STRING(m_file, "SYSTEM", subitem, m_macbind[i].mac, false, _out);
            sprintf(subitem, "MacBindArea%d", i);
            READ_INT(m_file, "SYSTEM", subitem, m_macbind[i].area, false, _out);
            sprintf(subitem, "MacBindIPType%d", i);
            READ_INT(m_file, "SYSTEM", subitem, m_macbind[i].iptype, false, _out);
        }
    }

#if (SUPPORT_DPDK==1)
    tmpint = 0;
    READ_INT(m_file, "SYSTEM", "CKDPDK", tmpint, false, _out);
    m_ckdpdk = (tmpint == 1);
#endif

    m_file.CloseFile();
    if (LoadDevConfig() && LoadSysInfo()) {
        return true;
    }

_out:
    m_file.CloseFile();
    return false;
}

bool CDEVBS::Start(void)
{
    return true;
}
