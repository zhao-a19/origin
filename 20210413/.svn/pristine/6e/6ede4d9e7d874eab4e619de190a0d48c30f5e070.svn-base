/*******************************************************************************************
*文件:    ddos.cpp
*描述:    iptables的ddos防护配置
*
*作者:    dzj
*日期:    2019-11-14
*修改:
*          去掉ping of death的iptables                                ------> 2020-02-21 -dzj
*          解决开启DDOS防护，导致内联异常问题                           ------> 2021-03-04 -wjl
*******************************************************************************************/
#include "datatype.h"
#include "debugout.h"
#include "FCLogManage.h"
#include "fileoperator.h"
#include "readcfg.h"
#include "FCDdos.h"
#include "quote_global.h"

#define DDOS_SYN_FLOOD_TYPE 0
#define DDOS_UDP_FLOOD_TYPE 1
#define DDOS_ICMP_FLOOD_TYPE 2
static const char *DDOS_TYPE_STR[] = {
    "tcp --syn",
    "udp",
    "icmp --icmp-type echo-request",
    NULL,
};

static const pchar DDOS_LOG_STR[] = {
    "LINKLOG_SYNDDOS",
    "LINKLOG_UDPDDOS",
    "LINKLOG_ICMPDDOS",
    NULL,
};

/**
 * [clean_tmp_chain 清空并删除指定临时链，使用前请先解除该链的引用]
 * @param chain_name [临时链名称]
 */
static void clean_tmp_chain(char *chain_name)
{
    char tmp[200] = {0};
    sprintf(tmp, "iptables --wait -F %s", chain_name);
    system(tmp);
}

/**
 * [create_flood_rules 创建指定的防flood攻击链]
 * @param chain_name   [链名称]
 * @param need_create  [是否需要创建]
 * @param type         [flood类型]
 * @param limit        [每秒平均上限]
 * @param burst        [突发上限]
 */
static void create_flood_rules(const char *chain_name, bool need_create, const int32 type,
                               const int32 limit, const int32 burst)
{
    if (type > DDOS_ICMP_FLOOD_TYPE) {
        PRINT_ERR_HEAD;
        print_err("DDOS CREATE CHAIN ERROR: INVALID FLOOD TYPE=%d", type);
        return;
    }

    char cmd[500] = {0};
    if (need_create) {
        PRINT_DBG_HEAD;
        print_dbg("DDOS CREATE CHAIN=%s, TYPE=%d", chain_name, type);
        sprintf(cmd, "iptables --wait -N %s", chain_name);
        system(cmd);
    }

    sprintf(cmd, "iptables --wait -A %s -p %s -m limit --limit %d/s --limit-burst %d -j RETURN",
            chain_name, DDOS_TYPE_STR[type], limit, burst);
    system(cmd);
#if 0
    if (s_b_inside && (type == DDOS_SYN_FLOOD_TYPE)) {
        // 对于管理口 每个IP可以建100个连接 保证别人攻击时 正常机能登录管理设备
        sprintf(cmd,
                "iptables --wait -A %s -p %s -d %s -m connlimit ! --connlimit-above 100 --connlimit-mask 32 -j RETURN",
                chain_name, DDOS_TYPE_STR[type], g_csip);
        system(cmd);
    }
#endif
    sprintf(cmd, "iptables --wait -A %s -p %s -m limit --limit 100/s -j LOG --log-level 7 --log-prefix \"%s \"",
            chain_name, DDOS_TYPE_STR[type], DDOS_LOG_STR[type]);
    system(cmd);
    sprintf(cmd, "iptables --wait -A %s -p %s -j DROP", chain_name, DDOS_TYPE_STR[type]);
    system(cmd);
}

#if 0
/**
 * [create_pod_chain 创建防护ping of death的临时链]
 * @param chain_name   [临时链的名字]
 * @param parent_chain [引用它的父链的名字]
 * @param idx          [引用它的规则在父链中的位置]
 */
static void create_pod_chain(const char *chain_name, bool need_create)
{
    char tmp[500];

    if (need_create) {
        PRINT_DBG_HEAD;
        print_dbg("DDOS CREATE CHAIN=%s, TYPE=POD", chain_name);
        sprintf(tmp, "iptables --wait -N %s", chain_name);
        system(tmp);
    }

    sprintf(tmp, "iptables --wait -A %s -p icmp --icmp-type echo-request -m length --length 65500:65535 "
            "-m limit --limit 100/s -j LOG --log-level 7 --log-prefix \"LINKLOG_ICMPDDOS \"", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p icmp --icmp-type echo-request -m length "
            "--length 65500:65535 -j DROP", chain_name);
    system(tmp);
}

/**
 * [create_nmap_chain  创建NMAP防护的临时链]
 * @param chain_name   [临时链的名字]
 * @param parent_chain [引用它的父链的名字]
 * @param idx          [引用它的规则在父链中的位置]
 */
static void create_nmap_chain(const char *chain_name, const char *parent_chain, const int32 idx)
{
    char tmp[500];

    sprintf(tmp, "iptables --wait -N %s", chain_name);
    system(tmp);

    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags ALL FIN,URG,PSH -m limit "
            "--limit 100/s -j LOG --log-level 7 --log-prefix \"LINKLOG_NMAPDDOS \"", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags SYN,RST SYN,RST -m limit "
            "--limit 100/s -j LOG --log-level 7 --log-prefix \"LINKLOG_NMAPDDOS \"", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags SYN,RST SYN,RST -j DROP", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit "
            "--limit 100/s -j LOG --log-level 7 --log-prefix \"LINKLOG_NMAPDDOS \"", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP", chain_name);
    system(tmp);
    sprintf(tmp, "iptables --wait -A %s -p tcp -j RETURN", chain_name);
    system(tmp);

    //插入到父链中
    sprintf(tmp, "iptables --wait -I %s %d -p tcp -j %s", parent_chain, idx, chain_name);
    system(tmp);

#if 0
    /*iptables --wait -t filter -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags FIN,RST SYN,RST -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags ACK,FIN FIN -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags ACK,PSH PSH -j DROP
    iptables --wait -t filter -A FORWARD -p tcp --tcp-flags ACK,URG URG -j DROP*/
#endif
}
#endif

/**
 * [do_ddos_protection ddos防护]
 */
void do_ddos_protection(void)
{
    CFILEOP fileop;
    char ddos_chain[40] = {"FILTER_DDOS"};

    clean_tmp_chain(ddos_chain);

    if (fileop.OpenFile(SYSSET_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file fail[%s]", SYSSET_CONF);
        return;
    }

    bool need_create_chain = false; //判断是否需要创建ddos链
    int32 limit = 1000, synflood = 0, udpflood = 0, icmpflood = 0;

    READ_INT(fileop, "SYSTEM", "DEFENSE_LIMIT", limit, false, _out);
    if ((limit < 1000) || (limit > 10000)) {
        limit = 1000;
    }
    READ_INT(fileop, "SYSTEM", "DEFENSE_SYN_FLOOD", synflood, false, _out);
    READ_INT(fileop, "SYSTEM", "DEFENSE_UDP_FLOOD", udpflood, false, _out);
    READ_INT(fileop, "SYSTEM", "DEFENSE_ICMP_FLOOD", icmpflood, false, _out);
    if ((synflood == 1) || (udpflood == 1) || (icmpflood == 1)) {
        char chcmd[CMD_BUF_LEN] = {0};
        if (g_workflag == WORK_MODE_TRANSPARENT) {
            sprintf(chcmd, "iptables -A %s -s %d.0.0.%d -j RETURN",
                    ddos_chain, g_linklanipseg, s_b_inside ? 253 : 254);
            system(chcmd);
        } else {
            sprintf(chcmd, "iptables -A %s -i eth%d -j RETURN", ddos_chain, g_linklan);
            system(chcmd);
        }
    }
    if (synflood == 1) {
        create_flood_rules(ddos_chain, need_create_chain,  DDOS_SYN_FLOOD_TYPE, limit, limit / 2);
        PRINT_DBG_HEAD;
        print_dbg("DDOS SYN_FLOOD PROTECTION OPEN");
    }
    if (udpflood == 1) {
        create_flood_rules(ddos_chain, need_create_chain, DDOS_UDP_FLOOD_TYPE, limit, limit / 2);
        PRINT_DBG_HEAD;
        print_dbg("DDOS UDP_FLOOD PROTECTION OPEN");
    }
    if (icmpflood == 1) {
        create_flood_rules(ddos_chain, need_create_chain, DDOS_ICMP_FLOOD_TYPE, limit, limit / 2);
        PRINT_DBG_HEAD;
        print_dbg("DDOS ICMP_FLOOD PROTECTION OPEN");
    }

_out:
    fileop.CloseFile();
    PRINT_DBG_HEAD;
    print_dbg("SET DDOS DONE");
}
