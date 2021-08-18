/*******************************************************************************************
*文件:  FCIPPortMap.h
*描述:  IP端口映射关系类
*作者:  王君雷
*日期:  2016-03
*修改:
**        去除ICMPMAP相关内容;修改匹配函数参数类型                    ------> 2018-12-27
*         支持ipv6，开发过程版                                        ------> 2019-01-30
*         重新封装IP端口映射关系类                                    ------> 2019-02-14
*******************************************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "FCIPPortMap.h"
#include "debugout.h"
#include "const.h"

IpPortMap::IpPortMap(void)
{
    m_iptype = IP_TYPE4;//默认为ipv4
}

IpPortMap::~IpPortMap(void)
{
}

IpPortMap::IpPortMap(const char *tip, const char *tport, const char *dip, const char *dport,
                     const char *midip, const char *appname, const char *proto, int iptype)
{
    if (!SetMap(tip, tport, dip, dport, midip, appname, proto, iptype)) {
        PRINT_ERR_HEAD
        print_err("set map info fail.");
    }
}

/**
 * [IpPortMap::SetMap 设置映射IP端口信息]
 * @param  tip     [代理IP]
 * @param  tport   [代理端口]
 * @param  dip     [目的IP]
 * @param  dport   [目的端口]
 * @param  midip   [跳转IP]
 * @param  appname [应用名称]
 * @param  proto   [应用协议]
 * @param  iptype  [IP类型]
 * @return         [成功返回true]
 */
bool IpPortMap::SetMap(const char *tip, const char *tport, const char *dip, const char *dport,
                       const char *midip, const char *appname, const char *proto, int iptype)
{
    if ((tip == NULL) || (tport == NULL) || (dip == NULL) || (dport == NULL) || (midip == NULL)
        || (appname == NULL) || (proto == NULL)) {
        PRINT_ERR_HEAD
        print_err("param null. tip[%s] tport[%s] dip[%s] dport[%s] midip[%s] appname[%s] proto[%s] iptype[%d]",
                  tip, tport, dip, dport, midip, appname, proto, iptype);
        return false;
    } else {
        strcpy(m_tip, tip);
        strcpy(m_tport, tport);
        strcpy(m_dip, dip);
        strcpy(m_dport, dport);
        strcpy(m_midip, midip);
        strcpy(m_appname, appname);
        strcpy(m_proto, proto);
        m_iptype = iptype;

        PRINT_DBG_HEAD
        print_dbg("set map ok.tip[%s] tport[%s] dip[%s] dport[%s] midip[%s] appname[%s] proto[%s] iptype[%d]",
                  tip, tport, dip, dport, midip, appname, proto, iptype);
        return true;
    }
}

/**
 * [IpPortMap::IfMatch 是否匹配]
 * @param  port  [端口]
 * @param  addr  [IP地址]
 * @return       [匹配返回true]
 */
bool IpPortMap::IfMatch(unsigned short port, ip4addr_t addr)
{
    if (m_iptype != IP_TYPE6) {
        if ((port >= m_tmpports) && (port <= m_tmpporte)) {
            if (m_dstisall) {
                return true;
            }

            uint32 n1 = ntohl(addr.s_addr);
            return ((n1 >= m_tmpips) && (n1 <= m_tmpipe));
        }
    }
    return false;
}

/**
 * [IpPortMap::IfMatchIPv6 是否匹配 IPv6]
 * @param  port [端口]
 * @param  addr [IP地址]
 * @return      [匹配返回true]
 */
bool IpPortMap::IfMatchIPv6(unsigned short port, ip6addr_t addr)
{
    if (m_iptype == IP_TYPE6) {
        if ((port >= m_tmpports) && (port <= m_tmpporte)) {
            if (m_dstisall || is_inip6r(&addr, &m_ip6range)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * [IpPortMap::ProxyInfoEqual 判断参数对象与本对象的代理信息是否相同]
 * @param  info [输入对象]
 * @return      [相同返回true]
 */
bool IpPortMap::ProxyInfoEqual(IpPortMap &info)
{
    return (strcmp(m_tip, info.m_tip) == 0)
           && (strcmp(m_tport, info.m_tport) == 0)
           && (strcmp(m_proto, info.m_proto) == 0);
}

/**
 * [IpPortMap::AppNameEqual 应用名称相同]
 * @param  info [输入对象]
 * @return      [相同返回true]
 */
bool IpPortMap::AppNameEqual(IpPortMap &info)
{
    return (strcmp(m_appname, info.m_appname) == 0);
}

/**
 * [IpPortMap::AppNameEqual 判断输入的名称是否跟当前应用名称相同]
 * @param  name [输入应用名称]
 * @return      [相同返回true]
 */
bool IpPortMap::AppNameEqual(const char *name)
{
    if (name == NULL) {
        PRINT_ERR_HEAD
        print_err("input name null while cmpare appname");
        return false;
    }
    return (strcmp(name, m_appname) == 0);
}

/**
 * [IpPortMap::DstInfoEqual 判断参数对象与本对象的目的对象信息是否相同]
 * @param  info [输入对象]
 * @return      [相同返回true]
 */
bool IpPortMap::DstInfoEqual(IpPortMap &info)
{
    return (strcmp(m_dip, info.m_dip) == 0)
           && (strcmp(m_dport, info.m_dport) == 0)
           && (strcmp(m_proto, info.m_proto) == 0);
}

/**
 * [IpPortMap::MakeTmpPortProxyInfo 使用代理信息 组装端口临时信息 策略匹配时要使用]
 */
void IpPortMap::MakeTmpPortProxyInfo(void)
{
    MakeTmpPort(m_tport);
}

/**
 * [IpPortMap::MakeTmpPortDstInfo 使用目的对象信息 组装端口临时信息 策略匹配时要使用]
 */
void IpPortMap::MakeTmpPortDstInfo(void)
{
    MakeTmpPort(m_dport);
}

/**
 * [IpPortMap::MakeTmpPort 组装端口临时信息 策略匹配时要使用]
 * @param port [端口信息]
 */
void IpPortMap::MakeTmpPort(const char *port)
{
    const char *ptr = NULL;
    if ((ptr = strchr(port, '-')) != NULL) {
        m_tmpports = atoi(port);
        m_tmpporte = atoi(ptr + 1);
    } else {
        m_tmpports = atoi(port);
        m_tmpporte = atoi(port);
    }

    PRINT_DBG_HEAD
    print_dbg("tmpports[%d],tmpporte[%d]", m_tmpports, m_tmpporte);
}

/**
 * [IpPortMap::MakeTmpIPProxyInfo 使用代理信息 组装地址临时信息 策略匹配时要使用]
 */
void IpPortMap::MakeTmpIPProxyInfo(void)
{
    m_dstisall = false;
    if (m_iptype == IP_TYPE6) {
        inet_pton(AF_INET6, m_midip, (void *) & (m_ip6range.ip6l));
        inet_pton(AF_INET6, m_midip, (void *) & (m_ip6range.ip6h));
    } else {
        ip4addr_t addr1;
        inet_pton(AF_INET, m_midip, (void *)&addr1);
        m_tmpipe = m_tmpips = ntohl(addr1.s_addr);
    }
}

/**
 * [IpPortMap::MakeTmpIPDstInfo 使用目的对象信息 组装地址临时信息 策略匹配时要使用]
 */
void IpPortMap::MakeTmpIPDstInfo(void)
{
    char ip1[IP_STR_LEN] = {0};
    char ip2[IP_STR_LEN] = {0};

    if (m_iptype == IP_TYPE6) {
        if (IPV6_ALL_OBJ(m_dip)) {
            m_dstisall = true;
        } else {
            m_dstisall = false;
            SeparateIP(m_dip, ip1, ip2);
            inet_pton(AF_INET6, ip1, (void *) & (m_ip6range.ip6l));
            inet_pton(AF_INET6, ip2, (void *) & (m_ip6range.ip6h));
        }
    } else {
        if (ALL_OBJ(m_dip)) {
            m_dstisall = true;
        } else {
            m_dstisall = false;
            ip4addr_t addr1, addr2;
            SeparateIP(m_dip, ip1, ip2);
            inet_pton(AF_INET, ip1, (void *)&addr1);
            inet_pton(AF_INET, ip2, (void *)&addr2);
            m_tmpips = ntohl(addr1.s_addr);
            m_tmpipe = ntohl(addr2.s_addr);
        }
    }
}

/**
 * [IpPortMap::SeparateIP 分割ip，对于减号连接的范围IP，把前者放到ip1，后者放到ip2；
 *                        对于单个IP，则把它直接复制到ip1 ip2]
 * @param ip  [待处理的IP]
 * @param ip1 [description]
 * @param ip2 [description]
 */
void IpPortMap::SeparateIP(const char *ip, char *ip1, char *ip2)
{
    if ((ip == NULL) || (ip1 == NULL) || (ip2 == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while separate ip.[%s]", ip);
        return;
    }
    const char *p = strchr(ip, '-');
    if (p != NULL) {
        memcpy(ip1, ip, p - ip);
        strcpy(ip2, p + 1);
    } else {
        strcpy(ip1, ip);
        strcpy(ip2, ip);
    }
}

/**
 * [IpPortMap::GetMidIP 获取内部跳转IP]
 * @return  [description]
 */
const char *IpPortMap::GetMidIP(void)
{
    return m_midip;
}

/**
 * [IpPortMap::GetTIP 获取代理IP]
 * @return  [description]
 */
const char *IpPortMap::GetTIP(void)
{
    return m_tip;
}

/**
 * [MidIPEqual 判断参数IP是否与本对象的内部跳转IP相等]
 * @param  ip [参数IP]
 * @return    [相等返回true]
 */
bool IpPortMap::MidIPEqual(char *ip) //为了适应ip6strcmp函数参数类型  暂不加const
{
    if (m_iptype == IP_TYPE6) {
        return is_ip6addr(ip) && (ip6strcmp(ip, m_midip) == 0);
    } else {
        return (strcmp(ip, m_midip) == 0);
    }
}
