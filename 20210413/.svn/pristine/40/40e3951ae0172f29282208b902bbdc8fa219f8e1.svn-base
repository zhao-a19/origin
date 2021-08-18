/*******************************************************************************************
*文件:  FCIPPortMap.h
*描述:  IP端口映射关系类
*       存放IP和端口的映射关系 截取的数据包，通过跟类成员匹配，来区别出是哪个应用的
*作者:  王君雷
*日期:  2016-03
*修改:
*        去除ICMPMAP相关内容;修改匹配函数参数类型                      ------> 2018-12-27
*        重新封装IP端口映射关系类                                      ------> 2019-02-14
*******************************************************************************************/
#ifndef __FC_IPPORT_MAP_H__
#define __FC_IPPORT_MAP_H__

#include "define.h"
#include "stringex.h"
#include <arpa/inet.h>

typedef struct in_addr ip4addr_t;

class IpPortMap
{
public:
    IpPortMap(void);
    IpPortMap(const char *tip, const char *tport, const char *dip, const char *dport,
              const char *midip, const char *appname, const char *proto, int iptype);
    virtual ~IpPortMap(void);

    bool IfMatch(unsigned short port, ip4addr_t addr);
    bool IfMatchIPv6(unsigned short port, ip6addr_t addr);

    const char *GetMidIP(void);
    const char *GetTIP(void);
    bool ProxyInfoEqual(IpPortMap &info);
    bool AppNameEqual(IpPortMap &info);
    bool AppNameEqual(const char *name);
    bool DstInfoEqual(IpPortMap &info);
    bool MidIPEqual(char *ip);
    void MakeTmpPortProxyInfo(void);
    void MakeTmpPortDstInfo(void);
    void MakeTmpIPProxyInfo(void);
    void MakeTmpIPDstInfo(void);
    bool SetMap(const char *tip, const char *tport, const char *dip, const char *dport,
                const char *midip, const char *appname, const char *proto, int iptype);

private:
    void MakeTmpPort(const char *port);
    static void SeparateIP(const char *ip, char *ip1, char *ip2);

private:
    int m_iptype;                      //IP类型  ipv4 ipv6？
    char m_tip[IP_STR_LEN];            //代理ip
    char m_tport[PORT_STR_LEN];        //代理端口
    char m_dip[IP_STR_LEN];            //目的ip
    char m_dport[PORT_STR_LEN];        //目的端口
    char m_midip[IP_STR_LEN];          //网闸间通信使用的ip
    char m_appname[APP_NAME_LEN];      //应用名称
    char m_proto[TRANSPORT_PROTO_LEN]; //协议TCP UDP ...
    unsigned short m_tmpports;
    unsigned short m_tmpporte;
    unsigned long m_tmpips;
    unsigned long m_tmpipe;

    ip6range_t m_ip6range;
    bool m_dstisall;                    //目的是全对象
};

#endif
