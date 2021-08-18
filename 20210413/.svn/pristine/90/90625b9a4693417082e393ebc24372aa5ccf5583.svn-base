/*******************************************************************************************
*文件:    netosi.h
*描述:    网络相关数据结构定义
*         移植网络应用
*
*作者:    张冬波
*日期:    2015-11-11
*修改:    创建文件                            ------>     2015-11-11
*         修改IP分片BUG                       ------>     2015-12-09
*         修改编译冲突                        ------>     2015-12-18
*         添加接口，修改bug                   ------>     2015-12-22
*         修改IP层接口和分片判断bug           ------>     2016-04-06
*         修改IP头长度bug                     ------>     2016-05-27
*         添加IPV6头部                        ------>     2018-12-27 王君雷
*         添加DNS头部                         ------>     2019-01-19 王君雷
*         添加ipv6的各种扩展头部              ------>     2019-01-22 王君雷
*         添加ipv6版本的伪首部等结构          ------>     2019-01-30 王君雷
*         修改ipv6伪首部字段大小有误的BUG     ------>     2019-04-09 王君雷
*******************************************************************************************/
#include "datatype.h"

#ifndef __NETOSI_H__
#define __NETOSI_H__

#include <arpa/inet.h>

#pragma pack(push, 1)

#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__   (1)   //BYTE ORDER
#else
#error Redefine LITTLE_ORDER
#endif

/*********************************************/
//计算机网络各种协议的结构
#define ETHER_ADDR_LEN 6 //NIC物理地址占6字节
#define MAXDATA 10240
/*
网络实验程序
数据包中的TCP包头,IP包头,UDP包头,ARP包,Ethernet包等.
以及各种表.路由寻址表,地址解析协议表DNS表等
*/
#define ETHERTYPE_IP 0x0800   //IP Protocal
#define ETHERTYPE_ARP 0x0806   //Address Resolution Protocal
#define ETHERTYPE_REVARP 0x0835   //Reverse Address Resolution Protocal 逆地址解析协议
/*********************************************/
//ethernet
typedef struct ether_header {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
} ETH_HEADER;
/*********************************************/
//ether_header eth;
/*********************************************/
//arp
typedef struct arphdr {
    u_short ar_hrd;
    u_short ar_pro;
    u_char ar_hln;
    u_char ar_pln;
    u_short ar_op;
} ARP_HEADER;
/*********************************************/
/*********************************************/
//IP报头
typedef struct ip {
#if __LITTLE_ENDIAN__
    u_char ip_hl: 4; //header length(报头长度)
    u_char ip_v: 4; //version(版本)
#else
    u_char ip_v: 4; //version(版本)
    u_char ip_hl: 4; //header length(报头长度)
#endif
    u_char ip_tos;

    u_short ip_len;
    u_short ip_id;
    union {
        u_short ip_off;
#if __LITTLE_ENDIAN__
        struct {
            u_char ip_reserved1: 5;
            u_char ip_flag: 3;
            u_char ip_reserved2;
        };
#else
        struct {
            u_char ip_reserved2;
            u_char ip_flag: 3;
            u_char ip_reserved1: 5;
        };
#endif
    };

    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
} IP_HEADER, *PIP_HEADER;

//ip_p部分定义
enum {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ICMPV6 = 58,
    HOP_BY_HOP = 0,        //逐跳选项
    DESTINATIONS_OPT = 60, //目的选项报头
    ROUTING_HEADER = 43,   //路由报头
    FRAGMENT_HEADER = 44,  //分段报头
    AUTH_HEADER = 51,      //认证报头
    ESP = 50,              //封装安全有效载荷
    MIPV6 = 135,           //移动
    NO_NEXT_HEADER = 59,   //无下一个首部
};

#define _ipv4(ip) (((IP_HEADER*)(ip))->ip_v==4)
#define _ipv6(ip) (((IP_HEADER*)(ip))->ip_v==6)
#define _ipheadlen(ip) (((IP_HEADER*)(ip))->ip_hl * 4)

#if __LITTLE_ENDIAN__
#define _iplen(ip) (((((IP_HEADER*)(ip))->ip_len & 0xFF)<<8) + ((((IP_HEADER*)(ip))->ip_len >>8)&0xFF))
#else
#define _iplen(ip) (((IP_HEADER*)(ip))->ip_len & 0xFF)
#endif

//分片判断
#if __LITTLE_ENDIAN__
#define _ipoff(ip) (u_short)((((u_short)(((IP_HEADER*)(ip))->ip_reserved1))<<8)+((IP_HEADER*)(ip))->ip_reserved2)
#else
#define _ipoff(ip) (((IP_HEADER*)(ip))->ip_off&0x1FFF)
#endif
#define IPDF   (0x02)
#define IPMF   (0x01)
#define _ipfragment(ip) (!(((((IP_HEADER*)(ip))->ip_flag&IPMF)==0) && (_ipoff(ip)==0)))

#define _ipproto(ip) (((IP_HEADER*)(ip))->ip_p)

//头结构判断
#define _iphead(ip) ((_ipheadlen(ip) >= sizeof(IP_HEADER)) && (_ipheadlen(ip) <= _iplen(ip)))

/*********************************************/
/*********************************************/
//TCP报头结构体
typedef struct tcphdr {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
#if __LITTLE_ENDIAN__
    u_char reserved_1: 4;
    u_char th_off: 4;       //tcp头部长度
#else
    u_char th_off: 4;       //tcp头部长度
    u_char reserved_1: 4;
#endif
    u_char th_flags;        //8位标志
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} TCP_HEADER, *PTCP_HEADER;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
/*********************************************/
/*********************************************/
//UDP报头结构体*/
typedef struct udphdr {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
} UDP_HEADER, *PUDP_HEADER;
/*********************************************/
//=============================================
/*********************************************/
/*ARP与ETHERNET生成的报头*/
typedef struct ether_arp {
    struct arphdr ea_hdr;
    u_char arp_sha[ETHER_ADDR_LEN];
    u_char arp_spa[4];
    u_char arp_tha[ETHER_ADDR_LEN];
    u_char arp_tpa[4];
} ETH_ARP;
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op
#define ARPHRD 1
/*********************************************/
/*********************************************/
//tcp与ip生成的报头    有IP选项时不能使用 不建议使用该结构
/*
typedef struct packet_tcp {
    struct ip ip;
    struct tcphdr tcp;
    u_char data[MAXDATA];
} TCP_IP;
*/
#define _tcpipdata(d) (TCP_HEADER*)((pchar)(d)+_ipheadlen(d))
#define _tcpheadlen(d) (((TCP_HEADER*)(d))->th_off*4)
#define _tcpdata(d) ((pchar)(d)+_tcpheadlen(d))

/*********************************************/
/*********************************************/
//udp与ip生成的报头    有IP选项时不能使用 不建议使用该结构
/*
typedef struct packet_udp {
    struct ip ip;
    struct udphdr udp;
} UDP_IP;
*/

#define _udpipdata(d) (UDP_HEADER*)((pchar)(d)+_ipheadlen(d))
#define _udpheadlen(d) (sizeof(UDP_HEADER))
#define _udpdata(d) ((pchar)(d)+_udpheadlen(d))

/*********************************************/
/*********************************************/
//ICMP的各种形式
//icmpx,x==icmp_type;
//icmp报文(能到达目的地,响应-请求包)
typedef struct icmp8 {
    u_char icmp_type; //type of message(报文类型)
    u_char icmp_code; //type sub code(报文类型子码)
    u_short icmp_cksum;
    u_short icmp_id;
    u_short icmp_seq;
    char icmp_data[1];
} ICMP8, *PICMP8;
//icmp报文(能返回目的地,响应-应答包)
struct icmp0 {
    u_char icmp_type; //type of message(报文类型)
    u_char icmp_code; //type sub code(报文类型子码)
    u_short icmp_cksum;
    u_short icmp_id;
    u_short icmp_seq;
    char icmp_data[1];
};
//icmp报文(不能到达目的地)
struct icmp3 {
    u_char icmp_type; //type of message(报文类型)
    u_char icmp_code; //type sub code(报文类型子码),例如:0网络原因不能到达,1主机原因不能到达...
    u_short icmp_cksum;
    u_short icmp_pmvoid;
    u_short icmp_nextmtu;
    char icmp_data[1];
};
//icmp报文(重发结构体)
struct icmp5 {
    u_char icmp_type; //type of message(报文类型)
    u_char icmp_code; //type sub code(报文类型子码)
    u_short icmp_cksum;
    struct in_addr icmp_gwaddr;
    char icmp_data[1];
};
struct icmp11 {
    u_char icmp_type; //type of message(报文类型)
    u_char icmp_code; //type sub code(报文类型子码)
    u_short icmp_cksum;
    u_int icmp_void;
    char icmp_data[1];
};

#define _icmp8ipdata(d) (PICMP8)((pchar)(d)+_ipheadlen(d))

//TCP or UDP 伪首部
typedef struct _pseudo_header {
    struct in_addr ip_src; //4B
    struct in_addr ip_dst; //4B
    u_char zeros;          //1B
    u_char protocol;       //1B
    u_short len;           //2B
} PSEUDO_HEADER, *PPSEUDO_HEADER;

//IPV6版本的伪首部
typedef struct _pseudo_header_ipv6 {
    struct in6_addr ip_src;//16B
    struct in6_addr ip_dst;//16B
    uint32 len;            //4B
    u_char zeros[3];       //3B
    u_char next_header;    //1B
} PSEUDO_HEADER_IPV6, *PPSEUDO_HEADER_IPV6;

//ipv6
typedef struct _ipv6header {
#if __LITTLE_ENDIAN__
    u_char ip_tc1: 4;   //traffic class
    u_char ip_v: 4;     //version(版本)
    u_char ip_flowlabel1: 4; //
    u_char ip_tc2: 4;   //traffic class
#else
    u_char ip_v: 4;    //version(版本)
    u_char ip_tc1: 4;  //traffic class
    u_char ip_tc2: 4;  //traffic class
    u_char ip_flowlabel1: 4;//
#endif
    u_short ip_flowlabel2;
    u_short ip_payloadlen;
    u_char ip_nexthd;     //下一个头部
    u_char ip_hoplimit;
    struct in6_addr ip_src;
    struct in6_addr ip_dst;
} IPV6_HEADER, *PIPV6_HEADER;

#define _ipv6headlen(ip) 40

#if __LITTLE_ENDIAN__
#define _ipv6len(ip) (((((IPV6_HEADER*)(ip))->ip_payloadlen & 0xFF)<<8) + ((((IPV6_HEADER*)(ip))->ip_payloadlen >>8)&0xFF))
#else
#define _ipv6len(ip) (((IPV6_HEADER*)(ip))->ip_payloadlen & 0xFF)
#endif

//DNS头部
typedef struct _dns_header {
    u_short transaction_id;
    u_char flags[2];
    u_short qd_count;
    u_short an_count;
    u_short ns_count;
    u_short ar_count;
} DNS_HEADER, *PDNS_HEADER;

//逐跳选项报头
typedef struct _ext_hop_by_hop {
    u_char next_header; //下一个头部
    u_char hdr_ext_len; //报头扩展长度
    char options[];     //选项
} EXT_HOP_BY_HOP, *PEXT_HOP_BY_HOP;

//目的选项报头
typedef struct _ext_destinations_opt {
    u_char next_header;     //下一个头部
    u_char hdr_ext_len;     //报头扩展长度
    char options[];         //选项
} EXT_DESTINATIONS_OPT, *PEXT_DESTINATIONS_OPT;

//路由报头
typedef struct _ext_router_header {
    u_char next_header;  //下一个头部
    u_char hdr_ext_len;  //报头扩展长度
    u_char routing_type; //路由类型
    u_char segments_left;//段剩余
    char type_specified_data[];//路由特定类型数据
} EXT_ROUTING_HEADER, *PEXT_ROUTING_HEADER;

//分片头部
typedef struct _ext_fragment_header {
    u_char next_header;
    u_char reserved;
    u_char offset1;
#if __LITTLE_ENDIAN__
    u_char m: 1;
    u_char res: 2;
    u_char offset2: 5;
#else
    u_char offset2: 5;
    u_char res: 2;
    u_char m: 1;
#endif
    u_char identification[4];
} EXT_FRAGMENT_HEADER, *PEXT_FRAGMENT_HEADER;

//认证报头
typedef struct _ext_auth_header {
    u_char next_header;
    u_char hdr_ext_len;
    u_char reserved[2];
    uint32 spi;    //安全参数索引
    uint32 seq;    //序列号
    u_char value[];//完整性校验值

} EXT_AUTH_HEADER, *PEXT_AUTH_HEADER;

//封装安全有效载荷
typedef struct _ext_esp {
    uint32 spi;    //安全参数索引
    uint32 seq;    //序列号
    u_char value[];//负载数据
} EXT_ESP, *PEXT_ESP;

//移动ipv6头部
typedef struct _ext_mipv6 {
    u_char next_header;
    u_char hdr_ext_len;
    u_char mh_type; //移动性首部类型
    u_char reserved;
    u_char check[2];//校验和
    u_char value[];
} EXT_MIPV6, *PEXT_MIPV6;

typedef struct _icmpv6_header {
    u_char type;
    u_char code;
    u_short cksum;
    u_char body[];
} ICMPV6_HEADER, *PICMPV6_HEADER;

#pragma pack(pop)

#endif

