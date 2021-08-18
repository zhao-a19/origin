/*******************************************************************************************
*文件:    syssocket6.h
*描述:    支持IPv6和IPv4, 禁止单独引用此文件，需要syssocket.h即可
*
*作者:    张冬波
*日期:    2018-12-24
*修改:    创建文件                            ------>     2018-12-24
*         添加兼容性接口                      ------>     2019-01-02
*
*
*******************************************************************************************/
#ifndef __SYSSOCKET6_H__
#define __SYSSOCKET6_H__
#include "ip6str.h"

#define IPV4_TAG 4
#define IPV6_TAG 6
//兼容所有地址类型
typedef union sockaddr_types {
    struct sockaddr_storage storage;
    struct sockaddr addr;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
} ssaddr_t;

/**
 * 基础类定义
 */
class CSYSSOCKET6: public CSYSSOCKET
{
public:
    CSYSSOCKET6();
    CSYSSOCKET6(SOCKETTYPE type, bool encode, int domain);
    CSYSSOCKET6(const CSYSSOCKET6 &obj);
    CSYSSOCKET6(SOCKETTYPE type, bool encode, const pchar ip, uint16 port);

    virtual ~CSYSSOCKET6();

    SYSSOCKET createsocket(SOCKETTYPE type, int domain);

    bool setaddress(const pchar ip, uint16 port);
    bool setaddress(const pchar ip, const pchar port);
    bool getaddress(ssaddr_t *addr);
    bool getaddress(void *ip, puint16 port, bool self = false, pchar straddr = NULL);

    bool setconnect(SOCKETTYPE type);
    bool getconnect(void);

    int32 readsocket(void *data, const int32 size);
    int32 writesocket(const void *data, const int32 size);

    bool set6only(bool flag = false);

private:
    int32 m_domain;
    ssaddr_t m_ssaddr;
    char m_addr_lstr[SSADDR_MAX];   //本地地址，端口
    char m_addr_rstr[SSADDR_MAX];   //远端地址，端口

    void init6(void);
    int32 readtcp(SYSSOCKET socket_r, void *data, const int32 size);
    int32 readudp(SYSSOCKET socket_r, void *data, const int32 size);
};


#endif

