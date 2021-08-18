/*******************************************************************************************
*文件:  nginx_manager.h
*描述:  nginx管理类
*作者:  王君雷
*日期:  2019-06-12
*修改:
*       nginx可以实现WEB代理功能                                      ------> 2019-06-19
*       nginx支持重新加载配置；web代理支持分模块生效                    ------> 2020-11-18
*******************************************************************************************/
#ifndef __NGINX_MANAGER_H__
#define __NGINX_MANAGER_H__
#include "define.h"
using namespace std;
#include <list>

typedef struct NIGIX_CONF {
    char tip[IP_STR_LEN];
    int tport;
    int tiptype;
    char dip[IP_STR_LEN];
    int dport;
    int diptype;
    char protocal[TRANSPORT_PROTO_LEN];
} NIGIX_CONF, *PNIGIX_CONF;

typedef struct HTTP_NIGIX_CONF {
    char tip[IP_STR_LEN];
    int tport;
    int tiptype;
    char dns[IP_STR_LEN];
    char dnsipv6[IP_STR_LEN];
} HTTP_NIGIX_CONF, *PHTTP_NIGIX_CONF;

class NGINX_MANAGER
{
public:
    NGINX_MANAGER(void);
    virtual ~NGINX_MANAGER(void);
    bool push_back(const char *tip, int tport, int tiptype, const char *dip, int dport, int diptype, const char *proto);
    bool push_back(const char *tip, int tport, const char *dns, const char *dnsipv6);
    void show_conf(void);
    void clear(void);
    void clear_httpconf(void);
    bool start(void);
    bool reload(void);
    bool stop(void);
    int rule_num(void);
    int rule_num_http(void);
    void generate_file(void);
private:

private:
    list<NIGIX_CONF> m_conf;
    list<HTTP_NIGIX_CONF> m_http_conf;
};

int StartNginxProcess(NGINX_MANAGER *pnginx);

#endif
