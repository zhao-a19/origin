/*******************************************************************************************
*文件:  nginx_manager.cpp
*描述:  nginx管理类
*作者:  王君雷
*日期:  2019-06-12
*修改:
*       nginx可以实现WEB代理功能                                      ------> 2019-06-19
*       web代理可以支持上传下载大文件；可以支持访问任意端口           ------> 2019-07-05
*       修改支持大文件上传下载忘记调用system执行的BUG                 ------> 2019-07-09
*       nginx守护线程，拉起nginx后延迟5s再检查守护，解决飞腾平台判断问题 ------> 2020-09-25
*       写Nginx配置文件时，当只配置了ipv4的dns时加上ipv6=off           ------> 2020-10-14
*       nginx支持重新加载配置；web代理支持分模块生效                    ------> 2020-11-18
*******************************************************************************************/
#include "nginx_manager.h"
#include "debugout.h"
#include "common.h"
#include "stringex.h"
#include <pthread.h>

NGINX_MANAGER::NGINX_MANAGER(void)
{
    clear();
}

NGINX_MANAGER::~NGINX_MANAGER(void)
{
}

/**
 * [NGINX_MANAGER::push_back 把一个配置项添加到nginx管理者中]
 * @param  tip     [代理IP]
 * @param  tport   [代理端口]
 * @param  tiptype [代理IP类型]
 * @param  dip     [目的IP]
 * @param  dport   [目的端口]
 * @param  diptype [目的IP类型]
 * @param  proto   [传输层协议 TCP or UDP]
 * @return         [成功返回true]
 */
bool NGINX_MANAGER::push_back(const char *tip, int tport, int tiptype,
                              const char *dip, int dport, int diptype, const char *proto)
{
    if ((tip == NULL)
        || (tport <= 0)
        || (dip == NULL)
        || (dport <= 0)
        || ((strcmp(proto, "TCP") != 0) && (strcmp(proto, "UDP") != 0))) {
        PRINT_ERR_HEAD
        print_err("nginx push back para error.tip[%s] tport[%d] dip[%s] dport[%d] proto[%s]",
                  tip, tport, dip, dport, proto);
        return false;
    }

    list<NIGIX_CONF>::iterator iter;
    for (iter = m_conf.begin(); iter != m_conf.end(); iter++) {
        if ((strcmp(iter->tip, tip) == 0)
            && (iter->tport == tport)
            && (strcmp(iter->protocal, proto) == 0)) {

            PRINT_ERR_HEAD
            print_err("conf info already in list.tip[%s] tport[%d] tiptype[%d] dip[%s] dport[%d] diptype[%d] proto[%s]",
                      tip, tport, tiptype, dip, dport, diptype, proto);
            return false;
        }
    }

    NIGIX_CONF conf;
    BZERO(conf);
    strncpy(conf.tip, tip, sizeof(conf.tip) - 1);
    strncpy(conf.dip, dip, sizeof(conf.dip) - 1);
    strncpy(conf.protocal, proto, sizeof(conf.protocal) - 1);
    conf.tport = tport;
    conf.dport = dport;
    conf.tiptype = tiptype;
    conf.diptype = diptype;
    m_conf.push_back(conf);

    PRINT_DBG_HEAD
    print_dbg("add conf ok. tip[%s] tport[%d] tiptype[%d] dip[%s] dport[%d] diptype[%d] proto[%s]",
              tip, tport, tiptype, dip, dport, diptype, proto);
    return true;
}

/**
 * [NGINX_MANAGER::push_back 把一个配置项添加到nginx管理者中]
 * @param  tip     [代理IP]
 * @param  tport   [代理端口]
 * @param  dns     [DNS]
 * @param  dnsipv6 [DNSIPV6]
 * @return         [成功返回true]
 */
bool NGINX_MANAGER::push_back(const char *tip, int tport, const char *dns, const char *dnsipv6)
{
    if ((tip == NULL)
        || (tport <= 0)
        || (dns == NULL)) {
        PRINT_ERR_HEAD
        print_err("nginx push back http para error.tip[%s] tport[%d] dns[%s] dnsipv6[%s]",
                  tip, tport, dns, dnsipv6);
        return false;
    }

    list<HTTP_NIGIX_CONF>::iterator iter;
    for (iter = m_http_conf.begin(); iter != m_http_conf.end(); iter++) {
        if ((strcmp(iter->tip, tip) == 0) && (iter->tport == tport)) {
            PRINT_ERR_HEAD
            print_err("conf info already in list.tip[%s] tport[%d] dns[%s] dnsipv6[%s]",
                      tip, tport, dns, dnsipv6);
            return false;
        }
    }

    HTTP_NIGIX_CONF conf;
    BZERO(conf);
    strncpy(conf.tip, tip, sizeof(conf.tip) - 1);
    conf.tport = tport;
    conf.tiptype = is_ip6addr(tip) ? IP_TYPE6 : IP_TYPE4;
    strncpy(conf.dns, dns, sizeof(conf.dns) - 1);
    if (dnsipv6 != NULL) {
        strncpy(conf.dnsipv6, dnsipv6, sizeof(conf.dnsipv6) - 1);
    }
    m_http_conf.push_back(conf);

    PRINT_DBG_HEAD
    print_dbg("add conf ok. tip[%s] tport[%d] tiptype[%d] dns[%s] dnsipv6[%s]", tip, tport,
              conf.tiptype, dns, dnsipv6);
    return true;
}

/**
 * [NGINX_MANAGER::show_conf 打印配置信息]
 */
void NGINX_MANAGER::show_conf(void)
{
    PRINT_DBG_HEAD
    print_dbg("Conf size %d, httpconf size %d", (int)m_conf.size(), (int)m_http_conf.size());

    list<NIGIX_CONF>::iterator iter;
    for (iter = m_conf.begin(); iter != m_conf.end(); iter++) {
        PRINT_DBG_HEAD
        print_dbg("TIP %s TPORT %d TIPTYPE %d DIP %s DPORT %d DIPTYPE %d PROTO %s",
                  iter->tip, iter->tport, iter->tiptype, iter->dip, iter->dport, iter->diptype, iter->protocal);
    }

    list<HTTP_NIGIX_CONF>::iterator httpiter;
    for (httpiter = m_http_conf.begin(); httpiter != m_http_conf.end(); httpiter++) {
        PRINT_DBG_HEAD
        print_dbg("TIP %s TPORT %d TIPTYPE %d DNS %s DNSIPV6 %s",
                  httpiter->tip, httpiter->tport, httpiter->tiptype, httpiter->dns, httpiter->dnsipv6);
    }
}

/**
 * [NGINX_MANAGER::clear 清空操作]
 */
void NGINX_MANAGER::clear(void)
{
    m_conf.clear();
    m_http_conf.clear();
}

/**
 * [NGINX_MANAGER::clear_httpconf 清空http相关配置]
 */
void NGINX_MANAGER::clear_httpconf(void)
{
    m_http_conf.clear();
}

/**
 * [NGINX_MANAGER::generate_file 生成配置文件]
 */
void NGINX_MANAGER::generate_file(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    const char *filename = "/tmp/nginx.conf";

    remove(filename);
    sprintf(chcmd, "echo user root\\; >%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo worker_processes auto\\; >>%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo pid /tmp/nginx.pid\\; >>%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo error_log  /tmp/error.log\\; >>%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo events { >>%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo worker_connections 50000\\;>>%s", filename);
    system(chcmd);
    sprintf(chcmd, "echo }>>%s", filename);
    system(chcmd);


    if (m_http_conf.size() > 0) {
        sprintf(chcmd, "echo http {>>%s", filename);
        system(chcmd);
        sprintf(chcmd, "echo access_log off\\;>>%s", filename);
        system(chcmd);
        sprintf(chcmd, "echo default_type  application/octet-stream\\;>>%s", filename);
        system(chcmd);
        sprintf(chcmd, "echo sendfile on\\;>>%s", filename);
        system(chcmd);
        sprintf(chcmd, "echo keepalive_timeout 65\\;>>%s", filename);
        system(chcmd);

        list<HTTP_NIGIX_CONF>::iterator httpiter;
        for (httpiter = m_http_conf.begin(); httpiter != m_http_conf.end(); httpiter++) {
            sprintf(chcmd, "echo server{>>%s", filename);
            system(chcmd);
            if (strlen(httpiter->dns) > 0) {
                if (strlen(httpiter->dnsipv6) == 0) {
                    sprintf(chcmd, "echo resolver '%s' ipv6=off\\;>>%s", httpiter->dns, filename);
                } else {
                    sprintf(chcmd, "echo resolver '%s'\\;>>%s", httpiter->dns, filename);
                }
                system_safe(chcmd);
            }
            if (strlen(httpiter->dnsipv6) > 0) {
                sprintf(chcmd, "echo resolver '%s'\\;>>%s", httpiter->dnsipv6, filename);
                system_safe(chcmd);
            }
            sprintf(chcmd, "echo client_max_body_size 102400m\\;>>%s", filename);
            system(chcmd);
            sprintf(chcmd, "echo resolver_timeout 20s\\;>>%s", filename);
            system(chcmd);
            if (httpiter->tiptype == IP_TYPE6) {
                sprintf(chcmd, "echo listen ['%s']:%d ipv6only=on\\;>>%s", httpiter->tip, httpiter->tport, filename);
                system_safe(chcmd);
            } else {
                sprintf(chcmd, "echo listen '%s':%d\\;>>%s", httpiter->tip, httpiter->tport, filename);
                system_safe(chcmd);
            }
            sprintf(chcmd, "echo proxy_connect\\;>>%s", filename);
            system(chcmd);

            sprintf(chcmd, "echo proxy_connect_allow all\\;>>%s", filename);
            system(chcmd);
            sprintf(chcmd, "echo include %s\\;>>%s", NGINX_HTTP_CONF, filename);
            system(chcmd);

            sprintf(chcmd, "echo }>>%s", filename);
            system(chcmd);
        }
        sprintf(chcmd, "echo }>>%s", filename);
        system(chcmd);
    }
    if (m_conf.size() > 0) {
        sprintf(chcmd, "echo stream{>>%s", filename);
        system(chcmd);
        list<NIGIX_CONF>::iterator iter;
        for (iter = m_conf.begin(); iter != m_conf.end(); iter++) {
            sprintf(chcmd, "echo server{>>%s", filename);
            system(chcmd);

            if (iter->tiptype == IP_TYPE6) {
                sprintf(chcmd, "echo listen ['%s']:%d%s\\;>>%s", iter->tip, iter->tport,
                        (strcmp(iter->protocal, "TCP") == 0) ? "" : " udp", filename);
            } else {
                sprintf(chcmd, "echo listen '%s':%d%s\\;>>%s", iter->tip, iter->tport,
                        (strcmp(iter->protocal, "TCP") == 0) ? "" : " udp", filename);
            }
            system_safe(chcmd);
            sprintf(chcmd, "echo proxy_connect_timeout 10s\\;>>%s", filename);
            system(chcmd);
            sprintf(chcmd, "echo proxy_timeout 10s\\;>>%s", filename);
            system(chcmd);
            if (iter->diptype == IP_TYPE6) {
                sprintf(chcmd, "echo proxy_pass ['%s']:%d\\;>>%s", iter->dip, iter->dport, filename);
            } else {
                sprintf(chcmd, "echo proxy_pass '%s':%d\\;>>%s", iter->dip, iter->dport, filename);
            }
            system_safe(chcmd);
            sprintf(chcmd, "echo }>>%s", filename);
            system(chcmd);
        }
        sprintf(chcmd, "echo } >>%s", filename);
        system(chcmd);
    }
    PRINT_INFO_HEAD
    print_info("nginx generate file over[%s]", filename);
}

/**
 * [NGINX_MANAGER::start 运行nginx程序]
 * @return  [成功返回true]
 */
bool NGINX_MANAGER::start(void)
{
    char chcmd[CMD_BUF_LEN] = {0};

    if (rule_num() > 0) {
        system("mkdir -p /tmp/logs/");
        system("killall nginx");
        snprintf(chcmd, sizeof(chcmd), "%s -p /tmp/ -c nginx.conf", NGINX);
        PRINT_INFO_HEAD
        print_info("begin to run nginx[%s]", chcmd);
        system(chcmd);
    }
    return true;
}

/**
 * [NGINX_MANAGER::reload 重新加载配置信息]
 * @return  [成功返回true]
 */
bool NGINX_MANAGER::reload(void)
{
    char chcmd[CMD_BUF_LEN] = {0};
    snprintf(chcmd, sizeof(chcmd), "%s -p /tmp/ -c nginx.conf -s reload", NGINX);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("reload nginx[%s]", chcmd);
    return true;
}

/**
 * [NGINX_MANAGER::stop 停止nginx的运行]
 * @return  [成功返回true]
 */
bool NGINX_MANAGER::stop(void)
{
    system("killall nginx");
    return true;
}

/**
 * [NGINX_MANAGER::rule_num 规则数]
 * @return  [规则数]
 */
int NGINX_MANAGER::rule_num(void)
{
    return m_conf.size() + m_http_conf.size();
}

/**
 * [NGINX_MANAGER::rule_num_http HTTP规则数]
 * @return  [HTTP规则数]
 */
int NGINX_MANAGER::rule_num_http(void)
{
    return m_http_conf.size();
}

/**
 * [nginxproc 启动nginx的线程函数]
 * @param  arg [NGINX_MANAGER指针]
 * @return     [未使用]
 */
void *nginxproc(void *arg)
{
    pthread_setself("nginxproc");

    NGINX_MANAGER *ptr = (NGINX_MANAGER *)arg;
    CCommon common;

    PRINT_DBG_HEAD
    print_dbg("nignx proc begin.rulenum[%d]", ptr->rule_num());

    while (1) {
        sleep(1);
        ptr->start();
        sleep(5);
        while (common.ProcessRuning(NGINX)) {
            sleep(5);
        }
        if (ptr->rule_num() == 0) {
            break;
        } else {
            PRINT_INFO_HEAD
            print_info("Pull up nginx again");
        }
    }

    PRINT_DBG_HEAD
    print_dbg("nignx proc exit.");
    return NULL;
}

/**
 * [StartNginxProcess 启动WEB代理程序]
 * @param  pnginx   [管理对象指针]
 * @return          [成功返回0]
 */
int StartNginxProcess(NGINX_MANAGER *pnginx)
{
    if (pnginx == NULL) {
        PRINT_ERR_HEAD
        print_err("pnginx para null");
        return -1;
    }

    if (pnginx->rule_num() > 0) {
        PRINT_INFO_HEAD
        print_info("nginx conf rulenum[%d]", pnginx->rule_num());

        pnginx->generate_file();
        pthread_t threadid;
        if (pthread_create(&threadid, NULL, nginxproc, (void *)pnginx) != 0) {
            PRINT_ERR_HEAD
            print_err("create nginx thread error");
            return -1;
        }
    }
    return 0;
}
