/*******************************************************************************************
*文件:  simple.cpp
*描述:  通用函数 有多个地方调用 又不好分类的接口放在了这里
*作者:  王君雷
*日期:  2016
*修改:
*       把获取网卡MAC函数移出到单独文件中                                ------> 2019-09-09
*       GetAuthName函数添加第三个参数，指示缓冲区长度                    ------> 2018-12-21
*       create_and_bind_tcp函数支持IPV4 IPV6                             ------> 2019-02-20
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>

#include <vector>
using namespace std;

#include "const.h"
#include "simple.h"
#include "define.h"
#include "fileoperator.h"
#include "struct_info.h"
#include "quote_global.h"
#include "debugout.h"
#include "stringex.h"

/**
 * [mysql_init_connect mysql的初始化和连接]
 * @param  mysql [mysql对象指针]
 * @return       [成功返回0 失败返回负值]
 */
int mysql_init_connect(MYSQL *mysql)
{
    //初始化数据库链接信息
    if (mysql_init(mysql) == NULL) {
        PRINT_ERR_HEAD
        print_err("mysql_init err");
        return -1;
    }

    if (mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "client") != 0) {
        mysql_close(mysql);
        PRINT_ERR_HEAD
        print_err("mysql_options err");
        return -1;
    }

    if (mysql_real_connect(mysql, DEFAULT_HOST, "susqlroot", "suanmitsql", "sudb", 0, NULL, 0) == NULL) {
        PRINT_ERR_HEAD
        print_err("Connect DB error");
        mysql_close(mysql);
        return -1;
    }

    return 0;
}

/**
 * [GetAuthName 读取输入的ip对应的认证用户名]
 * @param  ip       [IP]
 * @param  authname [认证用户名称]
 * @param  len      [认证用户名称缓冲区长度]
 * @return          [成功返回0]
 */
int GetAuthName(const char *ip, char *authname, int len)
{
    if ((ip == NULL) || (authname == NULL) || (len <= 0)) {
        PRINT_ERR_HEAD
        print_err("para err.ip[%s] len[%d]", ip, len);
        return -1;
    }

    int ipnum = 0;
    char tmp[100] = {0};
    char iterm[32] = {0};

    //文件中找IP 认证用户
    CFILEOP fileop;
    if (fileop.OpenFile(IPAUTH_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("open file[%s] fail", IPAUTH_CONF);
        return -1;
    }

    if (fileop.ReadCfgFileInt("MAIN", "Num", &ipnum) == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("read ipnum fail");
        fileop.CloseFile();
        return -1;
    }

    for (int i = 0; i < ipnum; i++ ) {
        sprintf(iterm, "IP%d", i);
        BZERO(tmp);
        if (fileop.ReadCfgFile(iterm, "IP", tmp, sizeof(tmp)) == E_FILE_FALSE) {
            PRINT_ERR_HEAD
            print_err("read [%s][IP] fail", iterm);
            break;
        }
        if (strcmp(ip, tmp) == 0) {
            if (fileop.ReadCfgFile(iterm, "Name", authname, len) == E_FILE_FALSE) {
                PRINT_ERR_HEAD
                print_err("read [%s][Name] fail", iterm);
                break;
            }
            fileop.CloseFile();
            PRINT_DBG_HEAD
            print_dbg("get authname ok [%s:%s]", ip, authname);
            return 0;
        }
    }
    fileop.CloseFile();
    PRINT_ERR_HEAD
    print_err("ip[%s],get authname fail", ip);
    return -1;
}

/**
 * [get_out_mac 获取外网侧网卡MAC]
 * @param  ethno [网卡号]
 * @param  mac   [MAC  出参]
 * @return       [成功返回true]
 */
bool get_out_mac(int ethno, char *mac)
{
    //不准外网调用
    if (DEVFLAG[0] != 'I') {
        PRINT_ERR_HEAD
        print_err("out net cannot call this function");
        return false;
    }

    char send_buf[256] = {0};
    HEADER header;
    BZERO(header);
    header.appnum = GET_OUT_MAC_TYPE;
    unsigned int length = sizeof(length) + sizeof(ethno);

    //socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return false;
    }

    char ip[IP_STR_LEN] = {0};
    sprintf(ip, "%d.0.0.253", g_linklanipseg);

    //填写地址结构
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_linklanport);
    int ret = inet_pton(AF_INET, ip, (void *)&addr.sin_addr);
    if ( ret <= 0 ) {
        PRINT_ERR_HEAD
        print_err("inet_pton error[%s][%s]", strerror(errno), ip);
        close(fd);
        return false;
    }

    //设置接收超时 秒
    struct timeval timeout = {MSG_ACK_TIME_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

    //按协议组消息
    memcpy(send_buf, &header, sizeof(header));
    memcpy(send_buf + sizeof(header), &length, sizeof(length));
    memcpy(send_buf + sizeof(header) + sizeof(length), &ethno, sizeof(ethno));

    //发送给外网
    ret = sendto(fd, send_buf, sizeof(header) + length, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        PRINT_ERR_HEAD
        print_err("sendto error[%s]", strerror(errno));
        close(fd);
        return false;
    }

    char recvbuf[512] = {0};
    socklen_t addrlen = sizeof(addr);
    ret = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&addr, &addrlen);
    if (ret < 0) {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            printf("get_out_mac timeout!\n");
            PRINT_ERR_HEAD
            print_err("recvfrom timeout");
        } else {
            PRINT_ERR_HEAD
            print_err("recvfrom error[%s]", strerror(errno));
        }
        close(fd);
        return false;
    }
    close(fd);

    //xx:xx:xx:xx:xx:xx   17个字符
    if (ret < (int)sizeof(int) + 17) {
        PRINT_ERR_HEAD
        print_err("recv len error[%d]", ret);
        return false;
    }

    //检验一下
    int backethno = 0;
    char backmac[MAC_STR_LEN] = {0};
    memcpy(&backethno, recvbuf, sizeof(int));
    memcpy(backmac, recvbuf + sizeof(int), 17);

    if (backethno != ethno) {
        PRINT_ERR_HEAD
        print_err("recv ethno error.want[%d] actul[%d]", ethno, backethno);
        return false;
    }

    memcpy(mac, backmac, 17);
    return true;
}

/*
 * if_name like "ath0", "eth0". Notice: call this function
 * need root privilege.
 * return value:
 * -1 -- error , details can check errno
 * 1 -- interface link up
 * 0 -- interface link down.
 */
int get_netcard_status(const char *ethname)
{
    int skfd;

    struct ethtool_value edata;
    edata.cmd = ETHTOOL_GLINK;
    edata.data = 0;

    struct ifreq ifr;
    BZERO(ifr);
    sprintf(ifr.ifr_name, "%s", ethname);
    ifr.ifr_data = (char *) &edata;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

    if (ioctl(skfd, SIOCETHTOOL, &ifr) == -1) {
        PRINT_ERR_HEAD
        print_err("ioctl error[%s]", strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return edata.data;
}

/**
 * [FillAddr 把地址端口信息填充到结构中]
 * @param  ip      [IP]
 * @param  port    [端口]
 * @param  addr    [地址结构]
 * @param  addrlen [长度 出参]
 * @return         [成功返回true]
 */
bool FillAddr(const char *ip, int port, struct sockaddr_storage &addr, int &addrlen)
{
    if (is_ip6addr(ip)) {
        addr.ss_family = AF_INET6;
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&addr;
        addr_v6->sin6_family = AF_INET6;
        addr_v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &(addr_v6->sin6_addr)) <= 0) {
            PRINT_ERR_HEAD
            print_err("inet_pton error[%s] ip[%s]:%d", strerror(errno), ip, port);
            return false;
        }
        addrlen = sizeof(struct sockaddr_in6);
    } else {
        addr.ss_family = AF_INET;
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&addr;
        addr_v4->sin_family = AF_INET;
        addr_v4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &(addr_v4->sin_addr)) <= 0) {
            PRINT_ERR_HEAD
            print_err("inet_pton error[%s] ip[%s]:%d", strerror(errno), ip, port);
            return false;
        }
        addrlen = sizeof(struct sockaddr_in);
    }
    return true;
}

/**
 * [create_and_bind_tcp 创建socket 并绑定到指定的地址和端口]
 * @param  ip   [IP]
 * @param  port [端口]
 * @return      [成功返回大于0 失败返回负值]
 */
int create_and_bind_tcp(const char *ip, const int port)
{
    bool isipv6 = is_ip6addr(ip);
    int addrlen = 0;
    struct sockaddr_storage addr;
    BZERO(addr);

    if (!FillAddr(ip, port, addr, addrlen)) {
        PRINT_ERR_HEAD
        print_err("fill addr error[%s]:%d", ip, port);
        return -1;
    }

    //创建socket
    int fd = socket(isipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket error[%s]", strerror(errno));
        return -1;
    }

    //地址复用
    int opt = 1, yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));
    if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        PRINT_ERR_HEAD
        print_err("bind error[%s] [%s]:%d", strerror(errno), ip, port);
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * [RangeIP 判断是否为范围IP]
 * @param  ip [输入IP]
 * @return    [是返回true]
 */
bool RangeIP(const char *ip)
{
    if (ip == NULL) {
        PRINT_ERR_HEAD
        print_err("para null while judge range ip");
        return false;
    }

    return ALL_OBJ(ip) || IPV6_ALL_OBJ(ip) || (strchr(ip, '-') != NULL);
}

/**
 * [IPInRange 判断IP是否属于范围IP]
 * @param  rangeip [范围IP]
 * @param  absip   [具体IP]
 * @return         [是则返回true]
 */
bool IPInRange(const char *rangeip, const char *absip)
{
    if ((rangeip == NULL) || (absip == NULL)) {
        PRINT_ERR_HEAD
        print_err("para null while judge if in range. rangeip %p, absip %p", rangeip, absip);
        return false;
    }

    //absip必须为具体IP才继续
    if (RangeIP(absip)) { return false; }
    bool isipv6 = is_ip6addr(absip);
    if (isipv6 && IPV6_ALL_OBJ(rangeip)) {return true;}
    if ((!isipv6) && ALL_OBJ(rangeip)) {return true;}

    char tmpip1[IP_STR_LEN] = {0};
    char tmpip2[IP_STR_LEN] = {0};
    const char *p = strchr(rangeip, '-');
    if (p == NULL) {
        return (0 == strcmp(rangeip, absip));
    } else {
        memcpy(tmpip1, rangeip, p - rangeip);
        strcpy(tmpip2, p + 1);
        if (isipv6) {
            ip6range_t tmprange;
            ip6addr_t ipaddr;
            inet_pton(AF_INET6, tmpip1, (void *)&tmprange.ip6l);
            inet_pton(AF_INET6, tmpip2, (void *)&tmprange.ip6h);
            inet_pton(AF_INET6, absip, (void *)&ipaddr);
            return is_inip6r(&ipaddr, &tmprange);
        } else {
            struct in_addr addr1, addr2, addr3;
            inet_pton(AF_INET, tmpip1, (void *)&addr1);
            inet_pton(AF_INET, tmpip2, (void *)&addr2);
            inet_pton(AF_INET, absip, (void *)&addr3);
            unsigned long n1 = ntohl(addr1.s_addr);
            unsigned long n2 = ntohl(addr2.s_addr);
            unsigned long n3 = ntohl(addr3.s_addr);
            return (n3 >= n1 && n3 <= n2);
        }
    }
}

/**
 * [encodekey 对一个关键字进行编码 得到一个确定的字符]
 * @param  str [关键字]
 * @return     [编码后的字符]
 */
unsigned char encodekey(const char *str)
{
    unsigned char c = 0x6F;
    if (str != NULL) {
        int len = strlen(str);
        for (int i = 0; i < len; i++) {
            c = c ^ str[i];
        }
    }
    //printf("%02X\n", c);
    return c;
}
