/*******************************************************************************************
*文件:    syssocket.cpp
*描述:    基础网络通讯TCP&UDP，支持简单数据加密
*
*作者:    张冬波
*日期:    2015-01-12
*修改:    创建文件                            ------>     2015-01-12
*
*         添加专有类，实现文件传输和单向可靠传输
*                                             ------>     2015-01-14
*         TCP&UDP基本调试通过                 ------>     2015-01-22
*         专用类调试通过，但发送需要延时，待优化
*                                             ------>     2015-01-26
*         专用类增加缓冲机制，提高socket接收速度，调试通过
*                                             ------>     2015-02-12
*         调整配置，网络提高到20MB/s，系统消息队列配置为100MB
*         测试时遇到过队列达到70MB的情况，但无法复现，此时读取的队列包命中在
*         缓冲池中需要更新的包，而且传输可能出现了丢包，队列一直阻塞
*                                             ------>     2015-02-26
*         增加消息队列配置                    ------>     2015-03-16
*         修改文件接收，返回文件大小          ------>     2015-03-18
*         添加读取socket属性                  ------>     2015-03-25
*         添加调试信息                        ------>     2015-04-07
*         添加socket阻塞设置                  ------>     2015-04-13
*         添加调试信息&修改gcc兼容问题, 优化队列管理
*                                             ------>     2015-04-17
*         修改文件大小为0的bug, 以及接收文件错误处理
*                                             ------>     2015-05-08
*         添加关闭特定socket接口              ------>     2015-05-20
*         添加socket控制接口                  ------>     2015-05-26
*         删除文件名合法检查                  ------>     2015-06-04
*         修改缓冲区处理，防止假死            ------>     2015-06-17
*         修改超时处理（接收）                ------>     2015-07-02
*         单向传输支持丢包，以及修改文件接口
*                                             ------>     2015-07-27
*         修改bug                             ------>     2015-09-21
*         优化速度，增大发送包                ------>     2015-10-13
*         修改文件传输bug                     ------>     2015-11-13
*         添加获取客户端地址                  ------>     2015-11-19
*         修改版本定义，增加日期属性          ------>     2015-11-24
*         添加获取网卡MAC                     ------>     2015-11-27
*         修改获取网卡MAC的bug，防止用户不创建socket的情况下调用
*                                             ------>     2015-12-02
*         修改调试信息, 以及接口实现          ------>     2015-12-07
*         修改接收处理bug                     ------>     2016-03-03
*         优化网络系统设置                    ------>     2016-09-10
*         修改bug                             ------>     2016-11-07
*         修改获取客户端地址bug               ------>     2016-12-13
*         优化部分函数性能（注：需要重新考虑设计方案以提高最大性能）
*                                             ------>     2016-12-23
*         优化接收端输出日志                  ------>     2017-01-05
*         修改发送延迟处理，允许不加延迟      ------>     2017-01-11
*         文件校验算法配置优化                ------>     2017-02-10
*         优化延时策略                        ------>     2017-02-24
*         增加接收缓冲控制                    ------>     2017-05-02
*         修改接收缓冲控制变量初始化bug       ------>     2017-05-26
*         处理消息队列异常                    ------>     2017-06-22
*         发生消息队列阻塞问题，原因是send函数为阻塞模式，
*         当接收端异常会导致socket的SEND-Q满而阻塞消息处理
*         通过设置默认超时返回发送失败
*                                             ------>     2017-07-10
*         修改内核调优参数，后续通过统一调整/etc/sysctl.conf
*                                             ------>     2017-07-21
*         增加非阻塞模式处理                  ------>     2017-08-07
*         WINDOWS兼容性                       ------>     2017-08-09
*         修改丢包超时处理bug                 ------>     2017-08-11
*         修改非阻塞模式bug                   ------>     2017-08-28
*         修改errno处理方式                   ------>     2017-08-29
*         修改非阻塞模式的deadloop            ------>     2017-09-13
*         修改写writesocket                   ------>     2017-11-23
*         修改CYGWIN超时bug                   ------>     2018-05-24
*         修改listen连接数bug                 ------>     2018-09-14
*         修改超时逻辑                        ------>     2018-09-19
*         添加CPU绑定功能&优化delay处理       ------>     2018-09-27
*         修改文件丢包的处理逻辑，支持断续写入
*                                             ------>     2018-10-11
*         修改读超时逻辑bug                   ------>     2018-11-03
*         添加清除NAT CONTRACK功能            ------>     2018-11-30
*         添加接口获取重复、延时等私有参数       ------>     2019-01-02
*         可以设置线程名称                     ------>     2021-02-23
*******************************************************************************************/
#include "syssocket.h"
#include "debugout.h"
#include "stringex.h"
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>

/*******************************************************************************************
*功能:    构造
*参数:    type                ---->   socket创建类型
*         encode              ---->   true 加密数据
*
*注释:
*******************************************************************************************/
CSYSSOCKET::CSYSSOCKET()
{

    init();
}

CSYSSOCKET::CSYSSOCKET(SOCKETTYPE type, bool encode)
{

    init();
    m_encode = encode;

    if (type > 0) {
        createsocket(type);
    }

}
/*******************************************************************************************
*功能:    拷贝构造函数
*参数:    obj                 ---->   类对象
*
*
*注释:    TCP服务器类型，不包括服务端的socket描述符
*
*******************************************************************************************/
CSYSSOCKET::CSYSSOCKET(const CSYSSOCKET &obj)
{
    PRINT_DBG_HEAD;
    print_dbg("CSYSSOCKET construction");

    m_socket = obj.m_socket;
    m_socketnew = obj.m_socketnew;

    m_type = obj.m_type;
    m_srv = obj.m_srv;
    m_timeout = obj.m_timeout;
    m_encode = obj.m_encode;
    m_datamore = obj.m_datamore;
    m_fcntl = obj.m_fcntl;
    m_errno = 0;

    m_pdata = NULL;
    m_size = 0;

    memcpy(&m_addr, &obj.m_addr, sizeof(m_addr));

    if ((m_type == SOCKET_TCP) && (m_srv == SOCKET_SRV) &&
        (m_socketnew != SOCKET_ERR)) {
        m_socket = SOCKET_ERR;

    }
}

CSYSSOCKET::CSYSSOCKET(SOCKETTYPE type, bool encode, const pchar ip, uint16 port)
{
    init();
    m_encode = encode;

    if (type > 0) {
        createsocket(type);
        setaddress(ip, port);
    }

}

/*******************************************************************************************
*功能:    内部参数初始化
*参数:
*
*注释:    默认连接无超时
*         默认加密传输
*
*******************************************************************************************/
void CSYSSOCKET::init(void)
{
    m_socket = m_socketnew = SOCKET_ERR;
    m_type = m_srv = (SOCKETTYPE)SOCKET_ERR;
    m_timeout = 0;
    m_encode = true;

    m_pdata = NULL;
    m_size = 0;
    m_datamore = false;
    m_fcntl = true;
    m_errno = 0;

    memset(&m_addr, 0, sizeof(m_addr));

}

/*******************************************************************************************
*功能:    析构
*参数:
*
*注释:
*******************************************************************************************/
CSYSSOCKET::~CSYSSOCKET()
{
    closesocket();
    datafree();
}

void CSYSSOCKET::datafree(void)
{
    if ((m_pdata != NULL) && (m_pdata != m_data)) {
        free(m_pdata);
    }

    //在加密和不加密切换会导致数据接收、发送bug
    m_pdata = NULL;

}

/*******************************************************************************************
*功能:    创建SOCKET连接
*参数:    type                ---->   socket创建类型
*         返回值              ---->   socket描述符号，SOCKET_ERR 失败
*
*注释:
*******************************************************************************************/
SYSSOCKET CSYSSOCKET::createsocket(SOCKETTYPE type)
{

    //防止重复调用
    closesocket();

    switch (type) {
    case SOCKET_TCP:
        m_socket = socket(AF_INET, SOCK_STREAM, 0);
        break;
    case SOCKET_UDP:
        m_socket = socket(AF_INET, SOCK_DGRAM , 0);
        break;
    default: return SOCKET_ERR;
    }

    if (m_socket < 0) {
        m_socket = SOCKET_ERR;
        PRINT_ERR_HEAD;
        print_err("socket type = %d", type);
    } else {

        uint opt = 1;
        m_type = type;

        //允许使用待关闭的socket
        if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0) {
            PRINT_ERR_HEAD;
            print_err("setsockopt SO_REUSEADDR failed!");
        }
    }

    return m_socket;
}

/*******************************************************************************************
*功能:    关闭SOCKET连接
*参数:    s                   ---->   用户socket
*         返回值              ---->   SOCKET_OK 成功
*
*注释:
*******************************************************************************************/
#define _CLOSE_(s) {if((s) != SOCKET_ERR) close(s); s = SOCKET_ERR;}
int32 CSYSSOCKET::closesocket(SYSSOCKET &s)
{
    if (s == SOCKET_ERR) {
        _CLOSE_(m_socket);
        _CLOSE_(m_socketnew);
    } else {
        if (m_socketnew == s) {
            _CLOSE_(m_socketnew);
            s = m_socketnew;
        } else if (m_socket == s) {
            _CLOSE_(m_socket);
            s = m_socket;
        } else {
            _CLOSE_(s);
        }

    }

    return SOCKET_OK;
}

int32 CSYSSOCKET::closesocket(void)
{
    SYSSOCKET s = SOCKET_ERR;
    return closesocket(s);
}

/*******************************************************************************************
*功能:    设置socket超时
*参数:    s                   ---->   socket句柄
*         timeout             ---->   单位：秒
*         返回值              ---->   true 成功
*
*注释:    <= 0无超时
*
*******************************************************************************************/
bool CSYSSOCKET::settimeout(int32 timeout)
{
    if (timeout <= 0)
        m_timeout = 0;
    else {
        m_timeout = timeout * 1000;

        /*if (m_srv == SOCKET_CLIENT)*/ {
            struct timeval stimeout = {0, 0};
            stimeout.tv_sec = timeout;
            if (setsockopt(getsocket(), SOL_SOCKET, SO_RCVTIMEO, (char *)&stimeout, sizeof(stimeout)) < 0) {
                PRINT_ERR_HEAD;
                print_err("setsockopt %s", strerror(errno));
            }

            stimeout.tv_sec = 10;    //发送默认超时
            setsockopt(getsocket(), SOL_SOCKET, SO_SNDTIMEO, (char *)&stimeout, sizeof(stimeout));
        }

    }

    PRINT_DBG_HEAD;
    print_dbg("timeout recv = %d", timeout);

    return true;
}

bool CSYSSOCKET::settimeout(SYSSOCKET s, int32 timeout)
{
    if (timeout <= 0) return false;

    struct timeval stimeout = {0, 0};
    stimeout.tv_sec = timeout;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&stimeout, sizeof(stimeout)) < 0) {
        PRINT_ERR_HEAD;
        print_err("setsockopt %s", strerror(errno));
    }

    stimeout.tv_sec = 5;    //发送默认超时
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&stimeout, sizeof(stimeout));

    PRINT_DBG_HEAD;
    print_dbg("timeout recv = %d", timeout);

    return true;
}
/*******************************************************************************************
*功能:    设置socket连接地址
*参数:    ip                  ---->   地址
*         port                ---->   端口
*         返回值              ---->   true 成功
*
*注释:
*
*******************************************************************************************/
bool CSYSSOCKET::setaddress(uint32 ip, uint16 port)
{
    memset(&m_addr, 0, sizeof(m_addr));

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(port);
    m_addr.sin_addr.s_addr = ip;

    return true;
}

bool CSYSSOCKET::setaddress(const pchar ip, uint16 port)
{
    uint32 ip_t;

    if (ipstr2int(ip, &ip_t) < 0)    return false;

    return setaddress(ip_t, port);
}

bool CSYSSOCKET::setaddress(const pchar ip, const pchar port)
{
    if ((ip == NULL) || (port == NULL))  return false;

    return setaddress(ip, atoi(port));
}

/*******************************************************************************************
*功能:    读取当前socket
*参数:    type                ---->   TCP时指定客户端(默认)or服务器
*         返回值              ---->   SOCKET_ERR 失败
*注释:
*
*******************************************************************************************/
const SYSSOCKET CSYSSOCKET::getsocket(SOCKETTYPE type)
{
    if ((m_type == SOCKET_TCP) && (m_srv == SOCKET_SRV)) {

        if (type == SOCKET_SRV) return (const SYSSOCKET)m_socket;
        else return (const SYSSOCKET)m_socketnew;
    }

    return (const SYSSOCKET)m_socket;
}

/*******************************************************************************************
*功能:    读取当前socket连接地址
*参数:    返回值              ---->   false 失败
*
*注释:    setaddress定义地址
*
*******************************************************************************************/
bool CSYSSOCKET::getaddress(struct sockaddr_in *addr)
{
    if (addr == NULL)    return false;

    memcpy(addr, &m_addr, sizeof(struct sockaddr_in));

    return true;
}

/*******************************************************************************************
*功能:    读取当前socket连接地址
*参数:    ip                  ---->   地址
*         port                ---->   端口
*         self                ---->   true本地地址，false对端地址（默认）
*         straddr             ---->   格式化字符，默认NULL
*         返回值              ---->   false 失败
*
*注释:    仅支持TCP客户端连接SOCKET
*
*******************************************************************************************/
bool CSYSSOCKET::getaddress(puint32 ip, puint16 port, bool self, pchar straddr)
{
    if ((ip == NULL) || (port == NULL)) return false;

    SYSSOCKET tmps;
    struct sockaddr addr;
    socklen_t len;
    bool bret = true;

    //区分客户端|服务器
    if (m_srv == SOCKET_SRV)
        if (m_socketnew == SOCKET_ERR) {
            //PRINT_ERR_HEAD;
            //print_err("no client");
            //return false;
            tmps = m_socket;        //支持UDP获取本机地址

        } else tmps = m_socketnew;
    else
        tmps = m_socket;

    memset(&addr, 0, sizeof(addr));

    len = sizeof(addr);
    if (self) bret = (getsockname(tmps, &addr, &len) == 0);
    else bret = (getpeername(tmps, &addr, &len) == 0);

    if (bret) {
        //memcpy(&m_addr, &addr, sizeof(m_addr));

        *ip = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
        *port = ntohs(((struct sockaddr_in *)&addr)->sin_port);

        if (straddr != NULL) {
            ip2str(*ip, straddr);
            sprintf(straddr + strlen(straddr), ":%d", *port);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("getsockname_%d %s", self, strerror(errno));
    }

    return bret;
}

/*******************************************************************************************
*功能:    获取指定网卡MAC
*参数:    netcard             ---->   网卡名
*         mac                 ---->   mac地址
*         macstr              ---->   格式化字符，默认NULL
*         返回值              ---->   false 失败
*
*注释:
*
*******************************************************************************************/
bool CSYSSOCKET::getmac(const pchar netcard, puint64 mac, pchar macstr)
{
    if (is_strempty(netcard) || (mac == NULL)) return false;

    SYSSOCKET tmps;
    tmps = m_socket;
    if (tmps == SOCKET_ERR) {
        //创建临时变量
        tmps = socket(AF_INET, SOCK_STREAM, 0);
    }

    struct ifreq ifr;

    PRINT_DBG_HEAD;
    print_dbg("MAC %s", netcard);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, netcard, IFNAMSIZ);

    //获取mac
    if (ioctl(tmps, SIOCGIFHWADDR, &ifr) == 0 ) {
        char tmp[40] = {0};

#if 0
        memset(mac, 0, sizeof(uint64));
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        mac2str(*mac, tmp);
#else
#define _MACADDR(ifr,i) (uint8)((ifr).ifr_hwaddr.sa_data[i]&0xFF)
        sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", _MACADDR(ifr, 0), _MACADDR(ifr, 1),
                _MACADDR(ifr, 2), _MACADDR(ifr, 3), _MACADDR(ifr, 4), _MACADDR(ifr, 5));

        macstr2long(tmp, mac);
#endif
        if (macstr != NULL) strcpy(macstr, tmp);

        if (tmps != m_socket) close(tmps);

        PRINT_DBG_HEAD;
        print_dbg("MAC %s 0x%llx = %s", netcard, *mac, tmp);

        return true;
    }

    if (tmps != m_socket) close(tmps);

    PRINT_ERR_HEAD;
    print_err("MAC %s %s", netcard, strerror(errno));
    return false;
}


/*******************************************************************************************
*功能:    设置socket服务或者客户端
*参数:    返回值              ---->   false 失败
*
*注释:
*
*******************************************************************************************/
bool CSYSSOCKET::setconnect(SOCKETTYPE type)
{
    if (m_socket == SOCKET_ERR) return false;

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("socket info %s:%d", ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
#endif

    switch (type) {
    case SOCKET_SRV:
        if (m_type == SOCKET_TCP) {

            //TCP 服务器
            if (bind(m_socket, (struct sockaddr *)(&m_addr), sizeof(struct sockaddr)) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP SRV bind failed(%s)!", strerror(errno));
                return false;
            }

            if (listen(m_socket, 10000) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP SRV listen failed(%s)!", strerror(errno));
                return false;
            }
        } else {

            //UDP 服务器
            if (bind(m_socket, (struct sockaddr *)(&m_addr), sizeof(struct sockaddr)) < 0) {
                PRINT_ERR_HEAD;
                print_err("UDP SRV bind failed(%s)!", strerror(errno));
                return false;
            }
        }
        break;
    case SOCKET_CLIENT:
        if (m_type == SOCKET_TCP) {
            //TCP 客户端
            // struct linger so_linger;
            // so_linger.l_onoff = 1;
            // so_linger.l_linger = 5;    //单位S
            // setsockopt(m_socket, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));

            if (connect(m_socket, (struct sockaddr *)(&m_addr), sizeof(struct sockaddr)) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP CLIENT connect failed(%s)!", strerror(errno));
                return false;
            }
        } else {
            //UDP 客户端
        }
        break;
    default: return false;
    }

    m_srv = type;

    PRINT_DBG_HEAD;
    print_dbg("connect_%d|%d, socket = %d success!", m_type, m_srv, m_socket);

    return true;
}

/*******************************************************************************************
*功能:    获取socket服务连接
*参数:    返回值              ---->   true 成功
*
*注释:    仅支持面向连接的TCP
*
*******************************************************************************************/
bool CSYSSOCKET::getconnect(void)
{
    if (m_socket == SOCKET_ERR) return false;

    if ((m_type == SOCKET_TCP) && (m_srv == SOCKET_SRV)) {

        PRINT_INFO_HEAD;
        print_info("accept block...");

        struct sockaddr_in tmp;
        socklen_t i =  sizeof(tmp);

        m_socketnew = SOCKET_ERR;
        memcpy(&tmp, &m_addr, i);
        if ((m_socketnew = accept(m_socket, (struct sockaddr *)(&tmp), &i)) < 0) {
            PRINT_ERR_HEAD;
            print_err("TCP SRV accept failed! socket = %d, addr = %s:%d, error = %d(%s)",
                      m_socket, ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port), errno, strerror(errno));

            m_socketnew = SOCKET_ERR;
        } else {
            // struct linger so_linger;
            // so_linger.l_onoff = 1;
            // so_linger.l_linger = 5;    //单位S
            // setsockopt(m_socketnew, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
        }

        PRINT_INFO_HEAD;
        print_info("accept unblock...");

    }

    return (m_socketnew != SOCKET_ERR);
}

bool CSYSSOCKET::getconnect(int32 timeout)
{
    settimeout(timeout);

    return getconnect();
}

/*******************************************************************************************
*功能:    关闭socket服务连接
*参数:    返回值              ---->   true 成功
*
*注释:    关闭客户端
*
*******************************************************************************************/
bool CSYSSOCKET::closeconnect(void)
{
    if ((m_type == SOCKET_TCP) && (m_srv == SOCKET_SRV)) {
        _CLOSE_(m_socketnew);
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    加密设置
*参数:
*
*注释:
*
*******************************************************************************************/
void CSYSSOCKET::setencode(bool disable)
{
    m_encode = !disable;
    datafree(); //bug 2018-08-12
}

/*******************************************************************************************
*功能:    发送数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际发送量, -1 失败
*
*注释:
*
*******************************************************************************************/
int32 CSYSSOCKET::writesocket(const void *data, const int32 size)
{
    m_errno = 0;
    if ((data == NULL) || (size <= 0))   return -1;

    SYSSOCKET socket_w = getsocket();
    if (socket_w == SOCKET_ERR) return -1;

    bool bwrite = true;
    int32 writelen = -1, size_en = size;
    int32 writeoffset = 0;

    //加密数据
    if (m_encode) {
        m_pdata = m_data;
        if ((size_en = dataencode_size(size)) > (int32)sizeof(m_data)) {
            m_pdata = (puint8)malloc(size_en);
            if (m_pdata == NULL) {
                PRINT_ERR_HEAD;
                print_err("malloc %d failed!", size_en);
                return -1;
            }

        }
        size_en = dataencode((const puint8)data, size, m_pdata);
        if (size_en == -1) bwrite = false;
    }

    //开始发送
    int32 errorcnt_w = 5; //防止重试写deadloop
    if (bwrite) {
_sendagain:
        writelen = 0;
        switch (m_type) {
        case SOCKET_TCP:
            writelen = send(socket_w, ((m_pdata != NULL) ? m_pdata + writeoffset : ((const puint8)data) + writeoffset),
                            size_en - writeoffset, 0);
            break;
        case SOCKET_UDP:
            writelen = sendto(socket_w, ((m_pdata != NULL) ? m_pdata + writeoffset : ((const puint8)data) + writeoffset),
                              size_en - writeoffset, 0, (struct sockaddr *)&m_addr, sizeof(struct sockaddr));
            break;
        default:
            break;
        }

        if (writelen == -1) {
            m_errno = errno;

            PRINT_DBG_HEAD;
            print_dbg("write size %d -> %d, (%d:%s), retry = %d", size_en - writeoffset, writelen, m_errno, strerror(m_errno), errorcnt_w);
            if ((m_errno == ENOBUFS) || (m_errno == ENOMEM) || (m_errno == EINTR) ||
                (m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                usleep(1000);
                if (--errorcnt_w > 0) goto _sendagain;
            }

            PRINT_ERR_HEAD;
            print_err("write size %d -> %d, (%d:%s), retry = %d", size_en, writeoffset, m_errno, strerror(m_errno), errorcnt_w);

        } else if (writelen != (size_en - writeoffset)) {
            m_errno = 0;
            PRINT_DBG_HEAD;
            print_dbg("write size %d -> %d, (%d:%s), retry = %d", size_en - writeoffset, writelen, m_errno, strerror(m_errno), errorcnt_w);
            if (writelen > 0) writeoffset += writelen;

            usleep(1);
            if (--errorcnt_w > 0) goto _sendagain;

            PRINT_ERR_HEAD;
            print_err("write size %d -> %d, (%d:%s), retry = %d", size_en, writeoffset, m_errno, strerror(m_errno), errorcnt_w);

        } else {
            writeoffset = size_en;
        }
    }


    datafree();

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("write size %d -> %d(%s)", size, writeoffset, printbuf(data, size));
#endif

    if ((writelen < 0) && (writeoffset == 0)) writeoffset = -1;
    return writeoffset;
}

/*******************************************************************************************
*功能:    读取数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际读取量, -1 失败
*
*注释:
*
*******************************************************************************************/
#ifndef __CYGWIN__
int32 CSYSSOCKET::readsocket(void *data, const int32 size)
{
    m_errno = 0;
    if ((data == NULL) || (size <= 0))    return -1;

    SYSSOCKET socket_r = getsocket();
    if (socket_r == SOCKET_ERR) return -1;

    int32 readlen = -1, size_en = size;

    //memset(data, 0, size);

    //加密数据长度
    if (m_encode) {
        m_pdata = m_data;
        if ((size_en = dataencode_size(size)) > (int32)sizeof(m_data)) {
            m_pdata = (puint8)malloc(size_en);
            if (m_pdata == NULL) {
                PRINT_ERR_HEAD;
                print_err("malloc %d failed!", size_en);
                return -1;
            }
        }

        //memset(m_pdata, 0, size_en);
    }

    //开始接收
_recvagain:
    if (size_en > 0) {
        switch (m_type) {
        case SOCKET_TCP:
            readlen = recv(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en, 0);
            if (readlen == 0) {
                PRINT_DBG_HEAD;
                print_dbg("socket = %d closed, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                readlen = -1;
            } else if (readlen < 0) {
                m_errno = errno;
                if ((m_errno == EINTR)/* || (errno == EAGAIN)*/) goto _recvagain;
                if (m_fcntl) {
                    PRINT_ERR_HEAD;
                    print_err("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              m_errno, strerror(m_errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                } else {
#if __DEBUG_MORE__
                    PRINT_DBG_HEAD;
                    print_dbg("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              m_errno, strerror(m_errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
#endif
                    if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                        //非阻塞模式
#if __DEBUG_MORE__
                        PRINT_ERR_HEAD;
                        print_err("read unblock");
#endif
                        m_errno = ESUSOCKET2;

                    }
                }
            } else if (m_datamore) {

                //尽量一次多收数据
                int32 testlen = readlen;
                PRINT_DBG_HEAD;
                print_dbg("more socket = %d, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));

                while (testlen < size_en) {
                    int32 i = recv(socket_r, ((m_pdata != NULL) ? m_pdata + testlen : (puint8)data + testlen), size_en - testlen, 0);

                    if (i == 0) {
                        PRINT_DBG_HEAD;
                        print_dbg("more socket = %d closed, addr = %s:%d", socket_r,
                                  ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else if (i < 0) {
                        m_errno = errno;
                        PRINT_ERR_HEAD;
                        print_err("more socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                                  m_errno, strerror(m_errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else {
                        testlen += i;
                    }

                }

                readlen = testlen;
            }

            break;
        case SOCKET_UDP: {
            socklen_t i = sizeof(m_addr);

            readlen = recvfrom(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en, 0,
                               (struct sockaddr *)&m_addr, &i);
            if (readlen == 0) {
                PRINT_DBG_HEAD;
                print_dbg("socket = %d closed, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                readlen = -1;
            } else if (readlen < 0) {
                m_errno = errno;
                if (errno == EINTR) goto _recvagain;
                if (m_fcntl) {
                    PRINT_ERR_HEAD;
                    print_err("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                } else {
#if __DEBUG_MORE__
                    PRINT_DBG_HEAD;
                    print_dbg("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
#endif
                    if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                        //非阻塞模式
#if __DEBUG_MORE__
                        PRINT_ERR_HEAD;
                        print_err("read unblock");
#endif
                        m_errno = ESUSOCKET2;
                    }
                }

            } else if (m_datamore) {

                //尽量一次多收数据
                int32 testlen = readlen;
                PRINT_DBG_HEAD;
                print_dbg("more socket = %d, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));

                while (testlen < size_en) {
                    int32 j = recvfrom(socket_r, ((m_pdata != NULL) ? m_pdata + testlen : (puint8)data + testlen), size_en - testlen, 0,
                                       (struct sockaddr *)&m_addr, &i);

                    if (j == 0) {
                        PRINT_DBG_HEAD;
                        print_dbg("more socket = %d closed, addr = %s:%d", socket_r,
                                  ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else if (j < 0) {
                        PRINT_ERR_HEAD;
                        print_err("more socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                                  errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else {
                        testlen += j;
                    }

                }

                readlen = testlen;
            }
            break;
        }
        default:
            break;
        }

        //PRINT_DBG_HEAD;
        //print_dbg("read size %d -> %d", size_en, readlen);
    }


    //解密数据
    if (m_encode && (readlen > 0)) {

        readlen = dataencode(m_pdata, readlen, (puint8)data, true);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("read size %d -> %d(%s)", size_en, readlen, printbuf(data, readlen));
#endif
    }

    datafree();

    return readlen;
}
#else
//超时问题，通过select处理
int32 CSYSSOCKET::readsocket(void *data, const int32 size)
{
    m_errno = 0;
    if ((data == NULL) || (size <= 0))    return -1;

    SYSSOCKET socket_r = getsocket();
    if (socket_r == SOCKET_ERR) return -1;

    int32 readlen = -1, size_en = size;

    //memset(data, 0, size);

    //加密数据长度
    if (m_encode) {
        m_pdata = m_data;
        if ((size_en = dataencode_size(size)) > (int32)sizeof(m_data)) {
            m_pdata = (puint8)malloc(size_en);
            if (m_pdata == NULL) {
                PRINT_ERR_HEAD;
                print_err("malloc %d failed!", size_en);
                return -1;
            }
        }

        //memset(m_pdata, 0, size_en);
    }

    //开始接收
_recvagain:
    if (size_en > 0) {
        switch (m_type) {
        case SOCKET_TCP:
            if (m_timeout != 0) {

_intragain:
                struct timeval tmOut;
                int32 test = 0;
                fd_set fds;
                tmOut.tv_sec = m_timeout / 1000;
                tmOut.tv_usec = 0;
                FD_ZERO(&fds);
                FD_SET(socket_r, &fds);

                if ((test = select(socket_r + 1, &fds, NULL, NULL, &tmOut)) < 0) {
                    m_errno = errno;
                    if (errno == EINTR) goto _intragain;
                    PRINT_ERR_HEAD;
                    print_err("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                    break;
                } else if (test == 0) {
                    PRINT_DBG_HEAD;
                    print_dbg("socket = %d timeout, addr = %s:%d", socket_r,
                              ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                    break;
                }

                if (!FD_ISSET(socket_r, &fds)) {
                    PRINT_ERR_HEAD;
                    print_err("socket = %d timeout, addr = %s:%d", socket_r,
                              ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                    break;
                }
            }

            readlen = recv(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en, 0);
            if (readlen == 0) {
                PRINT_DBG_HEAD;
                print_dbg("socket = %d closed, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                readlen = -1;
            } else if (readlen < 0) {
                m_errno = errno;
                if ((m_errno == EINTR) /*|| (errno == EAGAIN)*/) goto _recvagain;
                if (m_fcntl) {
                    PRINT_ERR_HEAD;
                    print_err("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                } else {
#if __DEBUG_MORE__
                    PRINT_DBG_HEAD;
                    print_dbg("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
#endif
                    if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                        //非阻塞模式
#if __DEBUG_MORE__
                        PRINT_ERR_HEAD;
                        print_err("read unblock");
#endif
                        m_errno = ESUSOCKET2;
                    }
                }

            } else if (m_datamore) {

                //尽量一次多收数据
                int32 testlen = readlen;
                PRINT_DBG_HEAD;
                print_dbg("more socket = %d, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));

                while (testlen < size_en) {
                    int32 i = recv(socket_r, ((m_pdata != NULL) ? m_pdata + testlen : (puint8)data + testlen), size_en - testlen, 0);

                    if (i == 0) {
                        PRINT_DBG_HEAD;
                        print_dbg("more socket = %d closed, addr = %s:%d", socket_r,
                                  ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else if (i < 0) {
                        PRINT_ERR_HEAD;
                        print_err("more socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                                  errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else {
                        testlen += i;
                    }

                }

                readlen = testlen;
            }

            break;
        case SOCKET_UDP: {
            socklen_t i = sizeof(m_addr);

            readlen = recvfrom(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en, 0,
                               (struct sockaddr *)&m_addr, &i);
            if (readlen == 0) {
                PRINT_DBG_HEAD;
                print_dbg("socket = %d closed, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                readlen = -1;
            } else if (readlen < 0) {
                m_errno = errno;
                if (errno == EINTR) goto _recvagain;
                if (m_fcntl) {
                    PRINT_ERR_HEAD;
                    print_err("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                } else {
#if __DEBUG_MORE__
                    PRINT_DBG_HEAD;
                    print_dbg("socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                              errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
#endif
                    if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                        //非阻塞模式
#if __DEBUG_MORE__
                        PRINT_ERR_HEAD;
                        print_err("read unblock");
#endif
                        m_errno = ESUSOCKET2;
                    }
                }
            } else if (m_datamore) {

                //尽量一次多收数据
                int32 testlen = readlen;
                PRINT_DBG_HEAD;
                print_dbg("more socket = %d, addr = %s:%d", socket_r,
                          ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));

                while (testlen < size_en) {
                    int32 j = recvfrom(socket_r, ((m_pdata != NULL) ? m_pdata + testlen : (puint8)data + testlen), size_en - testlen, 0,
                                       (struct sockaddr *)&m_addr, &i);

                    if (j == 0) {
                        PRINT_DBG_HEAD;
                        print_dbg("more socket = %d closed, addr = %s:%d", socket_r,
                                  ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else if (j < 0) {
                        PRINT_ERR_HEAD;
                        print_err("more socket = %d unknown = %d(%s), addr = %s:%d", socket_r,
                                  errno, strerror(errno), ip2str(m_addr.sin_addr.s_addr), ntohs(m_addr.sin_port));
                        break;
                    } else {
                        testlen += j;
                    }

                }

                readlen = testlen;
            }
            break;
        }
        default:
            break;
        }

        //PRINT_DBG_HEAD;
        //print_dbg("read size %d -> %d", size_en, readlen);
    }


    //解密数据
    if (m_encode && (readlen > 0)) {

        readlen = dataencode(m_pdata, readlen, (puint8)data, true);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("read size %d -> %d(%s)", size_en, readlen, printbuf(data, readlen));
#endif
    }

    datafree();

    return readlen;
}
#endif

/*******************************************************************************************
*功能:    数据加密
*参数:    src                   ---->    源数据
*         len                   ---->    源数据长度
*         dst                   ---->    目的数据
*         decode                ---->    true 解密
*         返回值                ---->    处理后的数据长度， -1 失败
*
*注释:
*
*******************************************************************************************/
#define _dataprocess_(s, d, n, k) { \
    for (int32 i = 0; i < (n); i++) { \
        d[i] = (s[i]) ^ (k); \
    }   \
}

int32 CSYSSOCKET::dataencode(const puint8 src, int32 len, puint8 dst, bool decode)
{
    if ((src == NULL) || (len <= 0) || (dst == NULL)) return -1;
    const uint8 enkey = 0x87;

    //对齐处理, 优化性能
#define _ALIGN_BYTES_   (4)
    if ((((ptr_t)src & (_ALIGN_BYTES_ - 1)) == 0) && (((ptr_t)dst & (_ALIGN_BYTES_ - 1)) == 0)) {
        const uint32 enkeyalign = 0x87878787;

        puint32 _src, _dst;
        puint8 _srctail, _dsttail;
        int32 _len = len / _ALIGN_BYTES_;
        _src = (puint32)src;
        _dst = (puint32)dst;

        if (decode) {
            _dataprocess_(_src, _dst, _len, enkeyalign);
        } else {
            _dataprocess_(_src, _dst, _len, enkeyalign);
        }

        if ((len & (_ALIGN_BYTES_ - 1)) != 0) {
            _srctail = src + (_len * _ALIGN_BYTES_);
            _dsttail = dst + (_len * _ALIGN_BYTES_);
            if (decode) {
                _dataprocess_(_srctail, _dsttail, len & (_ALIGN_BYTES_ - 1), enkey);
            } else {
                _dataprocess_(_srctail, _dsttail, len & (_ALIGN_BYTES_ - 1), enkey);
            }
        }

        return len;
    }

    if (decode) {
        _dataprocess_(src, dst, len, enkey);
    } else {
        _dataprocess_(src, dst, len, enkey);
    }

    return len;
}

/*******************************************************************************************
*功能:    计算数据加密or解密后长度
*参数:    len                   ---->    源数据长度
*         返回值                ---->    处理后的数据长度， -1 失败
*
*注释:
*
*******************************************************************************************/
int32 CSYSSOCKET::dataencode_size(const int32 len, bool decode)
{
    if (len < 0) return -1;

    return len;
}


/*******************************************************************************************
*功能:    读取socket属性
*参数:    返回值                ---->    高字为服务类型，低字为连接类型
*
*注释:
*
*******************************************************************************************/
uint32 CSYSSOCKET::gettype(void)
{
    return MAKEDWORD(m_srv, m_type);
}

/*******************************************************************************************
*功能:    设置阻塞方式
*参数:    enable                ---->    true 阻塞，默认方式
*
*注释:
*
*******************************************************************************************/
void CSYSSOCKET::setblock(bool enable)
{
    int flags;
    SYSSOCKET s = getsocket();

    flags = fcntl(s, F_GETFL, 0);
    flags = enable ? (flags & (~O_NONBLOCK)) : (flags | O_NONBLOCK);
    fcntl(s, F_SETFL, flags);
    m_fcntl = enable;
}

/*******************************************************************************************
*功能:    设置延时发送
*参数:    enable                ---->    true 延时，默认方式
*
*注释:    初始无效
*
*******************************************************************************************/
void CSYSSOCKET::setnodelay(bool enable)
{
    int on = enable ? 1 : 0;

    setsockopt(getsocket(), IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
}

/*******************************************************************************************
*功能:    控制接收函数连续接收，直到超时或者用户缓冲区满
*参数:    enable                ---->    false 默认方式
*
*注释:    初始无效
*
*******************************************************************************************/
void CSYSSOCKET::setdatamore(bool enable)
{
    m_datamore = enable;
}

/*******************************************************************************************
*功能:    获取自定义errno
*参数:
*
*注释:
*
*******************************************************************************************/
int32 CSYSSOCKET::geterrno(void)
{
    return m_errno;
}


/*******************************************************************************************
*功能:    清除NAT的连接记录
*参数:
*
*注释:   网络代码，详情涉及NETLINK的内核态与用户态的交互通讯
*
*******************************************************************************************/
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
bool CSYSSOCKET::clear_contrack(void)
{
    SYSSOCKET fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) {
        PRINT_ERR_HEAD;
        print_err("NL CLEAR %d(%s)", errno, strerror(errno));
        return false;
    }

    struct nlmsghdr nlh;
    struct sockaddr_nl nladdr;
    struct iovec iov = { &nlh, nlh.nlmsg_len };
    struct msghdr msg = { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

    memset(&nladdr, 0, sizeof(nladdr));
    nlh.nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
    nladdr.nl_family = AF_NETLINK;
    nlh.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
    nlh.nlmsg_flags |= NLM_F_REQUEST;

    if (sendmsg(fd, &msg, 0) < 0) {
        PRINT_ERR_HEAD;
        print_err("NL CLEAR %d(%s)", errno, strerror(errno));
        return false;

    }

    PRINT_DBG_HEAD;
    print_dbg("NL CLEAR DONE");
    return true;
}







/*******************************************************************************************
 *
 *                              专有类实现
 *
*******************************************************************************************/
#include "filename.h"
#include "md5.h"
#include <sys/stat.h>

//丢包超时处理
#define DATA_TIMEOUT    20

//模块版本
const pchar CSUSOCKET::version = "2.0.1_"__DATE__" "__TIME__;

//消息队列配置，单位:B
const uint32 CSUSOCKET::msgmnb = 209715200;     //200MB
const uint32 CSUSOCKET::msgmax = 32768;

#if (_SSLIB_ == IPV6_TAG)
/*******************************************************************************************
*功能:    构造
*参数:    ip                    ---->   地址
*         port                  ---->   端口
*         srv_client            ---->   连接类型
*         tcp_udp               ---->   连接类型
*
*注释:
*******************************************************************************************/
CSUSOCKET::CSUSOCKET(): CSYSSOCKET6()
{
    init();
}

CSUSOCKET::CSUSOCKET(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp): CSYSSOCKET6()
{
    init();
    suopen(ip, port, srv_client, tcp_udp);
}

/*******************************************************************************************
*功能:    拷贝构造
*参数:    obj                 ---->   类对象
*
*注释:
*******************************************************************************************/
CSUSOCKET::CSUSOCKET(CSUSOCKET &obj): CSYSSOCKET6(obj)
{
    PRINT_DBG_HEAD;
    print_dbg("CSUSOCKET construction");

    init();
}
#else
/*******************************************************************************************
*功能:    构造
*参数:    ip                    ---->   地址
*         port                  ---->   端口
*         srv_client            ---->   连接类型
*         tcp_udp               ---->   连接类型
*
*注释:
*******************************************************************************************/
CSUSOCKET::CSUSOCKET(): CSYSSOCKET()
{
    init();
}

CSUSOCKET::CSUSOCKET(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp): CSYSSOCKET()
{
    init();
    suopen(ip, port, srv_client, tcp_udp);
}

/*******************************************************************************************
*功能:    拷贝构造
*参数:    obj                 ---->   类对象
*
*注释:
*******************************************************************************************/
CSUSOCKET::CSUSOCKET(CSUSOCKET &obj): CSYSSOCKET(obj)
{
    PRINT_DBG_HEAD;
    print_dbg("CSUSOCKET construction");

    init();
}
#endif

/*******************************************************************************************
*功能:    析构
*参数:
*
*注释:
*******************************************************************************************/
CSUSOCKET::~CSUSOCKET()
{
    suclose();

    //缓冲特殊处理，线程同步
    suend();
    suendq();
}

/*******************************************************************************************
*功能:    初始化成员变量
*参数:
*
*注释:
*******************************************************************************************/
void CSUSOCKET::init(void)
{
    memset(m_filebuf, 0, sizeof(m_filebuf));
    m_repeat = 3;           //发送重复次数
    m_delayus = 1;
    m_filechk = FILECHK_ALL;
    m_totalp = 0ULL;

    srand((uint)time(NULL));

    initq();

    PRINT_DBG_HEAD;
    print_dbg("initialize set = %d, %d, %d", m_repeat, m_delayus, m_filechk);

}

#if (_SSLIB_ == IPV6_TAG)
/*******************************************************************************************
*功能:    打开socket连接
*参数:    ip                    ---->   地址
*         port                  ---->   端口
*         srv_client            ---->   连接类型
*         tcp_udp               ---->   连接类型
*
*注释:
*******************************************************************************************/
bool CSUSOCKET::suopen(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp)
{
    bool bret = false;
    if (createsocket(tcp_udp, is_ip6addr(ip) ? IPV6_TAG : IPV4_TAG) != SOCKET_ERR) {

        setencode();
        bret = setaddress(ip, port);

        bret &= setconnect(srv_client);
    }

    return bret;
}

bool CSUSOCKET::suopen(uint32 ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp)
{
    bool bret = false;
    if (createsocket(tcp_udp, IPV4_TAG) != SOCKET_ERR) {
        char ipstr[SSADDR_MAX] = {0};
        setencode();

        bret = setaddress(ip2str(ip, ipstr), port);

        bret &= setconnect(srv_client);
    }

    return bret;
}
#else
/*******************************************************************************************
*功能:    打开socket连接
*参数:    ip                    ---->   地址
*         port                  ---->   端口
*         srv_client            ---->   连接类型
*         tcp_udp               ---->   连接类型
*
*注释:
*******************************************************************************************/
bool CSUSOCKET::suopen(const pchar ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp)
{
    bool bret = false;
    if (createsocket(tcp_udp) != SOCKET_ERR) {

        setencode();
        bret = setaddress(ip, port);

        bret &= setconnect(srv_client);
    }

    return bret;
}

bool CSUSOCKET::suopen(uint32 ip, uint16 port, SOCKETTYPE srv_client, SOCKETTYPE tcp_udp)
{
    bool bret = false;
    if (createsocket(tcp_udp) != SOCKET_ERR) {

        setencode();
        bret = setaddress(ip, port);

        bret &= setconnect(srv_client);
    }

    return bret;
}
#endif

/*******************************************************************************************
*功能:    关闭socket连接
*参数:
*
*注释:
*******************************************************************************************/
bool CSUSOCKET::suclose(void)
{
    return (closesocket() == SOCKET_OK);
}

//文件通讯关键字
static const pchar  _RET_FILE_OK = "okrs";
static const pchar  _RET_FILE_ERR = "falsers";
static const pchar  _RET_FILE_END = "recv_finish";
static const pchar  _SYN_FILE_KEY = "|=";
#define _RETLEN_(r) (strlen(r)+1)

/*******************************************************************************************
*功能:    发送文件
*参数:    fpath                    ---->    文件名路径
*
*注释:
*******************************************************************************************/
bool CSUSOCKET::sendfile(const pchar fpath)
{
    if (!is_file(fpath)) return false;

    FILE *fop = fopen(fpath, "rb");
    bool bret = false;

    if (fop != NULL) {

        int32 s = 0;
        bret = true;

        //发送文件大小, 包括结束符‘\0’
        struct stat filestat;

        memset(&filestat, 0, sizeof(filestat));
        stat(fpath, &filestat);
        sprintf((pchar)m_filebuf, "%s%s%llu", fpath, _SYN_FILE_KEY, filestat.st_size);

        if (writesocket(m_filebuf, strlen((const pchar)m_filebuf) + 1) !=
            (int32)(strlen((const pchar)m_filebuf) + 1)) {
            PRINT_ERR_HEAD;
            print_err("send file %s", (const pchar)m_filebuf);
            bret = false;
        }

        bret = false;
        if (readsocket(m_filebuf, sizeof(m_filebuf)) > 0) {
            bret = (strcmp((const pchar)m_filebuf, _RET_FILE_OK) == 0);
        }

        //发送文件
        while (bret && ((s = fread(m_filebuf, 1, sizeof(m_filebuf), fop)) > 0)) {
            if (writesocket(m_filebuf, s) != s) {
                PRINT_ERR_HEAD;
                print_err("send size = %d", s);
                bret = false;
            }

        }

        fclose(fop);

        //判断结束标志
        if (bret) {
            PRINT_DBG_HEAD;
            print_dbg("send file %s success", fpath);
        }

        bret = false;
        if (readsocket(m_filebuf, sizeof(m_filebuf)) > 0) {
            if (strcmp((const pchar)m_filebuf, _RET_FILE_END) == 0) {
                PRINT_DBG_HEAD;
                print_dbg("send file back %s success", fpath);
                bret = true;
            }
        }

        if (!bret) {
            PRINT_DBG_HEAD;
            print_dbg("send file back %s failed", fpath);
        }
    }

    return bret;
}


/*******************************************************************************************
*功能:    接收文件
*参数:    fpath                    ---->    文件名路径
*
*注释:
*******************************************************************************************/
bool CSUSOCKET::recvfile(const pchar fpath)
{
    //if (!is_filepathvalid(fpath))    return false;

    FILE *fop = fopen(fpath, "wb");
    bool bret = false;

    if (fop != NULL) {

        uint64 filesize = 0;
        int32 i;

        //接收文件大小
        if (readsocket(m_filebuf, sizeof(m_filebuf)) > 0) {
            pchar p = strstr((pchar)m_filebuf, _SYN_FILE_KEY);
            if (p != NULL) {
                bret = str2long(p + 2, &filesize);
            }
        }

        PRINT_DBG_HEAD;
        print_dbg("recv file size = %llu", filesize);

        if (bret) {
            i = writesocket(_RET_FILE_OK, _RETLEN_(_RET_FILE_OK));
            bret = (i == _RETLEN_(_RET_FILE_OK));
        } else {
            i = writesocket(_RET_FILE_ERR, _RETLEN_(_RET_FILE_ERR));
            bret = (i == _RETLEN_(_RET_FILE_ERR));
        }

        //接收文件
        if (bret) {
            uint64 readcnt = 0;
            int32 i;

            while (bret && ((i = readsocket(m_filebuf, sizeof(m_filebuf))) > 0)) {
                readcnt += i;
                if ((int32)fwrite(m_filebuf, 1, i, fop) != i) {
                    PRINT_ERR_HEAD;
                    print_err("recv size = %d", i);
                    bret = false;
                }

                if (readcnt >= filesize)  break;
            }

            if (readcnt != filesize) {
                bret = false;
                PRINT_ERR_HEAD;
                print_err("recv file = %llu", readcnt);
            }
        }

        fclose(fop);

        //接收完成
        if (bret) {
            writesocket(_RET_FILE_END, _RETLEN_(_RET_FILE_END));
            PRINT_DBG_HEAD;
            print_dbg("recv file %s success", fpath);
        } else {
            writesocket(_RET_FILE_ERR, _RETLEN_(_RET_FILE_ERR));
            PRINT_DBG_HEAD;
            print_dbg("recv file %s failed", fpath);
            remove(fpath);
        }
    }

    return bret;
}


//单向通讯配置
#include <time.h>        //随机数使用
#include <sys/time.h>
#include "msgcfg.h"

//非对齐赋值
inline static void _setint(uint8 data[3], int32 i)
{
    //little ending
    data[0] = (uint8)(i & 0xFF);
    data[1] = (uint8)((i >> 8) & 0xFF);
    data[2] = (uint8)((i >> 16) & 0xFF);
}

inline static void _setint(void *data, int32 i, uint8 size)
{
    memcpy(data, &i, size);
}

//内部包格式处理
static bool init_packet(PUNI_PACKET packet, int32 size, uint32 uniq);
static int32 init_packet(PUNI_PACKET packet, const puint8 user, int32 size, int32 &pos, puint8 dst, const int32 dstsize);
static bool update_packet(puint8 packet, int32 size);
static bool check_packet(puint8 packet, int32 size, PUNI_PACKET s_packet = NULL);
static bool check_packet1(puint8 packet, int32 size, PUNI_PACKET s_packet = NULL);
static bool checkmd5_packet(puint8 packet, int32 size, PUNI_PACKET s_packet = NULL);
bool checkmd5_packet1(puint8 packet, int32 size, PUNI_PACKET s_packet = NULL);

/*******************************************************************************************
*功能:    设置属性
*参数:    key                   ---->    属性
*         data                  ---->    数值
*
*注释:
*
*******************************************************************************************/
bool CSUSOCKET::susetopt(uint8 key, const void *data)
{
    if (data == NULL)    return false;

    switch (key) {
    case K_OPTRPT: {
        uint8 tmp = 0;
        memcpy(&tmp, data, sizeof(tmp));
        if (tmp == 0)    return false;

        m_repeat = tmp;
    }
    break;
    case K_OPTDLY: {
        int32 tmp = 0;
        memcpy(&tmp, data, sizeof(tmp));
        if (tmp < 0)    return false;

        m_delayus = tmp;
    }
    break;
    case K_OPTCHK: {
        memcpy(&m_filechk, data, sizeof(m_filechk));
    }
    break;
    default:
        return false;
    }

    PRINT_DBG_HEAD;
    print_dbg("option set = %d, %d, %d", m_repeat, m_delayus, m_filechk);

    return true;
}

/*******************************************************************************************
*功能:    发送数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际发送量, -1 失败
*
*注释:   单向数据传输，采用MD5校验+冗余发送
*
*******************************************************************************************/
//#define _writedly_(d) {if(d&0xFFFF) usleep(d&0xFFFF);}
inline static void _writedly_(int32 delayus)
{
    delayus &= 0xFFFF;
    if (delayus != 0) {
        struct timeval t1, t2;
        gettimeofday (&t1, NULL);
        do {
            gettimeofday (&t2, NULL);
        } while (((t2.tv_sec - t1.tv_sec) * 1000000 + t2.tv_usec - t1.tv_usec) < delayus);
    }
}

int32 CSUSOCKET::suwrite(const void *data, int32 size)
{
    if ((data == NULL) && (size <= 0))  return -1;

    if ((getsocket() != SOCKET_ERR) && (m_type == SOCKET_UDP)) {

        uint8 packet[_UNI_PACKETSIZE];
        UNI_PACKET s_packet;
        int32 datapos = 0;

        init_packet(&s_packet, size, m_wrUNIQ);

        //开始发送
        do {
            int32 sendsize = 0;
            bool berr = true;
            int32 tmp = datapos;

            sendsize = init_packet(&s_packet, (const puint8)data, size, datapos, packet, sizeof(packet));

            //延时策略开关
            if ((m_delayus & 0x10000) == 0) {
                for (uint8 i = 0; i < m_repeat; i++) {
                    if ((i & 1) == 1)   _writedly_(m_delayus);       //测试用
                    berr &= (writesocket(packet, sendsize) != sendsize);
                    m_totalp++;
                }
                _writedly_(m_delayus);        //测试用

                PRINT_DBG_HEAD;
                print_dbg("DELAY1 %d", m_delayus & 0xFFFF);
            } else {

                //基于发送包总数的延时处理
                for (uint8 i = 0; i < m_repeat; i++) {
                    berr &= (writesocket(packet, sendsize) != sendsize);
                    m_totalp++;
                }

                if ((m_totalp % (100 / m_repeat * m_repeat)) == 0) _writedly_(m_delayus);   //测试用

                PRINT_DBG_HEAD;
                print_dbg("DELAY2 %d", m_delayus & 0xFFFF);
            }

            //防止溢出错误
            if (m_totalp > 0x3FFFFFFFFFFFFFFFULL) {
                PRINT_DBG_HEAD;
                print_dbg("total packets size = %llu", m_totalp);
                m_totalp = 0ULL;
            }

            if (berr) {
                //系统有漏洞：区分完全未发出和部分发出（特别是头结构正确）情况

                /**
                 * zdb 2015-03-17，先假设全部未发出
                 */

                datapos = tmp;
                PRINT_ERR_HEAD;
                print_err("write data size = %d", datapos);
                break;
            }

        } while (datapos < size);

        m_wrUNIQ = s_packet.UNIQ;           //记录最新包号

        PRINT_DBG_HEAD;
        print_dbg("write data %d = %d", size, datapos);
        return datapos;
    }

    return -1;
}

/*******************************************************************************************
*功能:    接收数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际接收量, -1 失败
*
*注释:   单向数据传输，采用MD5校验+冗余发送
*
*******************************************************************************************/
int32 CSUSOCKET::suread(void *data, int32 size)
{
    if ((data == NULL) && (size <= 0))  return -1;

    if ((getsocket() != SOCKET_ERR) && (m_type == SOCKET_UDP)) {

        uint8 packet[_UNI_PACKETSIZE];
        int32 readsize = -1;
        int32 idx = 0;
        int32 packetcnt = 0, idxcnt = -1;
        int32 packetbuf[100];
        pint32 ppacket = packetbuf;
        uint16 badpacket = 0;

        //开始接收
        do {
            UNI_PACKET s_packet;

            int32 i = readsocket(packet, sizeof(packet));
            if (i < 0) break;

            if (checkmd5_packet(packet, i, &s_packet)) {

                int32 tmpidx = _getint(s_packet.idx);

                if (m_curUNIQ == s_packet.UNIQ) {
                    //防止suread重入，再次接收到上次已经正确处理的包
                    PRINT_DBG_HEAD;
                    print_dbg("read packet all ready");
                    continue;
                }

                m_curUNIQ = s_packet.UNIQ;       //记录当前包

                //起始包
                if (packetcnt == 0) {
                    packetcnt = _getint(s_packet.total);
                    if (packetcnt > (int32)(sizeof(packetbuf) / sizeof(int32))) {
                        if ((ppacket = (pint32)malloc(packetcnt * sizeof(int32))) == NULL) {
                            PRINT_ERR_HEAD;
                            print_err("read packet total = %d", packetcnt);
                            break;
                        }

                    }
                    memset(ppacket, 0xff, packetcnt * sizeof(int32));
                    readsize = 0;
                    idxcnt = 0;
                }

                if (packetcnt != _getint(s_packet.total)) {
                    break;
                }

                i = tmpidx;

                //是否是重复包， bug可能会i越界
                if (ppacket[i] == i) {
                    PRINT_DBG_HEAD;
                    print_dbg("read packet ready idx = %d", i);
                    continue;
                }
                ppacket[i] = i;

                //是否顺序接收
                if (idx == i) {
                    idx++;
                }
                idxcnt++;

                i = s_packet.length - sizeof(s_packet.payload);
                if ((tmpidx * (int32)(sizeof(packet) - sizeof(s_packet)) + i) > size) {
                    i = size - (tmpidx * (sizeof(packet) - sizeof(s_packet)));
                    PRINT_ERR_HEAD;
                    print_err("read overflow packet idx = %d, length = %d, valid = %d",
                              tmpidx, s_packet.length, i);
                    if (i <= 0) {
                        continue;
                    }
                }

                memcpy((puint8)data + tmpidx * (sizeof(packet) - sizeof(s_packet)),
                       (void *)_OFFSET_DATA(packet), i);
                readsize += i;
            } else {
                PRINT_ERR_HEAD;
                print_err("bad packet = %d", ++badpacket);

                if (badpacket > 10)  break;
            }

        } while ((idxcnt < packetcnt) && (readsize < size));

        if ((ppacket != packetbuf) && (ppacket != NULL)) {
            free(ppacket);
        }

        PRINT_DBG_HEAD;
        print_dbg("read data %d = %d", size, readsize);
        return readsize;
    }

    return -1;
}



//文件传输配置
static const uint32 _SUFILE_BUFMAX = (64 * 1024);

//文件结构
#pragma pack(push, 1)
//#pragma pack(1)      //gcc 3.x不支持
#define SUFILEHEAD "_FILE_"
typedef struct  _sufile {
    char head[20];
#if SUFILETEST
    int64 guid;
    //uint8 nmd5[_MD5LEN_];
#endif
    uint64 size;
    uint64 pos;
    uint8 dmd5[_MD5LEN_];
    //puint8 pdata;

} SUFILE, *PSUFILE;
#pragma pack(pop)

#define _OFFSET_FDATA(s) ((ptr_t)(&(((PSUFILE)(s))->dmd5)) + _MD5LEN_)
static bool getfilemd5(FILE *fp, uint64 size, int32 flag, puint8 md5);
static bool getfilemd5(const pchar fpath, puint8 md5);

/*******************************************************************************************
*功能:    发送文件
*参数:    fpath                    ---->    文件名路径
*         uid                      ---->    用户自定义编码
*
*注释:
*
*******************************************************************************************/
#if SUFILETEST
bool CSUSOCKET::susendfile(const pchar fpath, int64 uid)
#else
bool CSUSOCKET::susendfile(const pchar fpath)
#endif
{
    if (!is_file(fpath)) return false;

    FILE *fop = fopen(fpath, "rb");
    bool bret = false;

    if (fop != NULL) {

        int32 s = 0;
        bret = true;
        uint64 writecnt = 0;

        struct stat filestat;
        PSUFILE pfilebuf;

        memset(&filestat, 0, sizeof(filestat));
        stat(fpath, &filestat);

        pfilebuf = (PSUFILE)malloc(sizeof(SUFILE) + _SUFILE_BUFMAX);
        if (pfilebuf == NULL) {
            PRINT_ERR_HEAD;
            print_err("malloc size = %d, filesize = %llu", sizeof(SUFILE) + _SUFILE_BUFMAX, filestat.st_size);

            fclose(fop);
            return false;
        }
        memset(pfilebuf, 0, sizeof(SUFILE) + _SUFILE_BUFMAX);

        strcpy(pfilebuf->head, SUFILEHEAD);
#if SUFILETEST
        pfilebuf->guid = uid;
#if 0
        //文件名
        getfilemd5(fpath, pfilebuf->nmd5);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("send md5 = %s, filename = %s", printbuf(pfilebuf->nmd5, sizeof(pfilebuf->nmd5)), fpath);
#endif
#endif
#endif
        pfilebuf->size = filestat.st_size;

        //计算文件MD5, 包括文件长度
        getfilemd5(fop, pfilebuf->size, m_filechk, pfilebuf->dmd5);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("send md5 = %s, filesize = %llu", printbuf(pfilebuf->dmd5, sizeof(pfilebuf->dmd5)), filestat.st_size);
#endif

        //发送文件
        while (bret && ((s = fread((void *)_OFFSET_FDATA(pfilebuf), 1, _SUFILE_BUFMAX, fop)) > 0)) {

            if (m_keyqueue == 0) {
                if (suwrite((void *)pfilebuf, s + sizeof(SUFILE)) != (s + (int32)sizeof(SUFILE))) {
                    PRINT_ERR_HEAD;
                    print_err("send size = %d", s);
                    bret = false;
                } else {
                    pfilebuf->pos += s;
                    writecnt += s;
                }
            } else {
                if (suwriteq((void *)pfilebuf, s + sizeof(SUFILE)) != (s + (int32)sizeof(SUFILE))) {
                    PRINT_ERR_HEAD;
                    print_err("send size = %d", s);
                    bret = false;
                } else {
                    pfilebuf->pos += s;
                    writecnt += s;
                }

                // 测试用
                //PRINT_DBG_HEAD;
                //print_dbg("send wait");
                //usleep(10);

            }

        }

        if (filestat.st_size == 0) {
            s = 0;
            if (m_keyqueue == 0) {
                if (suwrite((void *)pfilebuf, s + sizeof(SUFILE)) != (s + (int32)sizeof(SUFILE))) {
                    PRINT_ERR_HEAD;
                    print_err("send size = %d", s);
                    bret = false;
                } else {
                    pfilebuf->pos += s;
                    writecnt += s;
                }
            } else {
                if (suwriteq((void *)pfilebuf, s + sizeof(SUFILE)) != (s + (int32)sizeof(SUFILE))) {
                    PRINT_ERR_HEAD;
                    print_err("send size = %d", s);
                    bret = false;
                } else {
                    pfilebuf->pos += s;
                    writecnt += s;
                }

                // 测试用
                //PRINT_DBG_HEAD;
                //print_dbg("send wait");
                //usleep(10);

            }

        }

        free(pfilebuf);
        fclose(fop);

        if (bret) {
            PRINT_DBG_HEAD;
            print_dbg("send file %s success", fpath);
        } else {
            PRINT_ERR_HEAD;
            print_err("send file %s failed!", fpath);
        }

    } else {
        PRINT_ERR_HEAD;
        print_err("open file = %s failed!", fpath);
    }

    return bret;
}

/*******************************************************************************************
*功能:    接收文件
*参数:    fpath                    ---->    文件名路径
*         uid                      ---->    用户自定义编码
*         size                     ---->    文件大小, 可为NULL
*
*注释:
*******************************************************************************************/
#if SUFILETEST
bool CSUSOCKET::surecvfile(const pchar fpath, int64 &uid, puint64 size)
#else
bool CSUSOCKET::surecvfile(const pchar fpath, puint64 size)
#endif
{
    //if (!is_filepathvalid(fpath))    return false;

    FILE *fop = fopen(fpath, "wb");
    bool bret = false;

#if SUFILETEST
    uid = SUFILEGUIDNULL;
#endif

    if (fop == NULL) {
        PRINT_ERR_HEAD;
        print_err("open file = %s failed!", fpath);
        if (size != NULL) *size = 0ull;
    } else {
        uint64 readcnt = 0ull, filesize = 0ull;
        uint64 pos = 0ull;
        int32 i;
        uint8 md5[_MD5LEN_] = {0};
#if SUFILETEST
#if 0
        uint8 nmd5[_MD5LEN_] = {0};
#endif
#endif

        PSUFILE pfilebuf;

        //接收文件
        pfilebuf = (PSUFILE)malloc(sizeof(SUFILE) + _SUFILE_BUFMAX);
        if (pfilebuf == NULL) {
            PRINT_ERR_HEAD;
            print_err("malloc size = %u", sizeof(SUFILE) + _SUFILE_BUFMAX);

            fclose(fop);
            remove(fpath);
            return false;
        }
        memset(pfilebuf, 0, sizeof(SUFILE) + _SUFILE_BUFMAX);

#if SUFILETEST
#if 0
        //文件名MD5
        getfilemd5(fpath, nmd5);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("recv file md5 = %s, name = %s", printbuf(nmd5, sizeof(nmd5)), fpath);
#endif
#endif
#endif
        bret = true;
        int32 errcnt = 0;
        while (1) {

            if (m_keyqueue == 0) {

                if ((i = suread((void *)pfilebuf, sizeof(SUFILE) + _SUFILE_BUFMAX)) < 0) {
                    if (++errcnt > 1000) {
                        PRINT_ERR_HEAD;
                        print_err("recvfile lost");
                        break;
                    }
                    //后续可能正确的包
                    continue;
                }
            } else {
                if ((i = sureadq((void *)pfilebuf, sizeof(SUFILE) + _SUFILE_BUFMAX)) < 0) {
                    if (++errcnt > 1000) {
                        PRINT_ERR_HEAD;
                        print_err("recvfile lost");
                        break;
                    }
                    //后续可能正确的包
                    continue;
                }
            }

            if (i == 0) continue;

            //检查类型字段
            if (strcmp(pfilebuf->head, SUFILEHEAD) != 0) {
                PRINT_ERR_HEAD;
                print_err("recv file head = %s", pfilebuf->head);
                //遗留bug，需要应用层配合处理

                break;
            }

#if SUFILETEST
            if (uid == SUFILEGUIDNULL)
                uid = pfilebuf->guid;
            else if (uid != pfilebuf->guid) {
                PRINT_ERR_HEAD;
                print_err("recv uid %llu = %llu", uid, pfilebuf->guid);
                //遗留bug，需要应用层配合处理

                break;
            }
#if 0
            //检查文件名
            if (memcmp(nmd5, pfilebuf->nmd5, sizeof(nmd5) != 0)) {
                PRINT_ERR_HEAD;
                print_err("recv file md5 = %s, name = %s", printbuf(pfilebuf->nmd5, sizeof(pfilebuf->nmd5)), fpath);
                break;
            }
#endif
#endif
            //记录文件信息
            if (filesize == 0ull) {
                filesize = pfilebuf->size;
                memcpy(md5, pfilebuf->dmd5, sizeof(md5));

                if (filesize == 0ull)   {readcnt = 0ull; break;}    //文件大小为0
            }

            //写入文件
            i -= sizeof(SUFILE);
            if (i <= 0) continue;

            if ((pfilebuf->pos - pos) != 0ULL) {
                PRINT_DBG_HEAD;
                print_dbg("recv pos %lld(%lld)", pfilebuf->pos, pos);
                fseek(fop, (int64)(pfilebuf->pos - pos), SEEK_CUR);
            }
            if ((int32)fwrite((void *)_OFFSET_FDATA(pfilebuf), 1, i, fop) != i) {
                PRINT_ERR_HEAD;
                print_err("recv size = %d", i);
                break;
            }
            pos = pfilebuf->pos + i;
            readcnt += i;
            if ((readcnt >= filesize) || (pos >= filesize))  break;
        }

        if (readcnt != filesize) {
            bret = false;
            PRINT_ERR_HEAD;
            print_err("recv file = %llu, %llu", readcnt, filesize);
        }

        free(pfilebuf);
        fclose(fop);

        if (size != NULL)   *size = readcnt;
        PRINT_DBG_HEAD;
        print_dbg("recv file %s checkmd5, size = %llu", fpath, readcnt);

        //校验MD5
        if (bret && (m_filechk != 0)) {
            uint8 tmp[_MD5LEN_] = {0};

            FILE *fop = fopen(fpath, "rb");
            getfilemd5(fop, readcnt, m_filechk, tmp);
            if (fop != NULL) fclose(fop);   //文件打开错误异常

#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("md5_1 = %s", printbuf(md5, sizeof(md5)));
            PRINT_DBG_HEAD;
            print_dbg("md5_2 = %s", printbuf(tmp, sizeof(tmp)));
#endif
            bret = (memcmp(tmp, md5, sizeof(md5)) == 0);
            if (!bret) {
                PRINT_ERR_HEAD;
                print_err("md5_1 = %s", printbuf(md5, sizeof(md5)));
                PRINT_ERR_HEAD;
                print_err("md5_2 = %s", printbuf(tmp, sizeof(tmp)));
            }
        }


        //接收完成
        if (bret) {
            PRINT_DBG_HEAD;
            print_dbg("recv file %s success, size = %llu", fpath, readcnt);
        } else {
            //remove(fpath);    //改为应用层处理
            bret = true;

            PRINT_ERR_HEAD;
            print_err("recv file %s failed! size = %llu", fpath, readcnt);
        }

    }

    return bret;
}


/*******************************************************************************************
*功能:    判断收到的数据是否有效
*参数:    obj                 ---->   对象
*         data                ---->   数据指针
*         size                ---->   数据大小
*         返回值              ---->   当前唯一编号， 0 失败
*
*注释:    保存编号作为消息队列的数据类型
*
*******************************************************************************************/
uint32 suisvalid(CSUSOCKET &obj, const puint8 data, uint32 size)
{

    UNI_PACKET packet;

    if (check_packet1(data, size, &packet)) {

        if (packet.UNIQ != obj.m_curUNIQ) {

            PRINT_DBG_HEAD;
            print_dbg("queue = 0x%x, new uniq = %u(%u), cur = %u, timestamp = %ld", obj.m_keyqueue,
                      obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].UNIQ, packet.UNIQ, obj.m_curUNIQ,
                      obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].timestamp);

            if (obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].UNIQ != packet.UNIQ) {
                obj.m_curUNIQ = packet.UNIQ;
                //更新记录
                int32 test = 60;
                while (1) {
                    if (obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].UNIQ != obj.m_rdUNIQ) {
                        break;
                    }

                    PRINT_DBG_HEAD;
                    print_dbg("wait1 queue = 0x%x, uniq = %u(%u)", obj.m_keyqueue, obj.m_rdUNIQ, packet.UNIQ);
                    usleep(1);
                    if (--test <= 0) break;
                }

                if (test <= 0) {
                    PRINT_ERR_HEAD;
                    print_err("wait2 queue = 0x%x, uniq = %u(%u)", obj.m_keyqueue, obj.m_rdUNIQ, packet.UNIQ);
                    //bug 误丢包
                    //return 0;
                }

                obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].UNIQ = packet.UNIQ;
                obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].timestamp = time(NULL);
                return packet.UNIQ;
            } else {
                //乱序可能导致的重复包
                PRINT_ERR_HEAD;
                print_err("queue = 0x%x, old uniq = %u(%u) timestamp = %d",
                          obj.m_keyqueue, obj.m_curUNIQ, packet.UNIQ, (int)time(NULL));

                obj.m_curUNIQ = packet.UNIQ;
                if (abs(time(NULL) - obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].timestamp) >= DATA_TIMEOUT) {
                    obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].UNIQ = packet.UNIQ;
                    obj.m_pool[(packet.UNIQ - 1) & SUPOOL_MASK].timestamp = time(NULL);
                    return packet.UNIQ;
                }
            }
        } else {
            //重复包
#if __DEBUG_MORE__
            PRINT_DBG_HEAD;
            print_dbg("queue = 0x%x, old uniq = %lu(%lu)", obj.m_keyqueue, obj.m_curUNIQ, packet.UNIQ);
#endif
        }
    }

    return 0;
}

/*******************************************************************************************
*功能:    初始化queue相关成员
*参数:
*
*注释:
*
*******************************************************************************************/
void CSUSOCKET::initq(void)
{
    m_threadflag = 0;
    m_wrUNIQ = 1;                        //不能为0, msgqueue需要以此作为消息类型进行顺序取数
    m_rdUNIQ = 1;
    m_curUNIQ = (uint32)(-1);
    memset(m_pool, 0, sizeof(m_pool));
    m_keyqueue = 0;

#if SUQCACHE
    memset(&m_queuecache, 0, sizeof(m_queuecache));
    timeout_q = time(NULL);
#endif

}

/*******************************************************************************************
*功能:    启动缓冲数据处理
*参数:
*
*注释:    将接收数据与数据处理分离，提高网络响应速度
*         重复调用，工作线程未必安全退出，最好的方式先删除当前实例
*
*******************************************************************************************/
#include "unistd.h"
#include <sched.h>

#ifndef _MSG_ONE_
void *_queuefunc_(void *arg)
{
    CSUSOCKET *self = (CSUSOCKET *)arg;
    SUQUEUE packet;
    int msgid;

    pthread_setself("syssockqueue");

    self->m_keyqueue = (key_t)pthread_self();

    //防止内核版本差异导致的线程重复问题
_retry:
    //msgctl(msgget(self->m_keyqueue, 0660), IPC_RMID, NULL);
    msgid = msgget(self->m_keyqueue, IPC_CREAT | 0660 | IPC_EXCL);
    if (msgid == -1) {
        PRINT_ERR_HEAD;
        print_err("start queue task, queue = 0x%x failed", self->m_keyqueue);
        //return NULL;
        //usleep(1);
        self->m_keyqueue += (key_t)self->getsocket();
        goto _retry;
    }


    PRINT_INFO_HEAD;
    print_info("start queue task, queue = 0x%x", self->m_keyqueue);

#ifndef __CYGWIN__
    //CPU绑定
    {
        self->setcpu();
    }
#endif

    self->m_threadflag = 1;
    while (self->m_threadflag) {
        int32 i;

        if ((i = self->readsocket(packet.mdata, sizeof(packet.mdata))) > 0) {
            if ((packet.mtype = (long)suisvalid(*self, packet.mdata, i)) == 0) continue;
            int32 testsnd = 5;  //重复发送

_remsgsnd:
            if (msgsnd(msgid, &packet, i, 0) == -1) {         //阻塞方式

                if ((errno == EINTR) || (errno == EAGAIN)) {
                    PRINT_ERR_HEAD;
                    print_err("task(%ld) queue = 0x%x errno = %d(%s) write failed!",
                              pthread_self(), self->m_keyqueue, errno, strerror(errno));
                    usleep(1);
                    if (--testsnd < 0)  goto _remsgsnd;

                } else if ((errno == EIDRM) || (errno == ENOMEM) || (errno == EACCES)) {
                    PRINT_ERR_HEAD;
                    print_err("task(%ld) queue = 0x%x errno = %d(%s) write failed!",
                              pthread_self(), self->m_keyqueue, errno, strerror(errno));
                    break;

                }
                PRINT_ERR_HEAD;
                print_err("task(%ld) queue = 0x%x errno = %d(%s) write failed!",
                          pthread_self(), self->m_keyqueue, errno, strerror(errno));

            }
        } else {
            PRINT_ERR_HEAD;
            print_err("task(%ld) queue = 0x%x errno = %d(%s) socket failed!",
                      pthread_self(), self->m_keyqueue, errno, strerror(errno));
        }

    }

    PRINT_INFO_HEAD;
    print_info("end queue task");

    //重建消息队列
    PRINT_ERR_HEAD;
    print_err("task(%ld) queue = 0x%x recreate", pthread_self(), self->m_keyqueue);

    msgctl(msgid, IPC_RMID, NULL);
    goto _retry;

    PRINT_ERR_HEAD;
    print_err("end queue task");
    //外部同步检查
    self->m_threadflag = -1;
    return NULL;
}
#endif

void CSUSOCKET::setcpu(void)
{
    int cpus = sysconf(_SC_NPROCESSORS_ONLN);
    PRINT_DBG_HEAD;
    print_dbg("BIND CPU%d", cpus);

    if (cpus > 2) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(cpus - 2, &mask);

        if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) {
            PRINT_ERR_HEAD;
            print_err("BIND CPU%d %s", cpus - 2, strerror(errno));
        }
        PRINT_DBG_HEAD;
        print_dbg("BIND CPU%d, %ld", cpus - 2, pthread_self());
    }
}

bool CSUSOCKET::sustart(void)
{
    if ((getsocket() != SOCKET_ERR) && (m_type == SOCKET_UDP)) {

        if (m_keyqueue != 0) {
            PRINT_DBG_HEAD;
            print_dbg("restart queue task");

            //结束当前
            msgctl(msgget(m_keyqueue, 0660), IPC_RMID, NULL);
        }

        initq();

        pthread_t tid;
        pthread_attr_t attr;
        struct sched_param sch;

        //设置优先级
        pthread_attr_init(&attr);
        sch.sched_priority = 80;
        pthread_attr_setschedpolicy(&attr, SCHED_RR) ;
        pthread_attr_setschedparam(&attr, &sch) ;
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) ;       //要使优先级其作用必须要有这句话

        if (pthread_create(&tid, NULL/*&attr*/, _queuefunc_, (void *)this) != 0) {
            PRINT_ERR_HEAD;
            print_err("create queue task failed!");
            return false;
        }

        usleep(10000);
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    结束缓冲数据处理
*参数:
*
*注释:    返回true，并不表示线程已经立即结束
*
*******************************************************************************************/
bool CSUSOCKET::suend(void)
{
    if (m_keyqueue != 0) {

        m_threadflag = 0;
        writesocket("[$$$$]", 7);         //发送一个特殊数据，结束线程
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    发送数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际发送量, -1 失败
*
*注释:    暂时无用，以suwrite代替
*
*******************************************************************************************/
int32 CSUSOCKET::suwriteq(const void *data, int32 size)
{
    return suwrite(data, size);
}

#ifndef _MSG_ONE_
/*******************************************************************************************
*功能:    接收数据
*参数:    data                  ---->    数据地址
*         size                  ---->    数据长度
*         返回值                ---->    实际接收量, -1 失败
*
*注释:    超时机制
*
*******************************************************************************************/
int32 CSUSOCKET::sureadq(void *data, int32 size)
{
    if (m_keyqueue == 0) return -1;

    SUQUEUE packet;
    int msgid = msgget(m_keyqueue, 0660);
    if (msgid == -1) {
        PRINT_ERR_HEAD;
        print_err("read queue = 0x%x failed", m_keyqueue);
        return -1;
    }

    PRINT_DBG_HEAD;
    print_dbg("read queue = 0x%x, uniq = %u", m_keyqueue, m_rdUNIQ);

    int32 readsize = -1;
    int32 packetcnt = 0, idxcnt = -1;
    uint16 badpacket = 0;
    int32 random = 0;
    UNI_PACKET s_packet;

    do {
        int32 len;
#if SUQCACHE
        len = _queuecache(msgid, (void *)&packet, sizeof(packet.mdata));
#else
        len = msgrcv(msgid, &packet, sizeof(packet.mdata), 0, 0/*IPC_NOWAIT | IPC_EXCEPT*/);
        if ((packet.mtype != m_rdUNIQ) && (len > 0)) {
            PRINT_ERR_HEAD;
            print_err("read queue = 0x%x, %d:%d", m_keyqueue, packet.mtype, m_rdUNIQ);
            m_rdUNIQ = packet.mtype;
        }
        m_errno = errno;
#endif
        if (len == -1) {

            int32 tmp = sugeterrno();
            if ((tmp == ENOMSG ) || (tmp == EINTR ) || (tmp == EAGAIN)) {
                //超时处理或者中断
                //usleep(1);
                PRINT_ERR_HEAD;
                print_err("read queue = 0x%x failed, errno = %d(%s)", m_keyqueue, tmp, strerror(tmp));

            } else {
                PRINT_ERR_HEAD;
                print_err("read queue = 0x%x failed, errno = %d(%s)", m_keyqueue, tmp, strerror(tmp));
                readsize = -1;
                break;
            }

        } else if (len == 0) {
            PRINT_ERR_HEAD;
            print_err("read queue = 0x%x data empty", m_keyqueue);
            continue;
        } else {
            _uniqinc((uint32 &)m_rdUNIQ);

            if (checkmd5_packet1(packet.mdata, len, &s_packet)) {

                int32 i;
                int32 tmpidx = _getint(s_packet.idx);

                //起始包
                if (packetcnt == 0) {
                    if (tmpidx != 0) {
#if __DEBUG_MORE__
                        PRINT_ERR_HEAD;
                        print_err("read queue = 0x%x maybe disordered0(%u)", m_keyqueue, 0);
#endif
                        readsize = -1;
                        break;
                    }
                    readsize = 0;
                    idxcnt = 0;
                    packetcnt = _getint(s_packet.total);
                    random = _getint(&(s_packet.payload.randomkey), sizeof(s_packet.payload.randomkey));
                }

                if (packetcnt != _getint(s_packet.total)) {
#if __DEBUG_MORE__
                    PRINT_ERR_HEAD;
                    print_err("read queue = 0x%x maybe disordered1(%u)", m_keyqueue, packetcnt);
#endif
                    readsize = -1;
                    break;
                }

                if (random != _getint(&(s_packet.payload.randomkey), sizeof(s_packet.payload.randomkey))) {
#if __DEBUG_MORE__
                    PRINT_ERR_HEAD;
                    print_err("read queue = 0x%x maybe disordered2(%u)", m_keyqueue, random);
#endif
                    readsize = -1;
                    break;
                }

                idxcnt++;

                i = s_packet.length - sizeof(s_packet.payload);
                if ((tmpidx * (int32)(sizeof(packet.mdata) - sizeof(s_packet)) + i) > size) {
                    i = size - (tmpidx * (sizeof(packet.mdata) - sizeof(s_packet)));
                    PRINT_ERR_HEAD;
                    print_err("read overflow packet idx = %d, length = %d, valid = %d",
                              tmpidx, s_packet.length, i);
                    if (i <= 0) {
                        PRINT_ERR_HEAD;
                        print_err("bad packet = %d", ++badpacket);
                        //if (badpacket <= 10) continue;
                        readsize = -1;
                        break;
                    }
                }

                memcpy((puint8)data + tmpidx * (sizeof(packet.mdata) - sizeof(s_packet)),
                       (void *)_OFFSET_DATA(packet.mdata), i);
                readsize += i;
            } else {
                PRINT_ERR_HEAD;
                print_err("bad packet = %d", ++badpacket);
                //if (badpacket <= 10) continue;
                readsize = -1;
                break;
            }
        }

    } while ((idxcnt < packetcnt) && (readsize < size));

    PRINT_DBG_HEAD;
    print_dbg("read data %d = %d", size, readsize);
    return readsize;
}

/*******************************************************************************************
*功能:    结束缓冲数据处理
*参数:
*
*注释:    可在在suend后调用，确保正常安全退出
*
*******************************************************************************************/
void CSUSOCKET::suendq(void)
{
    if (m_keyqueue != 0) {
        while (m_threadflag != -1) {
            usleep(1000);
        }

        PRINT_DBG_HEAD;
        print_dbg("delete queue 0x%x", m_keyqueue);
        if (msgctl(msgget(m_keyqueue, 0660), IPC_RMID, NULL) == -1) {
            PRINT_ERR_HEAD;
            print_err("delete queue 0x%x failed:%s", m_keyqueue, strerror(errno));
        }
        m_keyqueue = 0;
    }

#if SUQCACHE
    _queuecacheclear();
#endif

}
#endif

/*******************************************************************************************
*功能:    初始化发送数据包
*参数:    packet                    ---->    包结构
*         size                      ---->    发送数据
*         uniq                      ---->    唯一包号
*
*注释:
*******************************************************************************************/
bool init_packet(PUNI_PACKET packet, int32 size, uint32 uniq)
{
    if ((packet == NULL) || (size <= 0))  return false;

    int32 tmp = (_UNI_PACKETSIZE - sizeof(UNI_PACKET));

    memset(packet, 0, sizeof(UNI_PACKET));
    packet->ver = _PACKET_VER;
    _setint(packet->idx, 0);
    _setint(packet->total, (size + tmp - 1) / tmp);
    gettimeofday(&(packet->timestamp), NULL);
    _setint(&(packet->UNIQ), uniq, sizeof(packet->UNIQ));
    memset(packet->reserved, _PACKET_GAP, sizeof(packet->reserved));
    _setint(&(packet->length), 0, sizeof(packet->length));

    _setint(&(packet->payload.randomkey), rand(), sizeof(packet->payload.randomkey));

    return true;
}

/*******************************************************************************************
*功能:    初始化发送数据包
*参数:    packet                    ---->    包结构
*         user                      ---->    用户源数据
*         size                      ---->    用户数据大小
*         pos                       ---->    用户数据打包量，初始值必须为0
*         dst                       ---->    发送的数据
*         dstsize                   ---->    dst容量
*         返回值                    ---->    发送的数据大小， -1 错误
*
*注释:    packet中的idx字段自加1
*
*******************************************************************************************/
int32 init_packet(PUNI_PACKET packet, const puint8 user, int32 size, int32 &pos, puint8 dst, const int32 dstsize)
{
    if ((packet == NULL) || (user == NULL) || (size <= 0)) return -1;
    if (dst == NULL) return -1;

    //计算发送数据大小
    int32 tmp = (dstsize - sizeof(UNI_PACKET));     //最大值
    int32 sendsize = 0;

    if (tmp < (size - pos)) {
        sendsize = dstsize - _OFFSET_RAND(0) - sizeof(packet->md5);
        _setint(&(packet->length), sendsize, sizeof(packet->length));
        sendsize = dstsize;
    } else {
        tmp = size - pos;
        sendsize = tmp + sizeof(packet->payload);
        _setint(&(packet->length), sendsize, sizeof(packet->length));
        sendsize = tmp + sizeof(UNI_PACKET);
    }

    //tmp为用户数据长度
    PRINT_DBG_HEAD;
    print_dbg("one packet = %d, uniq = %u, idx = %d, total = %d, length = %d, user = %d",
              sendsize, packet->UNIQ, _getint(packet->idx), _getint(packet->total), packet->length, tmp);

    //拷贝用户数据
    memcpy(dst, packet, _OFFSET_DATA(0));
    memcpy((void *)_OFFSET_DATA(dst), (user + pos), tmp);

    //冗余数据
    if (tmp > (int32)sizeof(packet->payload.datakey)) {
        memcpy((void *)_OFFSET_DATAKEY(dst, tmp), (user + pos + tmp - sizeof(packet->payload.datakey)),
               sizeof(packet->payload.datakey));
    } else {
        memset((void *)_OFFSET_DATAKEY(dst, tmp), _PACKET_GAP, sizeof(packet->payload.datakey));
        memcpy((void *)_OFFSET_DATAKEY(dst, tmp), (user + pos), tmp);
    }

    update_packet(dst, sendsize);

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("one packet = %d, uniq = %lu, idx = %d, total = %d, length = %d, rand = %u, md5 = %s, user = %d",
              sendsize, packet->UNIQ, _getint(packet->idx), _getint(packet->total), packet->length,
              _getint(&(packet->payload.randomkey), sizeof(packet->payload.randomkey)),
              printbuf((void *)_OFFSETR_MD5(dst, sendsize), sizeof(packet->md5)), tmp);
#endif

    //更新数据地址
    pos += tmp;
    _setint(packet->idx, _getint(packet->idx) + 1);
    _uniqinc(packet->UNIQ);

    return sendsize;
}

/*******************************************************************************************
*功能:    更新发送数据报文字段
*参数:    packet                    ---->    数据报文
*         size                      ---->    数据大小
*
*注释:    UNI_PACKET结构
*
*******************************************************************************************/
bool update_packet(puint8 packet, int32 size)
{
    UNI_PACKET s_packet;

    if (check_packet(packet, size, &s_packet)) {

#if _PACKET_MD5_
        _setint((void *)_OFFSET_RAND(packet), rand(), sizeof(s_packet.payload.randomkey));

        //MD5处理
        MD5_CTX md5;
        uint8 digest[16] = {0};

        PRINT_DBG_HEAD;
        print_dbg("md5 calc");

        MD5Init(&md5);
        MD5Update(&md5, packet, size - sizeof(s_packet.md5));
        MD5Final(digest, &md5);

        memset(s_packet.md5, 0, sizeof(s_packet.md5));
        memcpy(s_packet.md5, digest, sizeof(digest));

        memcpy((void *)_OFFSETR_MD5(packet, size), s_packet.md5, sizeof(s_packet.md5));
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("md5 = %s", printbuf(s_packet.md5, sizeof(s_packet.md5)));
#endif

#else
        memset((void *)_OFFSETR_MD5(packet, size), 0, sizeof(s_packet.md5));
#endif
        return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    检查发送数据报文
*参数:    packet                    ---->    数据报文
*         size                      ---->    数据大小
*         s_packet                  ---->    报文结构
*
*注释:    UNI_PACKET结构
*
*******************************************************************************************/
#define _RETERR(e) {_errno = e; goto _err;}

bool check_packet(puint8 packet, int32 size, PUNI_PACKET s_packet)
{
    UNI_PACKET tmp;
    int32 _errno;

    if ((packet == NULL) || (size <= (int32)sizeof(UNI_PACKET))) _RETERR(0);
    if (s_packet == NULL)   s_packet = &tmp;

    memset(s_packet, 0, sizeof(UNI_PACKET));
    memcpy(s_packet, packet, _OFFSET_RAND(0));

    //检查基本报文头
    if (s_packet->ver < _PACKET_VER)    _RETERR(1);
    if (_getint(s_packet->idx) >= _getint(s_packet->total)) _RETERR(2);
    for (int i = 0; i < (int)sizeof(s_packet->reserved); i++) {
        if (s_packet->reserved[i] != _PACKET_GAP) _RETERR(3);
    }

    if (s_packet->length != ((size - sizeof(UNI_PACKET)) + sizeof(s_packet->payload))) _RETERR(4);

    return true;
_err:
    PRINT_ERR_HEAD;
    print_err("_errno = %d", _errno);

    return false;
}

//简单判断
bool check_packet1(puint8 packet, int32 size, PUNI_PACKET s_packet)
{
    UNI_PACKET tmp;
    int32 _errno;

    if ((packet == NULL) || (size <= (int32)sizeof(UNI_PACKET))) _RETERR(0);
    if (s_packet == NULL)   s_packet = &tmp;

    memcpy(s_packet, packet, _OFFSET_RAND(0));

    //检查基本报文头
    if (s_packet->ver < _PACKET_VER)    _RETERR(1);

    return true;
_err:
    PRINT_ERR_HEAD;
    print_err("_errno = %d, size = %d, data = %s", _errno, size, printbuf(packet, size));

    return false;
}

bool checkmd5_packet(puint8 packet, int32 size, PUNI_PACKET s_packet)
{
    if ((packet == NULL) || (size <= (int32)sizeof(UNI_PACKET))) return false;

#if _PACKET_MD5_
    //MD5处理
    MD5_CTX md5;
    uint8 digest[16] = {0};

    MD5Init(&md5);
    MD5Update(&md5, packet, size - sizeof(((PUNI_PACKET)0)->md5));
    MD5Final(digest, &md5);
#else
    uint8 digest[16] = {0};
#endif

    if (memcmp(digest, packet + size - sizeof(((PUNI_PACKET)0)->md5), sizeof(digest)) == 0) {

        UNI_PACKET tmp;
        puint8 data;
        uint16 i;
        bool bret = true;

        if (s_packet == NULL) s_packet = &tmp;

        //读取基本报文头
        memset(s_packet, 0, sizeof(UNI_PACKET));
        memcpy(s_packet, packet, _OFFSET_DATA(0));
        memcpy(s_packet->md5, (void *)_OFFSETR_MD5(packet, size), sizeof(s_packet->md5));

        i = s_packet->length - sizeof(s_packet->payload);
        data = (puint8)_OFFSET_DATAKEY(packet, i);
        memcpy(s_packet->payload.datakey, data, sizeof(s_packet->payload.datakey));

        //校验冗余数据
        if (i > sizeof(s_packet->payload.datakey)) {
            data -= sizeof(s_packet->payload.datakey);
            bret = (memcmp(data, s_packet->payload.datakey, sizeof(s_packet->payload.datakey)) == 0);
        } else {

            data = (puint8)_OFFSET_DATA(packet);
            bret = (memcmp(data, s_packet->payload.datakey, i) == 0);

            for (; i < sizeof(s_packet->payload.datakey); i++) {
                bret &= (s_packet->payload.datakey[i] == _PACKET_GAP);
            }

        }

        if (!bret) {
            PRINT_ERR_HEAD;
            print_err("one packet = %d, idx = %d, total = %d, length = %d, rand = %u, md5 = %s",
                      size, _getint(s_packet->idx), _getint(s_packet->total), s_packet->length,
                      _getint(&(s_packet->payload.randomkey), sizeof(s_packet->payload.randomkey)),
                      printbuf(s_packet->md5, sizeof(s_packet->md5)));
        }

#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("one packet = %d, idx = %d, total = %d, length = %d, rand = %u, md5 = %s",
                  size, _getint(s_packet->idx), _getint(s_packet->total), s_packet->length,
                  _getint(&(s_packet->payload.randomkey), sizeof(s_packet->payload.randomkey)),
                  printbuf(s_packet->md5, sizeof(s_packet->md5)));
#endif

        return bret;
    } else {
        PRINT_ERR_HEAD;
        print_err("one packet = %d, idx = %d, total = %d, length = %d, rand = %u, md5 = %s",
                  size, _getint(s_packet->idx), _getint(s_packet->total), s_packet->length,
                  _getint(&(s_packet->payload.randomkey), sizeof(s_packet->payload.randomkey)),
                  printbuf(s_packet->md5, sizeof(s_packet->md5)));

    }

    return false;
}

//简单判断
bool checkmd5_packet1(puint8 packet, int32 size, PUNI_PACKET s_packet)
{
    if ((packet == NULL) || (size <= (int32)sizeof(UNI_PACKET))) return false;

    UNI_PACKET tmp;
    puint8 data;
    uint16 i;

    if (s_packet == NULL) s_packet = &tmp;

    //读取基本报文头
    memset(s_packet, 0, sizeof(UNI_PACKET));
    memcpy(s_packet, packet, _OFFSET_DATA(0));
    memcpy(s_packet->md5, (void *)_OFFSETR_MD5(packet, size), sizeof(s_packet->md5));

    i = s_packet->length - sizeof(s_packet->payload);
    data = (puint8)_OFFSET_DATAKEY(packet, i);
    memcpy(s_packet->payload.datakey, data, sizeof(s_packet->payload.datakey));

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("one packet = %d, idx = %d, total = %d, length = %d, rand = %u, md5 = %s",
              size, _getint(s_packet->idx), _getint(s_packet->total), s_packet->length,
              _getint(&(s_packet->payload.randomkey), sizeof(s_packet->payload.randomkey)),
              printbuf(s_packet->md5, sizeof(s_packet->md5)));
#endif
    return true;
}

/*******************************************************************************************
*功能:    文件md5
*参数:    fp                        ---->    文件句柄
*         size                      ---->    文件大小
*         flag                      ---->    校验算法
*         md5                       ---->    计算结果
*
*注释:    先要计算size的md5
*
*******************************************************************************************/
bool getfilemd5(FILE *fp, uint64 size, int32 flag, puint8 md5)
{
    if ((fp == NULL) || (md5 == NULL))  return false;

    //判断算法配置
    uint8 digest[16] = {0};
    PRINT_DBG_HEAD;
    print_dbg("FILE CHECK %lld %d", size, flag);

    if (flag != 0) {
        uint64 pos = ftell(fp);
        uint8 buf[TMPBUFFMAX];
        int32 n;
        int32 sleepcnt = 0;
        uint64 nread = 0ULL;

        MD5_CTX md5_t;
        MD5Init(&md5_t);
        MD5Update(&md5_t, (const puint8)&size, sizeof(uint64));

        fseek(fp, 0, SEEK_SET);
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
            MD5Update(&md5_t, buf, n);

            nread += n;
            if (flag > 0) {if (nread / (1024 * 1024) == flag) break;} //文件头部分数据

            //防止资源占用过高, 每20MB等待
            if (++sleepcnt >= 2500) {
                usleep(1);
                sleepcnt = 0;
            }

        }

        //结束文件
        if (flag > 0) {
            uint64 nleft = 0ULL;
            fseek(fp, 0, SEEK_END);
            if ((nleft = (ftell(fp) - nread)) > 0ULL) {

                fseek(fp, MIN(nleft, sizeof(buf)), SEEK_END);
                n = fread(buf, 1, sizeof(buf), fp);
                MD5Update(&md5_t, buf, n);
            }
        }

        MD5Final(digest, &md5_t);
        memcpy(md5, digest, sizeof(digest));

        fseek(fp, pos, SEEK_SET);
    } else {
        memset(md5, 0, sizeof(digest));
    }

    PRINT_DBG_HEAD;
    print_dbg("FILE CHECK (%s)", printbuf(md5, sizeof(digest)));

    return true;
}

//文件名
bool getfilemd5(const pchar fpath, puint8 md5)
{
    if ((fpath == NULL) || (md5 == NULL))  return false;

    MD5_CTX md5_t;
    uint8 digest[16] = {0};

    MD5Init(&md5_t);
    MD5Update(&md5_t, (const puint8)fpath, strlen(fpath));

    MD5Final(digest, &md5_t);
    memcpy(md5, digest, sizeof(digest));

    return true;
}

/*******************************************************************************************
*功能:    系统消息队列设置
*参数:
*
*注释:
*
*******************************************************************************************/
void CSUSOCKET::msgqueueset(void)
{
    sysv_init(CSUSOCKET::msgmnb, CSUSOCKET::msgmax);

#if 0
    char cmd[1024];

    sprintf(cmd, "sysctl -w kernel.msgmnb=%d kernel.msgmax=%d",
            CSUSOCKET::msgmnb, CSUSOCKET::msgmax);

    system(cmd);

    //优化网络参数
    sprintf(cmd, "sysctl -w net.core.rmem_default=%d net.core.rmem_max=%d",
            64 * 1024, 20 * 1024 * 1024);

    system(cmd);

    sprintf(cmd, "sysctl -w net.core.wmem_default=%d net.core.wmem_max=%d",
            64 * 1024, 20 * 1024 * 1024);

    system(cmd);

    sprintf(cmd, "sysctl -w net.core.netdev_max_backlog=%d",
            5000);

    system(cmd);
#endif

}

//自定义接口
void CSUSOCKET::msgqueueset(int32 msgmnb, int32 msgmax)
{
    sysv_init(msgmnb, msgmax);
}

#if SUQCACHE
/*******************************************************************************************
*功能:    消息缓冲，支持丢包处理
*参数:    msgid                     ---->    消息队列
*         data                      ---->    用户数据
*         size                      ---->    数据大小
*         返回值                    ---->    有效数据长度
*
*注释:    对于m_rdUNIQ适时调整
*
*******************************************************************************************/
#define _queuecachedel(x) {free(m_queuecache.packet[x]); m_queuecache.packet[x] = NULL; m_queuecache.cnt--;}

int32 CSUSOCKET::_queuecache(int msgid, void *data, uint32 size)
{
    int32 len = -1;
    PSUQUEUE packet = (PSUQUEUE)data;

    if (m_queuecache.cnt) {
        PSUQUEUE tmp;

        PRINT_DBG_HEAD;
        print_dbg("queuecache count %d", m_queuecache.cnt);

        for (uint32 i = 0; i < SUQCACHE_L; i++) {
            if (m_queuecache.packet[i] == NULL) continue;
            tmp = (PSUQUEUE)((puint8)(m_queuecache.packet[i]) + sizeof(len));
            PRINT_DBG_HEAD;
            print_dbg("queuecache = %ld, %d", tmp->mtype, m_rdUNIQ);

            if (tmp->mtype == (long)m_rdUNIQ) {

                //找到并删除当前记录
                memcpy(&len, m_queuecache.packet[i], sizeof(len));
                memcpy(packet, (puint8)(m_queuecache.packet[i]) + sizeof(len), sizeof(SUQUEUE));

                _queuecachedel(i);
                return len;
            }
        }

    }

    if (m_queuecache.cnt == SUQCACHE_L) {
        PRINT_ERR_HEAD;
        print_err("queuecache full = %d", m_rdUNIQ);

        return _queuecache_err();
    }

#if __DEBUG_MORE__
    PRINT_DBG_HEAD;
    print_dbg("queuecache read %d", m_rdUNIQ);

    len = msgrcv(msgid, packet, size, 0, 0/*IPC_NOWAIT | IPC_EXCEPT*/);

    PRINT_DBG_HEAD;
    print_dbg("queuecache read %ld %d", packet->mtype, m_rdUNIQ);
#else
    len = msgrcv(msgid, packet, size, 0, 0/*IPC_NOWAIT | IPC_EXCEPT*/);
#endif

    m_errno = errno;
    //错误直接返回
    if (len <= 0)   return len;

    if (packet->mtype != (long)m_rdUNIQ) {
        //临时缓冲：len --> type --> data
        uint32 i;
        puint8 bak = (puint8)malloc(sizeof(len) + sizeof(SUQUEUE));
        if (bak == NULL) {
            PRINT_ERR_HEAD;
            print_err("queuecache nomemery");

            //丢包
            m_errno = ESUSOCKET1;
            return -1;
        }
        memcpy(bak, &len, sizeof(len));
        memcpy(bak + sizeof(len), packet, sizeof(SUQUEUE));

        for (i = 0; i < SUQCACHE_L; i++) {
            if (m_queuecache.packet[i] == NULL) break;
        }
        m_queuecache.packet[i] = bak;
        m_queuecache.cnt++;

        //超时处理，暂定2秒
        if (abs(time(NULL) - timeout_q) >= DATA_TIMEOUT) {
            PRINT_ERR_HEAD;
            print_err("queuecache timeout = %d, cnt = %d", m_rdUNIQ, m_queuecache.cnt);

            if (m_queuecache.cnt >= 1)
                return _queuecache_err();
        }

        //timeout_q = time(NULL);
        //PRINT_ERR_HEAD;
        //print_err("queuecache add %ld(%d), time = %d", packet->mtype, len, timeout_q);

        PRINT_ERR_HEAD;
        print_err("queuecache add %ld(%d), time = %ld", packet->mtype, len, time(NULL));

        m_errno = ENOMSG;   //模拟msgrcv处理
        len = -1;
    } else {
        timeout_q = time(NULL);

        if (m_queuecache.cnt) {
            //bug如果此时cache还有包的情况，但是包号回环，遗留包没有处理
            PRINT_ERR_HEAD;
            print_err("queuecache overflow = %d, cnt = %d", m_rdUNIQ, m_queuecache.cnt );

            //丢弃重建
            _queuecacheclear();
        }

    }

    return len;
}

int32 CSUSOCKET::_queuecache_err(void)
{
    //确认丢包处理
    uint32 cur, j;
    int32 len;
    PSUQUEUE tmp;

_loop:
    cur = 0;    //消息队列特性，cur不为了0
    j = -1;

    //UNIQ回环时，如何判断？？
    //暂时丢弃尾部包
    for (uint32 i = 0; i < SUQCACHE_L; i++) {
        if (m_queuecache.packet[i] == NULL) continue;
        tmp = (PSUQUEUE)((puint8)(m_queuecache.packet[i]) + sizeof(len));

        if (cur == 0) {cur = tmp->mtype; j = i;}      //第一个记录
        if (tmp->mtype < (long)cur) {cur = tmp->mtype; j = i;}
    }

    PRINT_ERR_HEAD;
    print_err("queuecache min %d", cur);

#if 0
    UNI_PACKET s_packet;
    SUQUEUE packet;
    //查找起始包
    while (true) {
        memcpy(&len, m_queuecache.packet[j], sizeof(len));
        memcpy(&packet, (puint8)(m_queuecache.packet[j]) + sizeof(len), sizeof(SUQUEUE));

        if (checkmd5_packet(packet.mdata, len, &s_packet)) {
            //临时补丁，不完善
            if ((_getint(s_packet.idx) == 0) && (_getint(s_packet.total) == 1)) {
                //找到退出
                PRINT_ERR_HEAD;
                print_err("queuecache head = %d", cur);
                break;
            }
        }

        _queuecachedel(j);

        _uniqinc(cur);
        if (m_queuecache.cnt) {
            bool bnew = false;
            for (uint32 i = 0; i < SUQCACHE_L; i++) {
                if (m_queuecache.packet[i] == NULL) continue;
                tmp = (PSUQUEUE)((puint8)(m_queuecache.packet[i]) + sizeof(len));

                if (tmp->mtype <= cur) {cur = tmp->mtype; j = i; bnew = true;}
            }

            if (bnew) {
                PRINT_ERR_HEAD;
                print_err("queuecache head loop = %d", cur);
                goto _loop;
            }

        } else {
            PRINT_ERR_HEAD;
            print_err("queuecache head not found = %d", cur);
            break;
        }
    }
#endif

    //容错
    if (cur == 0) {
        PRINT_ERR_HEAD;
        print_err("queuecache = %d, [%d] = %d", m_rdUNIQ, j, cur);

        //cache异常，重建
        _queuecacheclear();
        m_errno = ESUSOCKET1;
        return -1;
    }

    m_rdUNIQ = cur;
    PRINT_ERR_HEAD;
    print_err("queuecache = %d", m_rdUNIQ);
    m_errno = ESUSOCKET1;
    return -1;
}

void CSUSOCKET::_queuecacheclear(void)
{
    PRINT_DBG_HEAD;
    print_dbg("queuecache = %d", m_queuecache.cnt);

    while (m_queuecache.cnt) {
        for (uint32 i = 0; i < SUQCACHE_L; i++) {
            if (m_queuecache.packet[i] != NULL) {
                free(m_queuecache.packet[i]);
                m_queuecache.packet[i] = NULL;
            }
        }
        m_queuecache.cnt = 0;
    }

    memset(&m_queuecache, 0, sizeof(m_queuecache));

    PRINT_DBG_HEAD;
    print_dbg("queuecache = %d", m_queuecache.cnt);

}

#endif


/*******************************************************************************************
*功能:    获取自定义errno
*参数:
*
*注释:
*
*******************************************************************************************/
int32 CSUSOCKET::sugeterrno(void)
{
    return m_errno;
}


uint8 CSUSOCKET::getrepeat(void)
{
    return m_repeat;
}
int32 CSUSOCKET::getdelayus(void)
{
    return m_delayus;
}

