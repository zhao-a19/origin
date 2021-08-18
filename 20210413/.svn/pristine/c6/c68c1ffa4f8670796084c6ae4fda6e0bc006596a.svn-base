/*******************************************************************************************
*文件:    syssocket6.cpp
*描述:    支持IPv6和IPv4
*
*作者:    张冬波
*日期:    2018-12-24
*修改:    创建文件                            ------>     2018-12-24
*         添加兼容性接口                      ------>     2019-01-02
*
*
*******************************************************************************************/
#include "syssocket.h"
#include "debugout.h"
#include "stringex.h"
#include "syssocket.h"
#include <errno.h>

CSYSSOCKET6::CSYSSOCKET6(): CSYSSOCKET()
{
    init6();
}

/**
 * [CSYSSOCKET6 description]
 * @param  type   [description]
 * @param  domain [IPv4 or IPv6，以后可扩展其他类型]
 * @return        [description]
 */
CSYSSOCKET6::CSYSSOCKET6(SOCKETTYPE type, bool encode, int domain): CSYSSOCKET()
{
    init6();
    createsocket(type, domain);
    setencode(!encode);
}
CSYSSOCKET6::CSYSSOCKET6(const CSYSSOCKET6 &obj): CSYSSOCKET(obj)
{
    PRINT_DBG_HEAD;
    print_dbg("CSYSSOCKET6 construction");

    init6();
    m_domain = obj.m_domain;
    memcpy(&m_ssaddr, &obj.m_ssaddr, sizeof(m_ssaddr));
    strcpy(m_addr_lstr, obj.m_addr_lstr);
}

CSYSSOCKET6::~CSYSSOCKET6()
{
}

CSYSSOCKET6::CSYSSOCKET6(SOCKETTYPE type, bool encode, const pchar ip, uint16 port): CSYSSOCKET()
{
    init6();
    createsocket(type, is_ip6addr(ip) ? IPV6_TAG : IPV4_TAG);
    setencode(!encode);
    setaddress(ip, port);
}

void CSYSSOCKET6::init6(void)
{
    m_domain = IPV6_TAG;
    memset(&m_ssaddr, 0, sizeof(m_ssaddr));
    memset(m_addr_lstr, 0, sizeof(m_addr_lstr));
    memset(m_addr_rstr, 0, sizeof(m_addr_rstr));
}

/**
 * [CSYSSOCKET6::createsocket description]
 * @param  type   [description]
 * @param  domain [description]
 * @return        [description]
 */
SYSSOCKET CSYSSOCKET6::createsocket(SOCKETTYPE type, int domain)
{
    //防止重复调用
    closesocket();

    m_domain = domain;
    PRINT_DBG_HEAD;
    print_dbg("socket[%d] type = %d", m_domain, type);

    switch (type) {
    case SOCKET_TCP:
        m_socket = socket((m_domain == IPV4_TAG) ? PF_INET : PF_INET6, SOCK_STREAM, 0);
        break;
    case SOCKET_UDP:
        m_socket = socket((m_domain == IPV4_TAG) ? PF_INET : PF_INET6, SOCK_DGRAM , 0);
        break;
    default: return SOCKET_ERR;
    }

    if (m_socket < 0) {
        m_socket = SOCKET_ERR;
        PRINT_ERR_HEAD;
        print_err("socket[%d] type = %d, %d(%s)", m_domain, type, errno, strerror(errno));
    } else {

        uint opt = 1;
        m_type = type;

        //允许使用待关闭的socket
        if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0) {
            PRINT_ERR_HEAD;
            print_err("setsockopt SO_REUSEADDR failed, %d(%s)!", errno, strerror(errno));
        }
    }

    return m_socket;
}

/**
 * [CSYSSOCKET6::setaddress description]
 * @param  ip   [description]
 * @param  port [description]
 * @return      [description]
 */
bool CSYSSOCKET6::setaddress(const pchar ip, uint16 port)
{
    m_ssaddr.storage.ss_family = (m_domain == IPV4_TAG) ? PF_INET : PF_INET6;

    if (m_domain == IPV4_TAG) {
        uint32 ip_t;
        if (ipstr2int(ip, &ip_t) < 0)    return false;
        m_ssaddr.in4.sin_addr.s_addr = ip_t;
        m_ssaddr.in4.sin_port = htons(port);
        return CSYSSOCKET::setaddress(ip_t, port);
    }

    m_ssaddr.in6.sin6_port = htons(port);
    if (!str2ip6(ip, &m_ssaddr.in6.sin6_addr)) return false;
}

bool CSYSSOCKET6::setaddress(const pchar ip, const pchar port)
{
    if ((ip == NULL) || (port == NULL))  return false;

    return setaddress(ip, (uint16)atoi(port));
}

/**
 * [CSYSSOCKET6::getaddress description]
 * @param  addr [description]
 * @return      [description]
 */
bool CSYSSOCKET6::getaddress(ssaddr_t *addr)
{
    if (addr == NULL)    return false;

    // if (m_domain == IPV4_TAG) {
    //     return CSYSSOCKET::getaddress((struct sockaddr_in *)addr);
    // }
    memcpy(addr, &m_ssaddr, sizeof(ssaddr_t));
    return true;
}

/**
 * [CSYSSOCKET6::getaddress description]
 * @param  ip      [description]
 * @param  port    [description]
 * @param  self    [description]
 * @param  straddr [description]
 * @return         [description]
 */
bool CSYSSOCKET6::getaddress(void *ip, puint16 port, bool self, pchar straddr)
{
    if ((ip == NULL) || (port == NULL)) return false;

    if (m_domain == IPV4_TAG) {
        return CSYSSOCKET::getaddress((puint32)ip, port, self, straddr);
    }

    SYSSOCKET tmps;
    ssaddr_t addr;
    socklen_t len = sizeof(addr);
    bool bret = true;

    //区分客户端|服务器
    if (m_srv == SOCKET_SRV) {
        if (m_socketnew == SOCKET_ERR) {
            tmps = m_socket;        //支持UDP获取本机地址
        } else {
            tmps = m_socketnew;
        }
    } else {
        tmps = m_socket;
    }
    memset(&addr, 0, len);
    if (self) bret = (getsockname(tmps, (struct sockaddr *)&addr, &len) == 0);
    else bret = (getpeername(tmps, (struct sockaddr *)&addr, &len) == 0);

    if (bret) {
        memcpy(ip, &addr.in6.sin6_addr, sizeof(addr.in6.sin6_addr));
        *port = ntohs(addr.in6.sin6_port);

        if (straddr != NULL) {
            ip6port2str((ip6addr_t *)ip, *port, straddr);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("getsockname_%d (%d:%s)", self, errno, strerror(errno));
    }

    return bret;
}

/**
 * [CSYSSOCKET6::setconnect description]
 * @param  type [description]
 * @return      [description]
 */
bool CSYSSOCKET6::setconnect(SOCKETTYPE type)
{
    if (m_socket == SOCKET_ERR) return false;

    socklen_t addrlen = 0;
    switch (type) {
    case SOCKET_SRV:
        if (m_domain == IPV4_TAG) {
            ipport2str(m_ssaddr.in4.sin_addr.s_addr, ntohs(m_ssaddr.in4.sin_port), m_addr_lstr);
            addrlen = sizeof(m_ssaddr.in4);
        } else {
            ip6port2str(&m_ssaddr.in6.sin6_addr, ntohs(m_ssaddr.in6.sin6_port), m_addr_lstr);
            addrlen = sizeof(m_ssaddr.in6);
        }

        PRINT_DBG_HEAD;
        print_dbg("socket[%d] info %s", m_domain, m_addr_lstr);
        if (m_type == SOCKET_TCP) {

            //TCP 服务器
            if (bind(m_socket, (struct sockaddr *)(&m_ssaddr), addrlen) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP SRV bind failed(%d:%s)!", errno, strerror(errno));
                return false;
            }

            if (listen(m_socket, 10000) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP SRV listen failed(%d:%s)!", errno, strerror(errno));
                return false;
            }
        } else {

            //UDP 服务器
            if (bind(m_socket, (struct sockaddr *)(&m_ssaddr), addrlen) < 0) {
                PRINT_ERR_HEAD;
                print_err("UDP SRV bind failed(%d:%s)!", errno, strerror(errno));
                return false;
            }
        }
        break;
    case SOCKET_CLIENT:
        if (m_domain == IPV4_TAG) {
            ipport2str(m_ssaddr.in4.sin_addr.s_addr, ntohs(m_ssaddr.in4.sin_port), m_addr_rstr);
            addrlen = sizeof(m_ssaddr.in4);
        } else {
            ip6port2str(&m_ssaddr.in6.sin6_addr, ntohs(m_ssaddr.in6.sin6_port), m_addr_rstr);
            addrlen = sizeof(m_ssaddr.in6);
        }

        PRINT_DBG_HEAD;
        print_dbg("socket[%d] info %s", m_domain, m_addr_rstr);

        if (m_type == SOCKET_TCP) {
            if (connect(m_socket, (struct sockaddr *)(&m_ssaddr), addrlen) < 0) {
                PRINT_ERR_HEAD;
                print_err("TCP[%d] CLIENT connect failed(%d:%s), addr = %s!",
                          m_domain, errno, strerror(errno), m_addr_rstr);
                return false;
            }

            ssaddr_t ip;
            uint16 port;
            getaddress(&ip, &port, true, m_addr_lstr);
            PRINT_DBG_HEAD;
            print_dbg("TCP[%d] info %s", m_domain, m_addr_lstr);
        } else {
            //UDP 客户端
        }

        break;
    default: return false;
    }

    m_srv = type;
    PRINT_DBG_HEAD;
    print_dbg("connect_%d|%d, socket[%d] = %d success!", m_type, m_srv, m_domain, m_socket);

    return true;
}

/**
 * [CSYSSOCKET6::getconnect description]
 * @return  [description]
 */
bool CSYSSOCKET6::getconnect(void)
{
    if (m_socket == SOCKET_ERR) return false;

    // if (m_domain == IPV4_TAG) {
    //     return CSYSSOCKET::getconnect();
    // }

    if ((m_type == SOCKET_TCP) && (m_srv == SOCKET_SRV)) {

        PRINT_INFO_HEAD;
        print_info("accept block...");

        if ((m_socketnew = accept(m_socket, NULL, NULL)) < 0) {
            m_errno = errno;
            PRINT_ERR_HEAD;
            print_err("TCP SRV accept failed! socket[%d] = %d, addr = %s, error = %d(%s)",
                      m_domain, m_socket, m_addr_lstr, m_errno, strerror(m_errno));

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

/**
 * [CSYSSOCKET6::readtcp/readudp description]
 * @param  socket_r [description]
 * @param  data     [description]
 * @param  size     [description]
 * @return          [description]
 */
int32 CSYSSOCKET6::readtcp(SYSSOCKET socket_r, void *data, const int32 size)
{
    int32 readlen = 0;
_recvagain1:
    int32 i = (int32)recv(socket_r, (puint8)data + readlen, size - readlen, 0);
    if (is_strempty(m_addr_rstr)) {
        ssaddr_t ip;
        uint16 port;
        getaddress(&ip, &port, false, m_addr_rstr);
    }
    if (i == 0) {
        PRINT_DBG_HEAD;
        print_dbg("TCP socket[%d] = %d closed, addr = %s,%s", m_domain, socket_r, m_addr_lstr, m_addr_rstr);
        if (readlen == 0) readlen = -1;

    } else if (i < 0) {
        m_errno = errno;
        if (m_errno == EINTR) goto _recvagain1;
        if (m_fcntl) {
            PRINT_ERR_HEAD;
            print_err("TCP socket[%d] = %d unknown = %d(%s), addr = %s,%s", m_domain, socket_r,
                      m_errno, strerror(m_errno), m_addr_lstr, m_addr_rstr);
        } else {
            PRINT_ERR_HEAD;
            print_err("TCP socket[%d] = %d unknown = %d(%s), addr = %s,%s", m_domain, socket_r,
                      m_errno, strerror(m_errno), m_addr_lstr, m_addr_rstr);

            if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                //非阻塞模式
                m_errno = ESUSOCKET2;
            }
        }
    } else {
        readlen += i;
        //尽量一次多收数据
        PRINT_DBG_HEAD;
        print_dbg("more TCP socket[%d] = %d, addr = %s,%s, size = %d,%d", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr, size, readlen);

        if ((m_datamore) && (readlen < size)) {
            goto _recvagain1;
        }
    }

    return readlen;
}

int32 CSYSSOCKET6::readudp(SYSSOCKET socket_r, void *data, const int32 size)
{
_recvagain2:
    int32 readlen = recvfrom(socket_r, data, size, 0, NULL, NULL);
    if (is_strempty(m_addr_rstr)) {
        ssaddr_t ip;
        uint16 port;
        getaddress(&ip, &port, false, m_addr_rstr);
    }
    if (readlen == 0) {
        PRINT_DBG_HEAD;
        print_dbg("UDP socket[%d] = %d closed, addr = %s,%s", m_domain, socket_r, m_addr_lstr, m_addr_rstr);
        readlen = -1;
    } else if (readlen < 0) {
        m_errno = errno;
        if (m_errno == EINTR) goto _recvagain2;
        if (m_fcntl) {
            PRINT_ERR_HEAD;
            print_err("UDP socket[%d] = %d unknown = %d(%s), addr = %s,%s", m_domain, socket_r,
                      m_errno, strerror(m_errno), m_addr_lstr, m_addr_rstr);
        } else {
            PRINT_ERR_HEAD;
            print_err("UDP socket[%d] = %d unknown = %d(%s), addr = %s,%s", m_domain, socket_r,
                      m_errno, strerror(m_errno), m_addr_lstr, m_addr_rstr);

            if ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK)) {
                //非阻塞模式
                m_errno = ESUSOCKET2;
            }
        }

    } else if (m_datamore) {
        //尽量一次多收数据
        PRINT_DBG_HEAD;
        print_dbg("more UDP socket[%d] = %d, addr = %s,%s, size = %d,%d", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr, readlen, size);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("UDP socket[%d] = %d, addr = %s,%s, size = %d,%d", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr, size, readlen);
    }

    return readlen;
}

/**
 * [CSYSSOCKET6::readsocket description]
 * @param  data [description]
 * @param  size [description]
 * @return      [description]
 */
#ifndef __CYGWIN__
int32 CSYSSOCKET6::readsocket(void *data, const int32 size)
{
    if ((data == NULL) || (size <= 0))    return -1;

    SYSSOCKET socket_r = getsocket();
    int32 readlen = -1, size_en = size;
    if (socket_r == SOCKET_ERR) return -1;

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
    m_errno = 0;
    switch (m_type) {
    case SOCKET_TCP:
        readlen = readtcp(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en);
        break;
    case SOCKET_UDP:
        readlen = readudp(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en);
        break;
    }

    //解密数据
    if (m_encode && (readlen > 0)) {

        readlen = dataencode(m_pdata, readlen, (puint8)data, true);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("read socket[%d] = %d, addr = %s,%s, size %d -> %d(%s)", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr, size_en, readlen, printbuf(data, readlen));
#endif
    }

    datafree();

    return readlen;
}
#else
//超时问题，通过select处理
int32 CSYSSOCKET6::readsocket(void *data, const int32 size)
{
    if ((data == NULL) || (size <= 0))    return -1;

    SYSSOCKET socket_r = getsocket();
    int32 readlen = -1, size_en = size;
    if (socket_r == SOCKET_ERR) return -1;

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
    struct timeval tmout;
    int test = 0;
    fd_set fds;
    tmout.tv_sec = m_timeout / 1000;
    tmout.tv_usec = 0;

    m_errno = 0;
    if (is_strempty(m_addr_rstr)) {
        ssaddr_t ip;
        uint16 port;
        getaddress(&ip, &port, false, m_addr_rstr);
    }
    //超时处理
_recvagain:
    FD_ZERO(&fds);
    FD_SET(socket_r, &fds);
    if ((test = select(socket_r + 1, &fds, NULL, NULL, &tmout)) < 0) {
        m_errno = errno;
        if (m_errno == EINTR) goto _recvagain;
        PRINT_ERR_HEAD;
        print_err("read socket[%d] = %d unknown = %d(%s), addr = %s,%s", m_domain, socket_r,
                  m_errno, strerror(m_errno), m_addr_lstr, m_addr_rstr);
        goto _recvend;
    } else if (test == 0) {
        PRINT_DBG_HEAD;
        print_dbg("read socket[%d] = %d timeout, addr = %s,%s", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr);
        goto _recvend;
    } else if (!FD_ISSET(socket_r, &fds)) {
        PRINT_ERR_HEAD;
        print_err("read socket[%d] = %d timeout, addr = %s,%s", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr);
        goto _recvend;
    }

    if (readlen == -1) readlen = 0;
    switch (m_type) {
    case SOCKET_TCP: {
        bool bbak = m_datamore;
        m_datamore = false;
        int i = readtcp(socket_r, ((m_pdata != NULL) ? m_pdata + readlen : (puint8)data + readlen), size_en - readlen);
        m_datamore = bbak;
        if (i > 0) {
            readlen += i;
            if (m_datamore) goto _recvagain;
        }
    }
    break;
    case SOCKET_UDP:
        readlen = readudp(socket_r, ((m_pdata != NULL) ? m_pdata : data), size_en);
        break;
    }

    //解密数据
    if (m_encode && (readlen > 0)) {
        readlen = dataencode(m_pdata, readlen, (puint8)data, true);
#if __DEBUG_MORE__
        PRINT_DBG_HEAD;
        print_dbg("read socket[%d] = %d, addr = %s,%s, size %d -> %d(%s)", m_domain, socket_r,
                  m_addr_lstr, m_addr_rstr, size_en, readlen, printbuf(data, readlen));
#endif
    }

_recvend:
    datafree();
    return readlen;
}
#endif

/**
 * [CSYSSOCKET6::writesocket description]
 * @param  data [description]
 * @param  size [description]
 * @return      [description]
 */
int32 CSYSSOCKET6::writesocket(const void *data, const int32 size)
{
    if ((data == NULL) || (size <= 0))   return -1;

    SYSSOCKET socket_w = getsocket();
    int32 writelen = -1, size_en = size;
    int32 writeoffset = 0;
    if (socket_w == SOCKET_ERR) return -1;

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
    }

    //开始发送
    m_errno = 0;
    int32 errorcnt_w = 5; //防止重试写deadloop
    if (size_en != -1) {
_sendagain:
        writelen = -1;
        switch (m_type) {
        case SOCKET_TCP:
            writelen = send(socket_w, ((m_pdata != NULL) ? m_pdata + writeoffset : ((const puint8)data) + writeoffset),
                            size_en - writeoffset, 0);
            break;
        case SOCKET_UDP:
            writelen = sendto(socket_w, ((m_pdata != NULL) ? m_pdata + writeoffset : ((const puint8)data) + writeoffset),
                              size_en - writeoffset, 0, (struct sockaddr *)&m_ssaddr, sizeof(m_ssaddr.in6));
            break;
        }

        if (is_strempty(m_addr_lstr)) {
            ssaddr_t ip;
            uint16 port;
            getaddress(&ip, &port, true, m_addr_lstr)
            PRINT_DBG_HEAD;
            print_dbg("write socket[%d] info %s", m_domain, m_addr_lstr);
        }

        if (writelen == -1) {
            m_errno = errno;

            PRINT_ERR_HEAD;
            print_err("write socket[%d] = %d, addr = %s,%s, size %d -> %d, (%d:%s), retry = %d",
                      m_domain, socket_w, m_addr_lstr, m_addr_rstr,
                      size_en - writeoffset, writelen, m_errno, strerror(m_errno), errorcnt_w);
            if ((m_errno == ENOBUFS) || (m_errno == EINTR)) {
                usleep(10);
                if (--errorcnt_w > 0) goto _sendagain;
            }

            if (/*!m_fcntl &&*/ ((m_errno == EAGAIN) || (m_errno == EWOULDBLOCK))) {

                usleep(10);
                if (--errorcnt_w > 0) goto _sendagain;
            }

            PRINT_ERR_HEAD;
            print_err("write socket[%d] = %d, addr = %s,%s, size %d -> %d, (%d:%s), retry = %d",
                      m_domain, socket_w, m_addr_lstr, m_addr_rstr,
                      size_en, writeoffset, m_errno, strerror(m_errno), errorcnt_w);

        } else if (writelen != (size_en - writeoffset)) {
            m_errno = 0;
            PRINT_DBG_HEAD;
            print_dbg("write socket[%d] = %d, addr = %s,%s, size %d -> %d, retry = %d",
                      m_domain, socket_w, m_addr_lstr, m_addr_rstr, size_en - writeoffset, writelen, errorcnt_w);
            if (writelen > 0) writeoffset += writelen;

            if (--errorcnt_w > 0) goto _sendagain;

            PRINT_ERR_HEAD;
            print_err("write socket[%d] = %d, addr = %s,%s, size %d -> %d, retry = %d",
                      m_domain, socket_w, m_addr_lstr, m_addr_rstr, size_en, writeoffset, errorcnt_w);

        } else {
            writeoffset = size_en;
        }
    }

    datafree();

    if ((writelen < 0) && (writeoffset == 0)) {
        writeoffset = -1;
        PRINT_ERR_HEAD;
        print_err("write socket[%d] = %d, addr = %s,%s, size %d -> %d",
                  m_domain, socket_w, m_addr_lstr, m_addr_rstr, size, writeoffset);
    } else {
        PRINT_DBG_HEAD;
        print_dbg("write socket[%d] = %d, addr = %s,%s, size = %d,%d",
                  m_domain, socket_w, m_addr_lstr, m_addr_rstr, size, writeoffset);
    }

    return writeoffset;
}

/**
 * [CSYSSOCKET6::set6only 需要在createsocket后调用]
 * @param  flag [true：打开,默认关闭]
 * @return      [description]
 */
bool CSYSSOCKET6::set6only(bool flag)
{
    //区分IPV4,主要解决监听相同端口问题
    int _on = flag ? 1 : 0;
    if (setsockopt(getsocket(), IPPROTO_IPV6, IPV6_V6ONLY, &_on, sizeof(_on)) < 0) {
        m_errno = errno;

        PRINT_ERR_HEAD;
        print_err("socket[%d] ipv6 only %d(%s)", m_domain, m_errno, strerror(m_errno));
        return false;
    }

    return true;
}
