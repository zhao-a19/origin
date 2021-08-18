/*******************************************************************************************
*文件:  FCBSTX.cpp
*描述:  TCP UDP 通信封装
*作者:  黄勇
*日期:  2004
*
*修改:
*       UDP客户端也可以bind自己的地址端口                             ------> 2018-07-30
*       UDP客户端支持使用IPv6                                         ------> 2019-02-12
*       UDP send接口支持IPV6                                          ------> 2019-03-05
*       全部支持IPV6                                                  ------> 2019-03-18 王君雷
*       Connect写zlog前保存errno 写完后恢复errno                      ------> 2019-04-12
*       解决TCP客户端类connect服务器失败时没有关闭描述符的BUG         ------> 2020-11-30
*******************************************************************************************/
#include "FCBSTX.h"
#include "debugout.h"
#include "stringex.h"
#include "define.h"

CBSTX::CBSTX(void)
{
    m_bipv6 = false;
}

CBSTX::~CBSTX(void)
{
}

/**
 * [CBSTX::SetReuseAddr 使用setsockopt函数设置地址重用]
 * @param  fd [描述符]
 * @return    [成功返回0]
 */
int CBSTX::SetReuseAddr(int fd)
{
    int dwyes = 1;
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&dwyes, sizeof(dwyes));
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("set reuse addr fail[%s]", strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * [CBSTX::SetRecvBuffLen 使用setsockopt函数设置接收缓冲区长度]
 * @param  fd   [描述符]
 * @param  rlen [接收缓冲区长度]
 * @return      [成功返回0]
 */
int CBSTX::SetRecvBuffLen(int fd, int rlen)
{
    int ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&rlen, sizeof(int));
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("set recvbuff len fail.rlen[%d],errinfo[%s]", rlen, strerror(errno));
        return -1;
    }
    return ret;
}

/**
 * [CBSTX::IsIPv6 当前的socket是否为ipv6类型的]
 * @return  [description]
 */
bool CBSTX::IsIPv6(void)
{
    return m_bipv6;
}

CBSTcpSockServer::CBSTcpSockServer(void)
{
    m_sersock = -1;
}

CBSTcpSockServer::~CBSTcpSockServer(void)
{
    Close();
}

/**
 * [CBSTcpSockServer::Open 监听地址端口]
 * @param  ipstr [IP地址]
 * @param  port  [端口]
 * @return       [成功返回监听描述符 失败返回负值]
 */
int CBSTcpSockServer::Open(const char *ipstr, int port)
{
    if ((ipstr == NULL) || (port <= 0) || (port > 65535)) {
        PRINT_ERR_HEAD
        print_err("tcp sock server open para err.ip[%s]port[%d]", ipstr, port);
        return -1;
    }

    //如果已经打开过就先关闭掉
    CLOSE(m_sersock);
    m_bipv6 = is_ip6addr(ipstr);

    //填充地址结构
    BZERO(m_servaddr);
    BZERO(m_servaddr6);
    if (m_bipv6) {
        m_servaddr6.sin6_family = AF_INET6;
        m_servaddr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ipstr, &m_servaddr6.sin6_addr) <= 0) {
            PRINT_ERR_HEAD
            print_err("tcp sock server inet_pton fail.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                      strerror(errno));
            return -1;
        }
    } else {
        m_servaddr.sin_family = AF_INET;
        m_servaddr.sin_port = htons(port);
        m_servaddr.sin_addr.s_addr = inet_addr(ipstr);
    }

    //socket
    m_sersock = socket(m_bipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (m_sersock < 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock server socket err.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                  strerror(errno));
        return -1;
    }

    //setsockopt
    int ret = SetReuseAddr(m_sersock);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock reuseaddr fail. ip[%s]port[%d]sock[%d]ret[%d]errinfo[%s]",
                  ipstr, port, m_sersock, ret, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    //bind
    if (m_bipv6) {
        ret = bind(m_sersock, (struct sockaddr *)(&m_servaddr6), sizeof(m_servaddr6));
    } else {
        ret = bind(m_sersock, (struct sockaddr *)(&m_servaddr), sizeof(m_servaddr));
    }
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock bind err.ip[%s]port[%d]errinfo[%s]", ipstr, port, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    //listern
    ret = listen(m_sersock, 1000);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock listen err.ip[%s]port[%d]errinfo[%s]", ipstr, port, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("tcp sock listen %s ok.ip[%s]port[%d]sock[%d]", m_bipv6 ? "ipv6" : "ipv4", ipstr, port,
              m_sersock);
    return m_sersock;
}

/**
 * [CBSTcpSockServer::StartServer 接收客户端的连接]
 * @return [返回接收后的客户端描述符]
 */
int CBSTcpSockServer::StartServer(void)
{
    int new_sock = accept(m_sersock, NULL, NULL);
    if (new_sock == -1) {
        PRINT_ERR_HEAD
        print_err("tcp sock accept error.listensock[%d]errinfo[%s]", m_sersock, strerror(errno));
    } else {
        PRINT_DBG_HEAD
        print_dbg("tcp sock accept one client.listensock[%d] newsock[%d]", m_sersock, new_sock);
    }
    return new_sock;
}

/**
 * [CBSTcpSockServer::Close 关闭监听描述符]
 * @return [成功返回0]
 */
int CBSTcpSockServer::Close(void)
{
    if (m_sersock > 0) {
        PRINT_INFO_HEAD
        print_info("tcp sock server close m_sersock %d", m_sersock);
        close(m_sersock);
        m_sersock = -1;
    }
    return 0;
}

/**
 * [CBSTcpSockServer::Recv 接收客户端发来的数据]
 * @param  sock    [accept接收客户端连接后得到的描述符]
 * @param  buff    [缓冲区]
 * @param  bufflen [缓冲区长度]
 * @return         [成功返回读取到的长度 失败返回负值]
 */
int CBSTcpSockServer::Recv(int sock, unsigned char *buff, int bufflen)
{
    if ((sock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("tcp sock server recv para err.sock[%d] bufflen[%d]", sock, bufflen);
        return -1;
    }

    int recvlen = recv(sock, buff, bufflen, 0);
    if (recvlen <= 0) {
        PRINT_ERR_HEAD
        print_err("recv sock[%d]. recvlen %d.peer may close", sock, recvlen);
    }
    return recvlen;
}

/**
 * [CBSTcpSockServer::Send 向客户端发送数据]
 * @param  sock    [accept接收客户端连接后得到的描述符]
 * @param  buff    [缓冲区]
 * @param  bufflen [缓冲区长度]
 * @return         [成功返回发送的长度 失败返回负值]
 */
int CBSTcpSockServer::Send(int sock, const unsigned char *buff, int bufflen)
{
    if ((sock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("tcp sock server send para err.sock[%d] bufflen[%d]", sock, bufflen);
        return -1;
    }
    int sendlen = send(sock, buff, bufflen, 0);
    if (sendlen <= 0) {
        PRINT_ERR_HEAD
        print_err("send sock[%d]. sendlen %d.peer may close", sock, sendlen);
    }
    return sendlen;
}

CBSTcpSockClient::CBSTcpSockClient(void)
{
}

CBSTcpSockClient::~CBSTcpSockClient(void)
{
}

/**
 * [CBSTcpSockClient::Open 连接服务]
 * @param  ipstr [地址]
 * @param  port  [端口]
 * @param  noblock [是否非阻塞方式去连接]
 * @return       [成功返回连接上之后的描述符]
 */
int CBSTcpSockClient::Open(const char *ipstr, int port, bool noblock)
{
    int sock = CreateSock(ipstr, port, noblock);
    if (sock < 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock open create sock fail.ret[%d]", sock);
        return sock;
    }
    int ret = Connect(sock);
    if (ret < 0) {
        close(sock);
    }
    return ret;
}

/**
 * [CBSTcpSockClient::CreateSock 创建socket]
 * @param  ipstr [IP]
 * @param  port  [端口]
 * @param  noblock [是否非阻塞方式]
 * @return       [成功返回描述符 失败返回负值]
 */
int CBSTcpSockClient::CreateSock(const char *ipstr, int port, bool noblock)
{
    if ((ipstr == NULL) || (port <= 0) || (port > 65535)) {
        PRINT_ERR_HEAD
        print_err("tcp sock client createsock para err.ip[%s]port[%d]", ipstr, port);
        return -1;
    }

    m_bipv6 = is_ip6addr(ipstr);

    //填充地址结构
    BZERO(m_toaddr);
    BZERO(m_toaddr6);
    if (m_bipv6) {
        m_toaddr6.sin6_family = AF_INET6;
        m_toaddr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ipstr, &m_toaddr6.sin6_addr) <= 0) {
            PRINT_ERR_HEAD
            print_err("tcp sock client inet_pton fail.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                      strerror(errno));
            return -1;
        }
    } else {
        m_toaddr.sin_family = AF_INET;
        m_toaddr.sin_port = htons(port);
        m_toaddr.sin_addr.s_addr = inet_addr(ipstr);
    }

    //socket
    int sock = socket(m_bipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PRINT_ERR_HEAD
        print_err("tcp sock client socket err.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                  strerror(errno));
        return -1;
    }
    if (noblock) {
        fcntl(sock, F_SETFL, O_NONBLOCK);
        PRINT_DBG_HEAD
        print_dbg("sock[%d] nonblock. %s", sock, m_bipv6 ? "ipv6" : "ipv4");
    }

    PRINT_DBG_HEAD
    print_dbg("craete sock ok.ip[%s]port[%d]sock[%d] %s", ipstr, port, sock, m_bipv6 ? "ipv6" : "ipv4");
    return sock;
}

/**
 * [CBSTcpSockClient::Connect 使用已经创建好的socket去连接服务器]
 * @param clisock [客户端socket描述符]
 * @return  [连接成功返回描述符 失败返回负值]
 */
int CBSTcpSockClient::Connect(int clisock)
{
    //connect
    int ret = 0;
    if (m_bipv6) {
        ret = connect(clisock, (struct sockaddr *)&m_toaddr6, sizeof(m_toaddr6));
    } else {
        ret = connect(clisock, (struct sockaddr *)&m_toaddr, sizeof(m_toaddr));
    }

    if (ret != 0) {
        int bakno = errno;
        PRINT_ERR_HEAD
        print_err("tcp sock client connect fail.clisock[%d]errinfo[%s]", clisock, strerror(errno));
        errno = bakno;
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("tcp sock client connect ok.sock[%d]", clisock);
    return clisock;
}

/**
 * [CBSTcpSockClient::Send 发送数据]
 * @param  sock    [connect服务器之后返回的描述符]
 * @param  buff    [待发送数据]
 * @param  bufflen [数据长度]
 * @return         [成功返回发送的数目 失败返回负值]
 */
int CBSTcpSockClient::Send(int sock, const unsigned char *buff, int bufflen)
{
    if ((sock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("tcp sock client send para err.sock[%d] bufflen[%d]", sock, bufflen);
        return -1;
    }
    int sendlen = send(sock, buff, bufflen, 0);
    if (sendlen <= 0) {
        PRINT_ERR_HEAD
        print_err("send sock[%d]. sendlen %d.peer may close", sock, sendlen);
    }
    return sendlen;
}

/**
 * [CBSTcpSockClient::Recv 接收数据]
 * @param  sock    [connect服务器之后返回的描述符]
 * @param  buff    [缓冲区]
 * @param  bufflen [缓冲区长度]
 * @return         [成功返回读取到的长度 失败返回负值]
 */
int CBSTcpSockClient::Recv(int sock, unsigned char *buff, int bufflen)
{
    if ((sock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("tcp sock client recv para err.sock[%d] bufflen[%d]", sock, bufflen);
        return -1;
    }

    int recvlen = recv(sock, buff, bufflen, 0);
    if (recvlen <= 0) {
        PRINT_ERR_HEAD
        print_err("recv sock[%d]. recvlen %d.peer may close", sock, recvlen);
    }
    return recvlen;
}

CBSUdpSockServer::CBSUdpSockServer(void)
{
    m_sersock = -1;
}

CBSUdpSockServer::~CBSUdpSockServer(void)
{
    //此处不要调用Close()
}

/**
 * [CBSUdpSockServer::Open UDP服务器绑定接收地址]
 * @param  ipstr [IP]
 * @param  port  [端口]
 * @return       [成功返回接收描述符 失败返回负值]
 */
int CBSUdpSockServer::Open(const char *ipstr, int port)
{
    if ((ipstr == NULL) || (port <= 0) || (port > 65535)) {
        PRINT_ERR_HEAD
        print_err("udp sock server open para err.ip[%s]port[%d]", ipstr, port);
        return -1;
    }

    Close();
    m_bipv6 = is_ip6addr(ipstr);

    //填充地址结构
    BZERO(m_servaddr);
    BZERO(m_servaddr6);
    if (m_bipv6) {
        m_servaddr6.sin6_family = AF_INET6;
        m_servaddr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ipstr, &m_servaddr6.sin6_addr) <= 0) {
            PRINT_ERR_HEAD
            print_err("udp sock server inet_pton fail.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                      strerror(errno));
            return -1;
        }
    } else {
        m_servaddr.sin_family = AF_INET;
        m_servaddr.sin_port = htons(port);
        m_servaddr.sin_addr.s_addr = inet_addr(ipstr);
    }

    //socket
    m_sersock = socket(m_bipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (m_sersock < 0) {
        PRINT_ERR_HEAD
        print_err("udp sock server socket err.ip[%s]port[%d]errinfo[%s]", ipstr, port, strerror(errno));
        return -1;
    }

    //setsockopt recv buf len
    int ret = SetRecvBuffLen(m_sersock);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("udp sock server set recvbuff len fail. ip[%s]port[%d]sock[%d]ret[%d]errinfo[%s]",
                  ipstr, port, m_sersock, ret, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    //setsockopt reuse addr
    ret = SetReuseAddr(m_sersock);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("udp sock server reuseaddr fail. ip[%s]port[%d]sock[%d]ret[%d]errinfo[%s]",
                  ipstr, port, m_sersock, ret, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    //bind
    if (m_bipv6) {
        ret = bind(m_sersock, (struct sockaddr *)(&m_servaddr6), sizeof(m_servaddr6));
    } else {
        ret = bind(m_sersock, (struct sockaddr *)(&m_servaddr), sizeof(m_servaddr));
    }
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("udp sock bind err.ip[%s]port[%d]errinfo[%s]", ipstr, port, strerror(errno));
        CLOSE(m_sersock);
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("udp sock server open ok.ip[%s]port[%d]sersock[%d]", ipstr, port, m_sersock);
    return m_sersock;
}

/**
 * [CBSUdpSockServer::Close 关闭接收描述符]
 * @return  [成功返回0]
 */
int CBSUdpSockServer::Close(void)
{
    if (m_sersock > 0) {
        PRINT_INFO_HEAD
        print_info("udp server close sersock[%d]", m_sersock);
        close(m_sersock);
    }
    m_sersock = -1;
    return 0;
}

/**
 * [CBSUdpSockServer::Recv 接收数据]
 * @param  buff    [缓冲区]
 * @param  bufflen [缓冲区长度]
 * @return         [成功返回接收的长度 失败返回负值]
 */
int CBSUdpSockServer::Recv(unsigned char *buff, int bufflen)
{
    if ((m_sersock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("udp sock server recv para err.sock[%d] bufflen[%d]", m_sersock, bufflen);
        return -1;
    }

    int ret = 0;
    socklen_t socklen = 0;

    if (m_bipv6) {
        socklen = sizeof(m_cliaddr6);
        ret = recvfrom(m_sersock, buff, bufflen, 0, (struct sockaddr *)&m_cliaddr6, &socklen);
    } else {
        socklen = sizeof(m_cliaddr);
        ret = recvfrom(m_sersock, buff, bufflen, 0, (struct sockaddr *)&m_cliaddr, &socklen);
    }
    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("recvfrom fail.ret[%d] errinfo[%s]", ret, strerror(errno));
    }

    PRINT_DBG_HEAD
    print_dbg("udp server recv ok, rlen %d, socklen %d, %s", ret, socklen, m_bipv6 ? "ipv6" : "ipv4");
    return ret;
}

/**
 * [CBSUdpSockServer::Send 发送数据]
 * @param  buff    [发送缓冲区]
 * @param  bufflen [待发送的数据长度]
 * @return         [成功返回发送的长度 失败返回负值]
 */
int CBSUdpSockServer::Send(const unsigned char *buff, int bufflen)
{
    if ((m_sersock <= 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("udp sock server send para err.sock[%d] bufflen[%d]", m_sersock, bufflen);
        return -1;
    }

    int ret = -1;
    if (m_bipv6) {
        ret = sendto(m_sersock, buff, bufflen, 0, (struct sockaddr *)&m_cliaddr6, sizeof(m_cliaddr6));
    } else {
        ret = sendto(m_sersock, buff, bufflen, 0, (struct sockaddr *)&m_cliaddr, sizeof(m_cliaddr));
    }

    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("sendto fail. %s. ret[%d] errinfo[%s]", m_bipv6 ? "ipv6" : "ipv4",
                  ret, strerror(errno));
    }
    return ret;
}

CBSUdpSockClient::CBSUdpSockClient(void)
{
    m_clisock = -1;
}

CBSUdpSockClient::~CBSUdpSockClient(void)
{
    //此处不要调用Close()
}

/**
 * [CBSUdpSockClient::Open UDP客户端 创建socket]
 * @param  ipstr [IP]
 * @param  port  [端口]
 * @return       [成功返回描述符 失败返回负值]
 */
int CBSUdpSockClient::Open(const char *ipstr, int port)
{
    if ((ipstr == NULL) || (port <= 0) || (port > 65535)) {
        PRINT_ERR_HEAD
        print_err("udp sock client open para err.ip[%s]port[%d]", ipstr, port);
        return -1;
    }

    Close();
    m_bipv6 = is_ip6addr(ipstr);

    //填充地址结构
    BZERO(m_toaddr);
    BZERO(m_toaddr6);
    if (m_bipv6) {
        m_toaddr6.sin6_family = AF_INET6;
        m_toaddr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ipstr, &m_toaddr6.sin6_addr) <= 0) {
            PRINT_ERR_HEAD
            print_err("udp sock client inet_pton fail.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                      strerror(errno));
            return -1;
        }
    } else {
        m_toaddr.sin_family = AF_INET;
        m_toaddr.sin_port = htons(port);
        m_toaddr.sin_addr.s_addr = inet_addr(ipstr);
    }

    //socket
    m_clisock = socket(m_bipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (m_clisock < 0) {
        PRINT_ERR_HEAD
        print_err("udp sock client socket err.ip[%s]port[%d]errinfo[%s]", ipstr, port,
                  strerror(errno));
        return -1;
    }

    PRINT_DBG_HEAD
    print_dbg("udp sock client open ok.ip[%s]port[%d]clisock[%d]", ipstr, port, m_clisock);
    return m_clisock;
}

/**
 * [CBSUdpSockClient::Close 关闭描述符]
 * @return  [成功返回0]
 */
int CBSUdpSockClient::Close(void)
{
    if (m_clisock > 0) {
        PRINT_INFO_HEAD
        print_info("udp client close m_clisock[%d]", m_clisock);
        close(m_clisock);
    }
    m_clisock = -1;
    return 0;
}

/**
 * [CBSUdpSockClient::Bind 绑定地址端口]
 * @param  myport [本地端口]
 * @param  myip   [本地IP]
 * @return        [成功返回0]
 */
int CBSUdpSockClient::Bind(const char *myip, int myport)
{
    bool input_ipv6 = is_ip6addr(myip);
    int ret = -1;

    if (m_clisock <= 0) {
        PRINT_ERR_HEAD
        print_err("create socket first,and than bind ip port. m_clisock[%d]ip[%s]port[%d]", m_clisock,
                  myip, myport);
        return -1;
    }

    if ((input_ipv6 && m_bipv6)
        || ((!input_ipv6) && (!m_bipv6))) {
        if (m_bipv6) {
            sockaddr_in6 myaddr;
            myaddr.sin6_family = AF_INET6;
            myaddr.sin6_port = htons(myport);
            if (inet_pton(AF_INET6, myip, &myaddr.sin6_addr) <= 0) {
                PRINT_ERR_HEAD
                print_err("udp sock client bind inet_pton fail[%s] ip[%s]port[%d]",
                          strerror(errno), myip, myport);
                return -1;
            }

            ret = bind(m_clisock, (struct sockaddr *)(&myaddr), sizeof(myaddr));
            if (ret < 0) {
                PRINT_ERR_HEAD
                print_err("udp sock client bind fail[%s]ipv6[%s]port[%d]", strerror(errno), myip, myport);
            }
        } else {
            sockaddr_in myaddr;
            myaddr.sin_family = AF_INET;
            myaddr.sin_addr.s_addr = inet_addr(myip);
            myaddr.sin_port = htons(myport);
            ret = bind(m_clisock, (struct sockaddr *)(&myaddr), sizeof(myaddr));
            if (ret < 0) {
                PRINT_ERR_HEAD
                print_err("udp sock client bind fail[%s]ip[%s]port[%d]", strerror(errno), myip, myport);
            }
        }
    } else {
        PRINT_ERR_HEAD
        print_err("myip[%s] iptype error", myip);
    }
    return ret;
}

/**
 * [CBSUdpSockClient::Recv 接收信息]
 * @param  buff    [缓冲区]
 * @param  bufflen [缓冲区长度]
 * @return         [接收到的长度 失败返回负值]
 */
int CBSUdpSockClient::Recv(unsigned char *buff, int bufflen)
{
    if ((m_clisock < 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("udp sock client recv para err.m_clisock=%d, bufflen=%d", m_clisock, bufflen);
        return -1;
    }

    int ret = 0;
    ret = recvfrom(m_clisock, buff, bufflen, 0, NULL, NULL);
    return ret;
}

/**
 * [CBSUdpSockClient::Send 发送消息]
 * @param  buff    [发送缓冲区]
 * @param  bufflen [待发送长度]
 * @return         [成功返回发送的字节数 失败返回负值]
 */
int CBSUdpSockClient::Send(const unsigned char *buff, int bufflen)
{
    if ((m_clisock < 0) || (buff == NULL) || (bufflen <= 0)) {
        PRINT_ERR_HEAD
        print_err("udp sock client send para err.m_clisock=%d, bufflen=%d", m_clisock, bufflen);
        return -1;
    }

    int ret = -1;
    if (m_bipv6) {
        ret = sendto(m_clisock, buff, bufflen, 0, (struct sockaddr *)&m_toaddr6, sizeof(m_toaddr6));
    } else {
        ret = sendto(m_clisock, buff, bufflen, 0, (struct sockaddr *)&m_toaddr, sizeof(m_toaddr));
    }

    if (ret <= 0) {
        PRINT_ERR_HEAD
        print_err("sendto ret:%d, m_clisock:%d, err:%s", ret, m_clisock, strerror(errno));
    }
    return ret;
}
