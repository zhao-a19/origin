/*******************************************************************************************
*文件:  FCBSTX.h
*描述:  TCP UDP 通信封装
*作者:  黄勇
*日期:  2004
*
*修改:
*       UDP客户端也可以bind自己的地址端口                             ------> 2018-07-30
*       UDP客户端支持使用IPv6                                         ------> 2019-02-12
*       全部支持IPV6                                                  ------> 2019-03-18 王君雷
********************************************************************************************/
#ifndef __FC_BSTX_H__
#define __FC_BSTX_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

//基类
class CBSTX
{
public:
    CBSTX(void);
    virtual ~CBSTX(void);
    bool IsIPv6(void);

protected:
    int SetReuseAddr(int fd);
    int SetRecvBuffLen(int fd, int rlen = 32 * 1024);

protected:
    bool m_bipv6;
};

//TCP 服务端
class CBSTcpSockServer: public CBSTX
{
public:
    CBSTcpSockServer(void);
    virtual ~CBSTcpSockServer(void);

    int Open(const char *ipstr, int port);
    int StartServer(void);
    int Close(void);
    int Recv(int sock, unsigned char *buff, int bufflen);
    int Send(int sock, const unsigned char *buff, int bufflen);

private:
    int m_sersock;
    sockaddr_in m_servaddr;
    sockaddr_in6 m_servaddr6;
};

//TCP 客户端
class CBSTcpSockClient: public CBSTX
{
public:
    CBSTcpSockClient(void);
    virtual ~CBSTcpSockClient(void);
    int Open(const char *ipstr, int port, bool noblock = false);
    int CreateSock(const char *ipstr, int port, bool noblock = false);
    int Connect(int clisock);
    int Recv(int sock, unsigned char *buff, int bufflen);
    int Send(int sock, const unsigned char *buff, int bufflen);

private:
    sockaddr_in m_toaddr;
    sockaddr_in6 m_toaddr6;
};

//UDP 服务端
class CBSUdpSockServer: public CBSTX
{
public:
    CBSUdpSockServer(void);
    virtual ~CBSUdpSockServer(void);
    int Open(const char *ipstr, int port);
    int Close(void);
    int Recv(unsigned char *buff, int bufflen);
    int Send(const unsigned char *buff, int bufflen);

private:
    int m_sersock;
    sockaddr_in m_servaddr;
    sockaddr_in6 m_servaddr6;
    sockaddr_in m_cliaddr;
    sockaddr_in6 m_cliaddr6;
};

//UDP 客户端
class CBSUdpSockClient: public CBSTX
{
public:
    CBSUdpSockClient(void);
    virtual ~CBSUdpSockClient(void);

public:
    int Open(const char *ipstr, int port);
    int Send(const unsigned char *buff, int bufflen);
    int Recv(unsigned char *buff, int bufflen);
    int Close(void);
    int Bind(const char *myip, int myport);

private:
    int m_clisock;
    sockaddr_in m_toaddr;
    sockaddr_in6 m_toaddr6;
};

#endif
