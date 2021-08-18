/******************************************************************
** 文件名: crt.h
** Copyright (c) 2005

** 创建人:黄勇
** 日  期:2005-2-20
** 修改人:
** 日  期:
** 描  述:B/S通讯类
**
** 版  本:V1.1
*******************************************************************/
#ifndef __CRT_H__
#define __CRT_H__

#ifndef UNIX
#define UNIX
#endif

const int E_SOCK_OK = 1;
const int E_SOCK_FALSE = -1;

#ifdef UNIX
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

/* 热备自定义以太网协议 ID */
#define ETH_P_HOTBAK          0X0801

//服务、客服通讯Tcp SOCK 服务端
class SockServer
{
public:
    int Open(char *eth, bool isall); //打开初始化服务
    int Send(unsigned char *p_uchBuff, int iBuffLen); //发送数据
    int Recv(unsigned char *p_uchBuff, int iBuffLen); //接收数据
    int Close(); //关闭通讯
private:
    struct sockaddr_ll sa;
    struct sockaddr_ll sa_send;
    struct sockaddr_ll sa_recv;
    socklen_t s;
    int ser_sock;//服务套接字
};

#endif
