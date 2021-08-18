/*******************************************************************************************
*文件:  fcpacket.h
*描述:  热备通信类
*作者:  王君雷
*日期:  2016-03
*修改:
*       统一成员变量的名称、删除没使用的成员变量                      ------> 2018-12-07
*       添加通过HA工具恢复用户配置功能                               ------> 2020-09-28
*       通过构造函数可以设置是否接收全部协议包                        ------> 2021-04-07
*******************************************************************************************/
#ifndef __FC_PACKET_H__
#define __FC_PACKET_H__

#include <netpacket/packet.h>
#include <net/ethernet.h>

#define MAX_PKTSIZE           65535

/* 热备自定义以太网协议 ID */
#define ETH_P_HOTBAK          0X0801

enum {
    C_SERCHDEV = 1,   //1
    C_INITDEV,        //2
    C_HEARTBEAT,      //3
    C_DEVID,          //4
    C_HEARTBEAT_RES,  //5
    C_GET_RULES,      //6
    C_RULES_FILE,     //7
    C_GETCTRL,        //8
    C_CTRL_INFO,      //9
    C_GETINFO,        //10
    C_INFO,           //11
    C_INIT_USERCONF,  //12
    C_INIT_USERCONF_RES, //13
};

typedef struct OPACKET {
    unsigned char DMac[6];
    unsigned char SMac[6];
    unsigned char BZType[2];
    unsigned char OType[2];
    unsigned char CType;
    unsigned char CKind;   //指令类型
    unsigned char CSum[2];
    unsigned char CSize[4];
} OPACKET, *POPACKET;

class CPACKET
{
public:
    CPACKET(int index, bool recvall, bool UseR = false, bool UseS = false);
    virtual ~CPACKET();

    int Open(const char *eth); //打开初始化服务
    int WritePacket(const unsigned char *p_uchBuff, int iBuffLen, unsigned char kind); //发送数据
    int ReadPacket(unsigned char *p_uchBuff, int *iBuffLen, unsigned char &kind); //接收数据
    int Close(); //关闭通讯
    int SetRecvTimeOut(int sec = 1);
private:
    void SetRecvAll(bool flag);

private:
    bool m_recv_all;//是否接收所有包
    struct sockaddr_ll m_sa;
    int m_sock;//服务套接字
    unsigned char m_peerMac[6];//设备初始化客户端MAC
    unsigned char m_masterMac[6];//上级主设备MAC
    unsigned char m_slaveMac[6];//下级从设备MAC
    unsigned char m_localMac[6];
};

#endif
