/*******************************************************************************************
*文件:  FCMulticast.h
*描述:  组播任务类
*作者:  王君雷
*日期:  2016-03
*修改:
*        支持ASM、SSM、SFM三种类型的组播                             ------> 2018-01-29
*        使用Multicast代替汉语拼音                                   ------> 2018-02-05
*        发送出去的组播报文设置TTL为64，设置禁止本地自环             ------> 2018-03-04
*        添加函数setBindToDevice，只接收指定网口的组播信息           ------> 2018-10-29
*        FSM修正为SFM,相关限制宏移动到critical.h中                   ------> 2018-12-21
*       安全通道使用SEC_WAY类                                        ------> 2019-01-02
*       组播支持IPV6                                                 ------> 2019-06-24
*       组播每间隔30s记录一次访问日志                                ------> 2019-09-02
*       支持分模块生效                                              ------> 2020-11-12
*******************************************************************************************/
#ifndef __FC_MULTICAST_H__
#define __FC_MULTICAST_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include "define.h"
#include "secway.h"
#include "datatype.h"
#include "quote_global.h"

#define MULTICAST_TTL_VAL 64
#define MULTICAST_HOPS_VAL MULTICAST_TTL_VAL
#define MULTICAST_LOG_CYCLE 30 //每多少秒 记录一次访问日志
#define MULTICAST_NAT_START_PORT 41000

enum {
    MULTICAST_UNKNOWN = -1,
    MULTICAST_ASM = 0, //任意信源组播
    MULTICAST_SSM = 1, //指定信源组播
    MULTICAST_SFM = 2, //过滤信源组播
};

bool IfMulticastIP(const char *ip);
bool IfMulticastIPV4(const char *ip);
bool IfMulticastIPV6(const char *ip);

class CMulticastTask
{
public:
    CMulticastTask(int taskid);
    virtual ~CMulticastTask(void);

    bool startMulticastTask(bool issrc);
    static bool setTTL(int fd, unsigned char ttlval);
    static bool setHops(int fd, int hops);
    static bool setLoop(int fd, bool ifloop, bool ipv6 = false);
    static bool setBindToDevice(int fd, const char *device);
    void setTmpIP(const char *ip);
    bool configCheck(void);
    int getSrcDev(void);
    int getDstDev(void);
    int getArea(void);
    unsigned int getSrcIfIndex(void);
    unsigned int getDstIfIndex(void);
    void increaseThread(void);
    void reduceThread(void);
    void stop(void);
    bool getStop(void);

private:
    static void *mcRecv(void *param);
    static void *mcSend(void *param);
    static void *mcStatistics(void *param);
    bool joinMembership(int fd);
    bool joinMembershipASM(int fd);
    bool joinMembershipASMIPV6(int fd);
    bool joinMembershipSSM(int fd);
    bool joinMembershipSFM(int fd);
    static int udpSocketBind(const char *ip, int port);
    static bool fillAddr(const char *ip, int port, struct sockaddr_storage &addr, int &addrlen);
    bool setSourceOpt6(int fd);
    void setOutputCard(void);
    void setInputCard(void);

public:
    char m_name[MULTICAST_RULE_NAME_LEN];
    SEC_WAY m_secway;
    char m_srcmulticastip[IP_STR_LEN];
    char m_srcport[PORT_STR_LEN];
    char m_recvip[IP_STR_LEN];
    char m_dstmulticastip[IP_STR_LEN];
    char m_dstport[PORT_STR_LEN];
    char m_sendip[IP_STR_LEN];

    int m_type;
    int m_srcnum;
    char m_srcip[MULTICAST_MAX_SRC_NUM][IP_STR_LEN];

    uint32 m_packetcnt;//转发包计数
    sem_t m_packetsem; //用户互斥访问m_packetcnt的锁

private:
    int m_taskid;
    sem_t m_threadnum;//本任务启动的线程个数
    bool m_stop;
    char m_tmpip[IP_STR_LEN];
    char m_tmpport[PORT_STR_LEN];
};

class MulticastMG
{
public:
    MulticastMG(void);
    virtual ~MulticastMG(void);
    int loadConf(void);
    void clear(void);
    int taskNum(void);
    void setTransparentIptables(void);
    void clearTransparentIptables(void);
    bool setTmpIP(int innum, int outnum);
    void run(void);

private:
    CMulticastTask *addTask(void);
    bool setTmpIP(void);

private:
    int m_task_num;
    char m_in_tmpip[IP_STR_LEN];
    char m_out_tmpip[IP_STR_LEN];
    CMulticastTask *m_task[C_MUTICAST_MAXNUM];
};

#endif
