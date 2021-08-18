/*******************************************************************************************
*文件:  FCMainRecv.h
*描述:  主接收进程类
*作者:  王君雷
*日期:  2016-03
*修改:
*         成员函数命名统一风格                                          ------> 2018-04-11
*         把MainRecvUdp拆分为10多个函数，减少函数体大小;
*         命令代理服务移动到本程序中                                    ------> 2018-11-28
*         可以处理DEV_ID_SYNC类型请求                                   ------> 2020-02-14
*         添加HandleSend函数                                            ------> 2020-02-20
*******************************************************************************************/
#ifndef __FC_MAIN_RECV_H__
#define __FC_MAIN_RECV_H__

#include <map>
#include <string>
using namespace std;
#include "define.h"
#include "struct_info.h"
#include "FCLogManage.h"

//主接收进程类
//网闸间通信内部命令由该进程接收处理
class CMainRecv
{
public:
    CMainRecv(int ipseg = 1, int port = DEFAULT_LINK_PORT);
    virtual ~CMainRecv(void);
    int MainRecvUdp(void);

private:
    int m_linkipseg;
    int m_linkport;
    CLOGMANAGE m_log;
    int m_recvfd;
    map<string, int> m_mapfd;

private:
    static int WriteVersion(const char *vername, int len);
    static void CheckMysql(void);
    static void InitClean(void);
    static bool IsRuleFile(const char *filename);

    int ConnectToApp(const char *ip_rule_app);
    void SetSocket(void);
    void CloseMapConnect(void);
    bool DoLogInfo(const char *sqlbuf);
    void HandleLog(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleSyncTime(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleSyncMicroTime(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleGetTime(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleSysInit(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleDevRestart(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleCmdProxy(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleCmdExec(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleVersionSync(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleGetFile(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleGetOutMac(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleGetCardStatus(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleGetLocalIP(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleDevIDSync(const char *buff, int len, int fd, struct sockaddr_in *paddr, socklen_t addrlen);

    void HandleEndOfFile(int localfd, bool isrulefile, struct sockaddr_in *paddr, socklen_t addrlen);
    void HandleFileTransfer(const char *buff, unsigned int length, HEADER &header, bool &isrulefile,
                            struct sockaddr_in *paddr, socklen_t addrlen);
    int HandleSend(int fd, const char *buff, unsigned int len);
};

#endif
