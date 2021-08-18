/*******************************************************************************************
*文件: SipInterConnect.h
*描述: 平台互联
*作者: dzj
*日期: 2019-07-05
*修改:
*        添加设置媒体流为TCP时主动方向设置接口
         添加设置视频代理和级联靠近下级的媒体流iptables接口               ------> 2019-08-14
*        修改向通道结构写数据的接口，解决内存泄漏问题                     ------> 2019-08-20
*        解决传输媒体流时每次都使用同一端口问题                           ------> 2019-11-21
*        封装适配厂家接口                                                 ------> 2019-12-10
*******************************************************************************************/
#ifndef __SIP_INTER_CONNECT_H__
#define __SIP_INTER_CONNECT_H__

#include <semaphore.h>
#include "SipInterConnectBase.h"

#define SIP_INTER_CONNECT_MAX_CHANNEL  10000 //通道数
#define SIP_INTER_CONNECT_PORT_START   30000 //媒体代理端口 开始使用的第一个端口

class CSipInterConnect: public CSipInterConnectBase
{
protected:

public:
    CSipInterConnect(int taskid);
    virtual ~CSipInterConnect(void);
    virtual int initChannel(void);
    virtual void dstVideoPrepare();
    virtual void setMediaTransfer(int channel_id, bool tansfer);
    virtual void deleteChannelByCallID(const char *callid);
    virtual int getChannelProxyPort(SipInterConnect_INFO *sip_info, char *channelport);
private:
    bool needDealFactory();
    int getChannelProxyPortRequest(SipInterConnect_INFO *sip_info, char *channelport);
    int getChannelProxyPortRespons(SipInterConnect_INFO *sip_info, char *channelport);
    int getChannelProxyPortResponsInCenter(SipInterConnect_INFO *sip_info, char *channelport);
    int getChannelProxyPortResponsOutCenter(SipInterConnect_INFO *sip_info, char *channelport);
    int getSipInfoToChannel(int index, bool area, SipInterConnect_INFO *sip_info);
    void resetOneChannel(int chanid);
    int delOneChannel(int chanid);
    int addOneChannel(int chanid);
    int channelOper(int chanid, bool isadd);
    int handelChannel(int chanid, bool isadd, bool is_udp, const char *inmsport, const char *outmsport);
    void handelOutToInChannel(int chanid, char oper, const char *pro, const char *inmsport, const char *outmsport);
    void handelInToOutChannel(int chanid, char oper, const char *pro, const char *inmsport, const char *outmsport);
    void initLock(void);
    void destroyLock(void);
    void lock(void);
    void unlock(void);

private:
    int m_lastid;
    int m_max_channel;
    PSipInterConnectCHANNEL m_pchannel;
    sem_t m_lock;
};

#endif
