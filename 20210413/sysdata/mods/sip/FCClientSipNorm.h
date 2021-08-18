/*******************************************************************************************
*文件: FCClientSipNorm.h
*描述: 视频代理
*作者: 王君雷
*日期: 2018-04-12
*修改:
*         编码，通过多态，支持视频代理、视频代理联动                    ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*******************************************************************************************/
#ifndef __FC_CLIENT_SIP_NORM_H__
#define __FC_CLIENT_SIP_NORM_H__

#include "FCClientSip.h"
#define CLI_SIP_NORM_STARTMPORT 40000 //传输视频流的动态代理端口 开始端口

class CClientSipNorm: public CClientSipBase
{
public:
    CClientSipNorm(int i);
    virtual ~CClientSipNorm();
    virtual int dstStart();
    virtual int srcStart();
    virtual void initChannel();
    virtual int getOneChannelID(const char *mrecvip, const char *mrecvport,
                                int &find, const char *callid, int &nodeid);
    virtual void addOneChannel(int nodeid, int chanid);
    virtual const char *getChannelProxyPort(int nodeid, int chanid);
    virtual const char *getChannelProxyIP(const char *callid);
    virtual const char *getChannelOutIP(const char *callid);
    virtual const char *getTypeDesc();
    virtual void delChannelByCallID(const char *callid);

private:
    void delOneChannel(int chanid);
    void dstVideoPrepare();
    void channelOper(int chanid, bool ifadd);

private:
    MediaChannel m_channel[CLI_SIP_NORM_MAX_CHANNEL];//媒体通道表
    int m_maxchannel;
	int m_lastid;
};

#endif
