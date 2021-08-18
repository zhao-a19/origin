/*******************************************************************************************
*文件: FCSipNorm.h
*描述: 普通平台级联（区别于平台级联联动）
*作者: 王君雷
*日期: 2018-04-13
*修改:
*         函数命名统一风格                                              ------>   2018-04-23
*         clearAChannel改名为delOneChannel                              ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*******************************************************************************************/
#ifndef __FC_SIP_NORM_H__
#define __FC_SIP_NORM_H__

#include "FCSip.h"

#define SIP_NORM_STARTPORT 20000

class CSipNorm: public CSipBase
{
public:
    CSipNorm(int i);
    virtual ~CSipNorm();
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
    MediaChannel m_channel[SIP_NORM_MAX_CHANNEL];
    int m_maxchannel;
	int m_lastid;
};

#endif
