/*******************************************************************************************
*文件: pdtcommon.h
*描述: PDT互联
*作者: 王君雷
*日期: 2018-07-31
*修改:
*
*******************************************************************************************/
#ifndef __PDT_COMMON_H__
#define __PDT_COMMON_H__

#include <semaphore.h>
#include "pdtbase.h"

#define PDT_COMMON_MAX_CHANNEL  10000 //通道数
#define PDT_COMMON_PORT_START   20000 //媒体代理端口 开始使用的第一个端口

class CPDTCommon: public CPDTBase
{
public:
    CPDTCommon(int taskid);
    virtual ~CPDTCommon(void);
    virtual int initChannel(void);
    virtual void deleteChannelByCallID(const char *callid);
    virtual int getChannelProxyIP(const char *callid, int area, char *channelproxyip);
    virtual int getChannelProxyPort(const char *callid, int area, const char *originip,
                                    const char *mediaport, bool isresp, char *channelport);
private:
    int getChannelProxyPortRequest(const char *callid, int area, const char *originip,
                                   const char *mediaport, char *channelport);
    int getChannelProxyPortRespons(const char *callid, int area, const char *originip,
                                   const char *mediaport, char *channelport);
    int getChannelProxyPortResponsInCenter(const char *callid, const char *originip,
                                           const char *mediaport, char *channelport);
    int getChannelProxyPortResponsOutCenter(const char *callid, const char *originip,
                                            const char *mediaport, char *channelport);
    void resetOneChannel(int chanid);
    int delOneChannel(int chanid);
    int addOneChannel(int chanid);
    int channelOper(int chanid, bool isadd);
    void initLock(void);
    void destroyLock(void);
    void lock(void);
    void unlock(void);

private:
    int m_max_channel;
    PPDTCHANNEL m_pchannel;
    sem_t m_lock;
};

#endif
