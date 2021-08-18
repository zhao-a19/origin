/*******************************************************************************************
*文件: FCClientSipLink.h
*描述: 视频代理联动
*作者: 王君雷
*日期: 2018-04-12
*修改:
*         编码实现视频代理联动                                          ------>   2018-06-06
*         日志中能区分视频的类型                                        ------>   2018-06-22
*         可通过会话ID清空、复用视频通道;支持多节点视频联动             ------>   2018-07-14
*******************************************************************************************/
#ifndef __FC_CLIENT_SIP_LINK_H__
#define __FC_CLIENT_SIP_LINK_H__
#include "FCClientSip.h"
using namespace std;
#include <vector>

class CSYSRULESBUSINESS;

class CClientSipLink: public CClientSipBase
{
public:
    CClientSipLink(int i);
    virtual ~CClientSipLink();
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

    friend class CSYSRULESBUSINESS;

private:
    void delOneChannel(int nodeid, int chanid);
    void nodeCmdNat();
    bool nodeTest(int nodeid);
    int getOneNode();
    void resetOneChannel(int nodeid, int chanid);
    void initWeight();
    bool portAble(int port);

private:
    int m_nodenum;
    int m_maxchannel;//每个节点支持的通道最大数
    ForwardNode *m_node[SIP_MAX_NODE];
    vector<int> m_exceptport;//不可用于视频流通道的端口

    int m_totalw;
    int m_lastpos;
    int *m_warray;
};

#endif
