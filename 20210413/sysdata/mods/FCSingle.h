/*******************************************************************************************
*文件:  FCSingle.h
*描述:  应用模块基类
*作者:  王君雷
*日期:  2016
*
*修改:
*        修改成员函数的作用域                                    ------> 2016-01-21
*        注释掉成员函数FilterKey，关键字过滤有全局iptables去控制 ------> 2017-10-24 王君雷
*        去除ICMPMAP相关内容，因为使用不到了                     ------> 2018-12-27
*******************************************************************************************/
#ifndef __FC_Single_H__
#define __FC_Single_H__
#include <string.h>
#include <stddef.h>// arm64 for offsetof

#include "const.h"
#include "FCServiceConf.h"
#include "common.h"
#include "FCLogManage.h"
#include "fileoperator.h"
#include "define.h"
#include "FCIPPortMap.h"
#include "quote_global.h"
#include "simple.h"

const int C_MAX_SQLOPERNAMELEN = 20;
const int C_MAX_TABLENAMELEN = 100;
const int C_MAX_SQLLEN = 500;
const int C_MAX_SQLOPER = 11;

class CSINGLE
{
public:
    CSINGLE(void);
    virtual ~CSINGLE(void);
    void  SetRecordFlag(bool bflag);
    virtual bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc) = 0;
    bool DoMsgIPV6(unsigned char *sdata, int slen, int offsetlen, char *cherror, int *pktchange, int bFromSrc);
    bool QueueNumEqual(int queuenum);
    bool Match(unsigned short dport, struct in_addr dip, unsigned short sport, struct in_addr sip, int &fromsrc);
    bool MatchIPv6(unsigned short dport, struct in6_addr dip, unsigned short sport, struct in6_addr sip, int &fromsrc);
    void SetService(CSERVICECONF *pserv);
    CSERVICECONF *GetService(void);
    void AddToMap(IpPortMap &val);

protected:
    int GetHeadLen(unsigned char *sdata);
    virtual bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    virtual bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    virtual bool DecodeReply(unsigned char *sdata, int slen, char *cherror);
    void RecordCallLog(unsigned char *sdata, const char *chcmd, const char *chpara, const char *cherror, bool result);
    void RecordFilterLog(unsigned char *sdata, const char *fname, const char *remark);

    bool IsSYN(unsigned char *sdata);
    bool IsFIN(unsigned char *sdata);
    bool IsRST(unsigned char *sdata);
    static bool FilterFileType(const char *fname, char *cherror);
    static int EncUnicodeToUTF8(unsigned long unic, unsigned char *pOutput, int outSize);
    bool GetAttachInfo(const char *sdata, int slen, char *para, int parasize);
    bool CheckSubject(const char *sdata, int slen, char *cherror);

private:
    static int GetHeadLenIPv4(unsigned char *sdata);
    int GetHeadLenIPv6(unsigned char *sdata);
    bool IsTCP(void);
    bool IsUDP(void);
    bool IsICMP(void);
    bool IsICMPV6(void);
    void GetIPPortFromPack(const unsigned char *sdata, char *sip, char *dip, char *sport, char *dport);
    bool MidIPToTIP(char *ip);

protected:
    CCommon m_common;
    CSERVICECONF *m_service;

private:
    vector<IpPortMap> m_ipportmap;
    bool m_recordlog;
    int m_ipv6_offsetlen; //IPV6报文 传输层头部相对于网络层头部的偏移量. 即：IPV6头部 和可选的扩展头部 长度之和
};

bool filter_key(const char *chcmd, char *cherror);
bool GetTableName(const char *ch, int len, char *param);

#endif
