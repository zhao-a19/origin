/*******************************************************************************************
*文件:  FCDnsSingle.h
*描述:  DNS模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_DNS_SINGLE_H__
#define __FC_DNS_SINGLE_H__

#include "FCSingle.h"

class CDNSSINGLE : public CSINGLE
{
public:
    CDNSSINGLE(void);
    virtual ~CDNSSINGLE(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    int AnalyseDns(unsigned char *sdata, int slen, char *cherror);
    int DecodeDnsUrl(unsigned char *ucdata, int ilen, char *chhostname);
    bool AnalyseUrlRule(char *chcmd, char *chpara, char *cherror);

private:
    char m_cmd[MAX_CMD_NAME_LEN];
    char m_param[MAX_PARA_NAME_LEN];
};

#endif
