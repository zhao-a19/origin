/*******************************************************************************************
*文件:  FCSmtpSingle.h
*描述:  smtp模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21

*     更改私有成员函数变为公有                                      ------> 2019-06-13  宋宇
*******************************************************************************************/
#ifndef __FC_SMTP_SINGLE_H__
#define __FC_SMTP_SINGLE_H__
#include "FCSingle.h"
#include "debugout.h"

class CSMTPSINGLE : public CSINGLE
{
public:
    CSMTPSINGLE();
    ~CSMTPSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeReply(unsigned char *sdata, int slen);

private:
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_param[MAX_PARA_NAME_LEN];
};

#endif
