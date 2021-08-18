/*******************************************************************************************
*文件:  FCPop3Single.h
*描述:  pop3模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_POP3_SINGLE_H__
#define __FC_POP3_SINGLE_H__

#include "FCSingle.h"

class CPOP3SINGLE : public CSINGLE
{
public:
    CPOP3SINGLE();
    ~CPOP3SINGLE();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
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
