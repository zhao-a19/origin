/*******************************************************************************************
*文件:  FCFtpSingle.h
*描述:  FTP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*       把所有私有类成员函数转为共有类成员函数(宋宇)                        ------> 2019-05-20
*******************************************************************************************/
#ifndef __FC_FTP_SINGLE_H__
#define __FC_FTP_SINGLE_H__

#include "FCSingle.h"
#include <glib.h>

class CFTPSINGLE : public CSINGLE
{
public:
    CFTPSINGLE(void);
    ~CFTPSINGLE(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);

private:
    GHashTable *cmd_hash_table;
    vector<string> ftpcmd;
    char m_cmd[MAX_CMD_NAME_LEN];
    char m_para[MAX_PARA_NAME_LEN];
};

#endif
