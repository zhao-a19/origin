/*******************************************************************************************
*文件:  FCDMSingle.h
*描述:  DM模块
*作者:  王君雷
*日期:  2017-10-23
*修改:
*******************************************************************************************/
#ifndef __FC_DM_SINGLE_H__
#define __FC_DM_SINGLE_H__
#include "FCSingle.h"

class CDM : public CSINGLE
{
public:
    CDM();
    ~CDM();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
    char m_SqlOperName[C_MAX_SQLOPERNAMELEN];
    char m_TableName[C_MAX_TABLENAMELEN];
    char m_Sql[C_MAX_SQLLEN];
    char *m_DefSqlOper[C_MAX_SQLOPER];

    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool FindSql(unsigned char *sdata, int slen, char *sql_com, int &sqllen);
    bool DecodeOper(char *csql, int sqllen, char *coper, char *cpara);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
};

#endif
