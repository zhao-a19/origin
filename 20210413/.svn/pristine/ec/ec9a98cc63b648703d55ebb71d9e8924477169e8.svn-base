/*******************************************************************************************
*文件:  cip.h
*描述:  cip模块
*作者:  王君雷
*日期:  2021-02-01
*修改:
*******************************************************************************************/
#ifndef __CIP_H__
#define __CIP_H__

#include <vector>
using namespace std;

#include "FCSingle.h"
#include "cip_parser.h"

class CCIP : public CSINGLE
{
public:
    CCIP(void);
    ~CCIP(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange);
    void Clear(void);
    bool Filter(char *cherror);
    bool MatchValue(const char *para2, bool action);
    bool MakePara(void);

    CIPParser m_parser;
    PointType m_pointtype;             //测点的数据类型
    char m_chcmd[MAX_CMD_NAME_LEN];
    char m_chpara[MAX_PARA_NAME_LEN];
    char m_chpara2[MAX_PARA_NAME_LEN]; //处理之后的参数

    vector<int> m_vecint;
    vector<float> m_vecfloat;
    vector<int> m_vecbool;
};

#endif
