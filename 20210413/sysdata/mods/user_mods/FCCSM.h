/*******************************************************************************************
*文件:  FCCSM.h
*描述:  FCCSM模块
*作者:  王君雷
*日期:  2016-05-31
*注释：
*     TCC---->列控中心
*     TC ---->电路
*     CSM---->信号集中监测
*修改:
*******************************************************************************************/
#ifndef __FC_CSM_H__
#define __FC_CSM_H__

#include "FCSingle.h"

class CCSM : public CSINGLE
{
public:
    CCSM();
    ~CCSM();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);

    //TCC 列控中心
    bool IsHeartBeatToTCC(unsigned char *sdata, int slen, char *cherror);
    bool IsDataFromTCC(unsigned char *sdata, int slen, char *cherror);

    //TC 电路
    bool IsRequestToTC(unsigned char *sdata, int slen, char *cherror);
    bool IsResponseFromTC(unsigned char *sdata, int slen, char *cherror);
    bool IsDataFromTC(unsigned char *sdata, int slen, char *cherror);

    //信号集中监控
    bool IsToCSM(unsigned char *sdata, int slen, char *cherror);
private:
    char ch_cmd[40];
    char ch_param[200];
};

#endif
