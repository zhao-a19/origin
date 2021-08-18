/*******************************************************************************************
*文件:  FCRTSP.h
*描述:  RTSP模块  即MEDIA模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_RTSP_H__
#define __FC_RTSP_H__

#include "FCSingle.h"

class CRTSP : public CSINGLE
{
public:
    CRTSP();
    ~CRTSP();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeReply(unsigned char *sdata, int slen);
    //bool IfRequest(char *chrequest);
private:
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_url[MAX_PARA_NAME_LEN];
};

#endif
