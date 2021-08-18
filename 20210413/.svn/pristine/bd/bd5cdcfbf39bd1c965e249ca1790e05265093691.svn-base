/*******************************************************************************************
*文件:  FCXMPP.h
*描述:  XMPP模块
*作者:  王君雷
*日期:  2020-08-17
*修改:
*******************************************************************************************/
#ifndef __FC_XMPP_H__
#define __FC_XMPP_H__

#include "FCSingle.h"
#include "debugout.h"

#define XMPP_NOT_FILE -1      //非xmpp传输文件
#define XMPP_FILE_SUCCESS 0   //xmpp传输文件
#define XMPP_FILE_FAILD 1     //xmpp传输文件失败
#define XMPP_PLATFORM 10     //xmpp平台类型个数
#define MAX_PARAM_NUM 3 //命令参数个数
enum FCXMPP_PARAM {
    FCXMPP_STATUS = 0,
    FCXMPP_TYPE,
    FCXMPP_MESSAGE
};

class CXMPP : public CSINGLE
{
public:
    CXMPP(void);
    ~CXMPP(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
private:
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_param[MAX_PARA_NAME_LEN];
};

#endif
