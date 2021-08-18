/*******************************************************************************************
*文件:  FCMMS.h
*描述:  MMS模块
*作者:  王君雷
*日期:  2017-12-01
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_MMS_H__
#define __FC_MMS_H__

#include "FCSingle.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ber_decode.h"
#include "iso_server.h"
#include "iso_session.h"
#include "cotp.h"
#include "iso_presentation.h"
#include "acse.h"
#include "MmsPdu.h"

#include <lib_memory.h>

#ifdef __cplusplus
}
#endif

class CMMS : public CSINGLE
{
public:
    CMMS();
    ~CMMS();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

private:
    typedef struct CMDPARAM {
        char request[40];
        char domainid[100];
        char itemid[100];
    } CMDPARAM;
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool xmltorule(unsigned char *pstr, CMDPARAM &cmdrule);
    bool FilterCmd(CMDPARAM &cmdrule);
    void MakeParaString(CMDPARAM &cmdrule);
private:
    CMDPARAM m_cmdrule;
    char m_chpara[MAX_PARA_NAME_LEN];
};

#endif
