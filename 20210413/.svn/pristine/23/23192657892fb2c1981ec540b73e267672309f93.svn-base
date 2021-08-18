/*******************************************************************************************
*文件:  FCSMBSingle.h
*描述:  SMB模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       命令和参数长度使用宏表示                                          ------> 2018-12-21
*******************************************************************************************/
#ifndef __FC_SMB_SINGLE_H__
#define __FC_SMB_SINGLE_H__
#include "FCSingle.h"
#include "smb.h"
#include "smb2.h"

class CSMBSINGLE : public CSINGLE
{
public:
    CSMBSINGLE();
    ~CSMBSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeRequestSMBV1(unsigned char *sdata, int slen, char *cherror);
    bool DecodeSMBV1NTCreateAndXRequest(unsigned char *sdata, int slen, char *cherror);
    bool DecodeSMBV1Trans2Request(unsigned char *sdata, int slen, char *cherror);
    bool DecodeRequestSMBV2(unsigned char *sdata, int slen, char *cherror);
    bool DecodeRequestSMBV2Create(unsigned char *sdata, int slen, char *cherror);
    bool DecodeRequestSMBV2SetInfo(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
    bool ParticularFile(const char *file);
    bool DecodeFileName(unsigned char *data, int len);
private:
    char m_action[MAX_CMD_NAME_LEN];
    char m_fname[MAX_PARA_NAME_LEN];
};

#pragma pack(push, 1)
typedef struct NETBIOS_SESSION_MESSAGE {
    uint8 messagetype;
    uint8 len1;
    uint16 len2;
} NETBIOS_SESSION_MESSAGE, *PNETBIOS_SESSION_MESSAGE;
#pragma pack(pop)

#endif
