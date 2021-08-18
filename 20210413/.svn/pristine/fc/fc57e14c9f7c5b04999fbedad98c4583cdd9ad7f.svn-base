/*******************************************************************************************
*文件:  StartRTSPInst.h
*描述:  开启RTSP任务实例
*作者:  王君雷
*日期:  2017-03
*修改:
*******************************************************************************************/
#ifndef __START_RTSP_INST_H__
#define __START_RTSP_INST_H__

#include <stdio.h>
#include <unistd.h>
#include "define.h"
#include "FCSysRulesBS.h"

int StartRTSPInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno);
void *RTSPListenThread(void *arg);
void *RTSPCliProcess(void *arg);

//需要传递给线程使用的参数
typedef struct {
    int seqno;
    int infd;
    char tip[IP_STR_LEN];
    char midip[IP_STR_LEN];
    char dip[IP_STR_LEN];
    char tport[PORT_STR_LEN];
    int appno;
    CSYSRULES *rule;
    char authname[AUTH_NAME_LEN];
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_url[MAX_PARA_NAME_LEN];
} RTSPPara;

bool DecodeRequest(unsigned char *data, int datasize, char *error_reason, RTSPPara *ppara);
bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror, RTSPPara *ppara);
void RecordCallLog(RTSPPara *ppara, const char *cherror, bool result);

#endif
