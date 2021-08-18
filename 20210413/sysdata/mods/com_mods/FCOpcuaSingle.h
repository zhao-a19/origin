/*******************************************************************************************
*文件:  FCOpcuaSingle.h
*描述:  OPCUA模块
*作者:dzj
*日期:  2019-09
*修改:
*          解决在V6环境下编辑不过问题                               ------> 2019-10-08-dzj
*          解决在V6环境下编辑不过问题                               ------> 2019-10-08-dzj
*          解决OPCUA端口改变不可解析的问题                          ------> 2019-10-10 -dzj
*          包含解析IP头的.h文件                                     ------> 2020-01-18 -dzj
*          修改接口参数命名和中文日志问题                           ------> 2020-02-13 -dzj
*******************************************************************************************/
#ifndef __FC_OPCUA_SINGLE_H__
#define __FC_OPCUA_SINGLE_H__
#include <map>
#include "FCSingle.h"
#include "network.h"


#if (SUOS_V!=6)
extern "C" {
#include "stdio.h"
#include "su_protocol.h"
#include "su_comm.h"
#include "su_wireshark_epan.h"
#include "su_wireshark_print.h"
}
extern struct su_epan_session_t *pSuEpanSession;
extern int su_epan_set_port(const char *protocol, uint32_t port_h);
#endif

#define READ_ONLY_TAG "allread"
#define WRITE_ONLY_TAG "allwrite"

#define OPCUA_MAX_CMD 10//最大支持是个粘包
class COPCUASINGLE : public CSINGLE
{
public:
    COPCUASINGLE(const char *dport);
    ~COPCUASINGLE(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
#if (SUOS_V!=6)
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
#endif
private:
    map<int, string> mapOpcua;
    char m_cmd[OPCUA_MAX_CMD][MAX_CMD_NAME_LEN];
    char m_para[OPCUA_MAX_CMD][MAX_PARA_NAME_LEN];
};

#endif
