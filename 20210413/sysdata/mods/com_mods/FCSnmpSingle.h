/*******************************************************************************************
*文件:  FCSnmpSingle.h
*描述:  SNMP模块
*作者:dzj
*日期:  2020-01
*修改:
*          包含解析IP头的.h文件                                     ------> 2020-01-18 -dzj
*          修改接口参数命名和中文日志问题                           ------> 2020-02-13 -dzj
*******************************************************************************************/
#ifndef __FC_SNMP_SINGLE_H__
#define __FC_SNMP_SINGLE_H__
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

#define SNMP_VERSION_1 "0"
#define SNMP_VERSION_2C "1"
#define SNMP_VERSION_3 "3"

#define SNMP_REQ_MAX_OID 5//获取一个报文里几个字段,由于获取到的字段ID从1开始，所以要n+1
#define SNMP_RES_MAX_OID 100//获取一个报文里几个字段,由于获取到的字段ID从1开始，所以要n+1
#define SNMPV1_RE_MAX_CMD 5
#define SNMPV2C_RE_MAX_CMD 8
#define SNMPV3_RE_MAX_CMD 9


static char SNMPV1_RE_CMD[SNMPV1_RE_MAX_CMD][MAX_CMD_NAME_LEN] = {{"get-request"}, {"get-next-request"}, {"get-response"},
                                                              {"set-request"}, {"trap"}};


static char SNMPV2C_RE_CMD[SNMPV2C_RE_MAX_CMD][MAX_CMD_NAME_LEN] = {{"get-request"}, {"get-next-request"}, {"get-response"},
                                                                {"set-request"}, {""}, {"getBulkRequest"}, {"informRequest"},
                                                                {"snmpV2-trap"}};

static char SNMPV3_RE_CMD[SNMPV3_RE_MAX_CMD][MAX_CMD_NAME_LEN] = {{"get-request"}, {"get-next-request"}, {"get-response"},
                                                                {"set-request"}, {""}, {"getBulkRequest"}, {"informRequest"},
                                                                {"snmpV2-trap"}, {"report"}};
class CSNMP : public CSINGLE
{
public:
    CSNMP(const char *dport);
    ~CSNMP(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
#if (SUOS_V!=6)
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
#endif
};

#endif
