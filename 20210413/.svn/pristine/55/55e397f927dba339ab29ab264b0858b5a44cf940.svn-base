/*******************************************************************************************
*文件:  slog.h
*描述:  发送syslog到本地服务接口
*作者:  王君雷
*日期:  2020-01-10
*修改:
*       成员变量数组长度使用宏表示                                    ------> 2020-02-05
*       添加函数ReadSwitch                                            ------> 2020-07-06
*******************************************************************************************/
#ifndef __SLOG_H__
#define __SLOG_H__

#include <string.h>
#include "critical.h"

//syslog发送客户端
class SLOG_CLI_OPER
{
public:
    SLOG_CLI_OPER(void);
    virtual ~SLOG_CLI_OPER(void);

    int WriteSysLog(const char *logtype, const char *result, const char *remark,
                    int isout, const char *dtime);
    int WriteSysStatusLog(int linknum, const char *cpuinfo, const char *diskinfo,
                          const char *meminfo, const char *netinfo, unsigned long long int netflow,
                          char devstatus, const char *descr, int isout, const char *dtime);
    int WriteCallLog(const char *user, const char *srcip, const char *dstip,
                     const char *srcport, const char *dstport, const char *srcmac, const char *dstmac,
                     const char *service, const char *cmd, const char *param, const char *result,
                     const char *remark, int isout, const char *dtime);
    int WriteFileSyncLog(int taskid, const char *taskname, const char *srcip, const char *dstip,
                         const char *spath, const char *dpath, const char *fname, const char *result,
                         const char *remark, int isout, const char *dtime);
    int WriteLinkLog(const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                     const char *remark, const char *srcmac, const char *dstmac, int isout, const char *dtime);
    int WriteFilterLog(const char *user, const char *fname, const char *remark, const char *service,
                       const char *srcip, const char *dstip, const char *srcport, const char *dstport,
                       int isout, const char *dtime);
    bool ReadSwitch(void);
private:
    bool ReadConfig(void);
    bool ReadSerial(char *serial, int len);
    int SlogInit(const char *ident = NULL);
    int SlogClose(void);
    int SlogFormat(const char *pri, const char *fmt, ...);
    const char *GetPriLevel(const char *result);
    int GetsyslogPriLevel(const char *pri);
private:
    char m_id[DEV_TYPE_LEN];  //设备类型
    char m_fw[HOST_NAME_LEN]; //hostname
    char m_devid[DEV_ID_LEN]; //设备序列号
    bool m_syslog;            //是否发送SYSLOG
    bool m_gbkset;            //syslog服务器编码 true：gbk  false：utf8
};

#endif
