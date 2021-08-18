/*******************************************************************************************
*文件:  rsyslogd.h
*描述:  运行rsyslogd线程函数
*作者:  王君雷
*日期:  2020-01-15
*修改:
*******************************************************************************************/
#ifndef __RSYSLOGD_THREAD_H__
#define __RSYSLOGD_THREAD_H__

int StartRsyslogd(void);

//syslog接收服务端
class SLOG_SVR_OPER
{
public:
    SLOG_SVR_OPER(void);
    virtual ~SLOG_SVR_OPER(void);

    int ReadConfig(void);
    int WriteConfig(void);
    int RunRsyslogd(void);
    void Check(void);
private:
    char m_svrip[50];
    char m_svrport[20];
    bool m_syslog;
};

#endif
