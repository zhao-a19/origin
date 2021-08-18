/*******************************************************************************************
*文件:  calllog.h
*描述:  syslog发送 calllog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*******************************************************************************************/
#ifndef __CALL_LOG_H__
#define __CALL_LOG_H__
#include "syslog_manager.h"

class CALLLOG: public LOGOBJ
{
public:
    CALLLOG();
    virtual ~CALLLOG();

    virtual bool MakeLogInfo(void);
    virtual bool MakeUpdateSql(void);
};

#endif
