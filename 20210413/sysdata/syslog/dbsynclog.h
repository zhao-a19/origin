/*******************************************************************************************
*文件:  dbsynclog.h
*描述:  syslog发送 dbsynclog
*作者:  王君雷
*日期:  2019-06-29
*修改:
*******************************************************************************************/
#ifndef __DBSYNC_LOG_H__
#define __DBSYNC_LOG_H__
#include "syslog_manager.h"

class DBSYNCLOG: public LOGOBJ
{
public:
    DBSYNCLOG();
    virtual ~DBSYNCLOG();

    virtual bool MakeLogInfo(void);
    virtual bool MakeUpdateSql(void);
};

#endif
