/*******************************************************************************************
*文件:  timemod.h
*描述:  时间模式
*作者:  王君雷
*日期:  2018-11-03
*修改:
*******************************************************************************************/
#ifndef __TIME_MOD__H__
#define __TIME_MOD__H__

#include "define.h"

//时间模式类型
enum TIME_TYPE {
    TIME_DAY_TYPE = 0,
    TIME_WEEKDAY_TYPE,
    TIME_DATE_TYPE
};

class TIME_MOD
{
public:
    TIME_MOD(void);
    virtual ~TIME_MOD(void);
    const char *tostring(void);
public:
    int m_timetype;
    char m_stime[20];
    char m_etime[20];
    char m_sdate[20];
    char m_edate[20];
    char m_weekdays[20];
private:
    char m_tmptime[128];
};

#endif
