/*******************************************************************************************
*文件:  timemod.cpp
*描述:  时间模式
*作者:  王君雷
*日期:  2018-11-03
*修改:
*******************************************************************************************/
#include <string.h>
#include <stdio.h>
#include "timemod.h"
#include "debugout.h"

TIME_MOD::TIME_MOD(void)
{
    BZERO(m_stime);
    BZERO(m_etime);
    BZERO(m_sdate);
    BZERO(m_edate);
    BZERO(m_weekdays);
    BZERO(m_tmptime);
}

TIME_MOD::~TIME_MOD(void)
{
}

/**
 * [TIME_MOD::tostring 获取组iptables语句使用的时间模式字符串]
 * @return  [时间模式字符串 失败返回NULL]
 */
const char *TIME_MOD::tostring(void)
{
    BZERO(m_tmptime);

    switch (m_timetype) {
    case TIME_DAY_TYPE:
        if ((strcmp(m_stime, "00:00:00") == 0) && (strcmp(m_etime, "23:59:59") == 0)) {
        } else {
            sprintf(m_tmptime, "-m time --timestart %s --timestop %s --kerneltz",
                    m_stime, m_etime);
        }
        break;
    case TIME_WEEKDAY_TYPE:
        if ((strcmp(m_stime, "00:00:00") == 0) && (strcmp(m_etime, "23:59:59") == 0)) {
            sprintf(m_tmptime, "-m time --weekdays %s --kerneltz", m_weekdays);
        } else {
            sprintf(m_tmptime, "-m time --timestart %s --timestop %s --weekdays %s --kerneltz",
                    m_stime, m_etime, m_weekdays);
        }
        break;
    case TIME_DATE_TYPE:
        if ((strcmp(m_stime, "00:00:00") == 0) && (strcmp(m_etime, "23:59:59") == 0)) {
            sprintf(m_tmptime, "-m time --datestart %sT00:00:00 --datestop %sT23:59:59 --kerneltz",
                    m_sdate, m_edate);
        } else {
            sprintf(m_tmptime,
                    "-m time --timestart %s --timestop %s --datestart %sT00:00:00 --datestop %sT23:59:59 --kerneltz",
                    m_stime, m_etime, m_sdate, m_edate);
        }
        break;
    default:
        PRINT_ERR_HEAD
        print_err("Unknown timetype[%d]", m_timetype);
        return NULL;
        break;
    }

    return m_tmptime;
}

