/*******************************************************************************************
*文件:    date.cpp
*描述:    计算两个日期之间相差天数
*
*作者:    张昆鹏
*日期:    2016-10-31
*修改:    创建文件                            ------>     2016-11-8
*         修改代码规范                        ------>     2016-11-22
*         新增DaysBetween2Date_函数           ------>     2017-02-27
*
*******************************************************************************************/

#include "date.h"

#define LEAPYEAR       366
#define NONLEAPYEAR    365
#define LEAPMONTH      29

/*******************************************************************************************
*功能:    判断一个年份是否为闰年
*参数:    year                  ---->    年份
*         返回值                ---->    true 是
*
*注释:
*
*******************************************************************************************/
static bool IsLeap(int32 year)
{
    return (((year % 4 == 0) || (year % 400 == 0)) && (year % 100 != 0));
}

/*******************************************************************************************
*功能:    取出日期中的年月日并判断日期是否合法
*参数:     date                                        ---->    日期
*          year                                        ---->    年份
*          month                                       ---->    月
*          day                                         ---->    天
*         返回值                                       ---->    true正确
*
*注释:从字符中最得年月日 规定日期的格式是yyyy-mm-dd
*******************************************************************************************/
static bool StringToDate(string date, int32& year, int32& month, int32& day)
{
    int32 DAY[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    year = atoi((date.substr(0, 4)).c_str());
    month = atoi((date.substr(5, 2)).c_str());
    day = atoi((date.substr(8, 2)).c_str());

    if (IsLeap(year)) {
        DAY[1] = LEAPMONTH;
    }
    return ((year >= 0) && (month <= 12) && (month > 0) && (day <= DAY[month]) && (day > 0));
}

/*******************************************************************************************
*功能:    计算指定日期属于该年的第几天
*参数:    year                               ---->    年份
*         month                              ---->    月
*         day                                ---->    天
*         返回值                             ---->    天数
*
*注释:
*******************************************************************************************/
static int32 DayInYear(int32 year, int32 month, int32 day)
{
    int32 DAY[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (IsLeap(year))
        DAY[1] = LEAPMONTH;
    for (int32 i = 0; i < month - 1; ++i) {

        day += DAY[i];
    }

    return day;
}

/*******************************************************************************************
*功能:    计算两个日期之间相差天数
*参数:    b_date                               ---->  日期
*         e_date                               ---->  日期
*         返回值                              ---->  正确相差天数，错误-1
*
*注释:
*******************************************************************************************/
int32 DaysBetween2Date(string b_date, string e_date)
{
    int32 b_year, b_month, b_day;
    int32 e_year, e_month, e_day;
    if (!StringToDate(b_date, b_year, b_month, b_day) || !StringToDate(e_date, e_year, e_month, e_day)) {  //取出日期中的年月日

        PRINT_DBG_HEAD;
        print_dbg("Format error");

        return -1;
    }
    if ((b_year == e_year) && (b_month == e_month)) {

        return ((b_day > e_day) ? (b_day - e_day) : (e_day - b_day));

    } else if (b_year == e_year) {                                 //如果年相同

        int32 d_day, m_day;
        d_day = DayInYear(b_year, b_month, b_day);
        m_day = DayInYear(e_year, e_month, e_day);
        return (d_day > m_day ? d_day - m_day : m_day - d_day);
    } else {                                                     //年月都不相同

        if (b_year > e_year)  {                                    //确保year1年份比year2早

            swap(b_year, e_year);                                  //swap进行两个值的交换
            swap(b_month, e_month);
            swap(b_day, e_day);
        }
        int32 d_day, m_day, y_day;
        if (IsLeap(b_year)) {

            d_day = LEAPYEAR - DayInYear(b_year, b_month, b_day);           //取得这个日期在该年还于下多少天
        } else {

            d_day = NONLEAPYEAR - DayInYear(b_year, b_month, b_day);
        }
        m_day = DayInYear(e_year, e_month, e_day);                     //取得在当年中的第几天

        y_day = 0;
        for (int32 year = b_year + 1; year < e_year; year++)  {

            if (IsLeap(year)) {

                y_day += LEAPYEAR;
            } else {

                y_day += NONLEAPYEAR;
            }
        }
        return (d_day + m_day + y_day);
    }
}


/*******************************************************************************************
*功能:    计算b_date小于e_date的天数
*参数:    b_date                               ---->  日期
*         e_date                               ---->  日期
*         返回值                               ---->  正确相差天数，-1: 错误,-2: b_date大于e_date的天数
*
*注释:   参数b_date要小于e_date,否则统一返回-2，
*******************************************************************************************/
int32 DaysBetween2Date_(string b_date, string e_date)
{
    int32 b_year, b_month, b_day;
    int32 e_year, e_month, e_day;
    if (!StringToDate(b_date, b_year, b_month, b_day) || !StringToDate(e_date, e_year, e_month, e_day)) {  //取出日期中的年月日

        PRINT_ERR_HEAD;
        print_err("Format error");
        return -1;
    }
    int32 day = -2;
    if ((b_year == e_year) && (b_month == e_month)) {

        day = e_day - b_day;
    } else if (b_year == e_year) {                                          //如果年相同

        int32 d_day, m_day;
        d_day = DayInYear(b_year, b_month, b_day);
        m_day = DayInYear(e_year, e_month, e_day);
        day = m_day - d_day;
    } else {                                                                //年月都不相同

        if (b_year < e_year) {

            int32 d_day, m_day, y_day;
            if (IsLeap(b_year)) {

                d_day = LEAPYEAR - DayInYear(b_year, b_month, b_day);           //取得这个日期在该年还于下多少天
            } else {

                d_day = NONLEAPYEAR - DayInYear(b_year, b_month, b_day);
            }
            m_day = DayInYear(e_year, e_month, e_day);                          //取得在当年中的第几天

            y_day = 0;
            for (int32 year = b_year + 1; year < e_year; year++) {

                if (IsLeap(year)) {

                    y_day += LEAPYEAR;
                } else {

                    y_day += NONLEAPYEAR;
                }
            }
            day = d_day + m_day + y_day;
        }
    }

    return ((day >= 0) ? day : -2);
}


