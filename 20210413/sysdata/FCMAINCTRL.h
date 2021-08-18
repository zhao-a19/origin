/*******************************************************************************************
*文件:  FCMAINCTRL.h
*描述:  主控制类
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_MAIN_CTRL_H__
#define __FC_MAIN_CTRL_H__

#include "FCMANAGEBS.h"

class CMAINCTRL
{
public:
    CMAINCTRL();
    virtual ~CMAINCTRL();
private:
    CMANAGEBS *m_managebs;
public:
    bool Start();
};

#endif
