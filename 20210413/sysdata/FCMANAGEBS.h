/*******************************************************************************************
*文件:  FCMANAGEBS.h
*描述:  管理业务类
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_MANAGE_BS_H__
#define __FC_MANAGE_BS_H__

#include "FCHotBakBS.h"

class CMANAGEBS
{
public:
    CMANAGEBS(void);
    virtual ~CMANAGEBS(void);

private:
    int m_bs_cnt;
    CSYSBS *m_bs[MAX_BUSINESS_NUM];
    int m_bs_type[MAX_BUSINESS_NUM];
    CHOTBAKBS *m_hotbakbs;

public:
    bool InitAllBS(void);//初始化所有业务
    int  CreateBS(int type);
};

#endif
