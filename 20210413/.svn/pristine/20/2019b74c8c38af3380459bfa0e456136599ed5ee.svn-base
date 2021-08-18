/*******************************************************************************************
*文件:  FCBonding.h
*描述:  负载均衡类
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FCBONDING_H__
#define __FCBONDING_H__

#include "critical.h"

enum _bondtype {
    BONDTYPE0,
    BONDTYPE1,
    BONDTYPE2,
    BONDTYPE3,
    BONDTYPE4,
    BONDTYPE5,
    BONDTYPE6
};

class CBonding
{
public:
    CBonding(void);
    virtual ~CBonding(void);

public:
    bool bond;
    int devnum;
    int ipnum;
    int bondtype;
    int dev[C_BONDING_DEV_MAXNUM];
    char ipaddr[C_BONDING_IP_MAXNUM][IP_STR_LEN];
    char maskaddr[C_BONDING_IP_MAXNUM][MASK_STR_LEN];
    int iptype[C_BONDING_IP_MAXNUM];
};

#endif
