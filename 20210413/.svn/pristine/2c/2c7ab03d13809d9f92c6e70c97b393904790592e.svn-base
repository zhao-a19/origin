/*******************************************************************************************
*文件:  FCObjectBS.h
*描述:  对象类
*作者:  王君雷
*日期:  2016-03
*修改:
*       COBJECT 添加以该类指针为参数的构造函数                            ------> 2018-04-11
*       对象名称长度宏移动到critical.h中；添加以对象名为参数的构造函数    ------> 2020-02-07
*******************************************************************************************/
#ifndef __FC_OBJECT_BS_H__
#define __FC_OBJECT_BS_H__

#include "define.h"

class COBJECT
{
public:
    COBJECT(void);
    COBJECT(const char *chname);
    COBJECT(const COBJECT *pobj);
    virtual ~COBJECT(void);
public:
    char m_objectname[OBJ_NAME_LEN];//对象名称
    char m_ipaddress[IP_STR_LEN];   //对象IP
    char m_netmask[MASK_STR_LEN];   //子网掩码
    char m_mac[MAC_STR_LEN];        //对象MAC地址
    int m_iptype;                   //IP类型 1：ipv6  0：ipv4
};

#endif
