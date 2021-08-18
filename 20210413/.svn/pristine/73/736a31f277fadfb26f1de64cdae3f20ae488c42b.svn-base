/*******************************************************************************************
*文件:  FCObjectBS.cpp
*描述:  对象类
*作者:  王君雷
*日期:  2016-03
*修改:
*       COBJECT 添加以该类指针为参数的构造函数            ------> 2018-04-11
*       COBJECT 添加以对象名称为参数的构造函数            ------> 2020-02-07
*******************************************************************************************/
#include "FCObjectBS.h"
#include "debugout.h"
#include <string.h>

COBJECT::COBJECT(void)
{
    BZERO(m_objectname);
    BZERO(m_ipaddress);
    BZERO(m_netmask);
    BZERO(m_mac);
    m_iptype = IP_TYPE4;
}

COBJECT::~COBJECT(void)
{
}

COBJECT::COBJECT(const COBJECT *pobj)
{
    if (pobj != NULL) {
        strcpy(m_objectname, pobj->m_objectname);
        strcpy(m_ipaddress, pobj->m_ipaddress);
        strcpy(m_netmask, pobj->m_netmask);
        strcpy(m_mac, pobj->m_mac);
        m_iptype = pobj->m_iptype;
    } else {
        PRINT_ERR_HEAD
        print_err("cobject para null");
    }
}

COBJECT::COBJECT(const char *chname)
{
    BZERO(m_objectname);
    BZERO(m_ipaddress);
    BZERO(m_netmask);
    BZERO(m_mac);
    m_iptype = IP_TYPE4;

    if ((chname != NULL) && (strlen(chname) < sizeof(m_objectname))) {
        strcpy(m_objectname, chname);
    } else {
        PRINT_ERR_HEAD
        print_err("object name error[%s]", chname);
        BZERO(m_objectname);
    }
}
