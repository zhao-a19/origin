/*****************************************************************************
*                                                                            *
*  Copyright (C) 2014 www.anmit.com All rights reserved.                     *
*                                                                            *
*  @file     su_comm                                                         *
*  @brief    公共定义头文件                                                    *
*  Details.                                                                  *
*                                                                            *
*  @author   yumm                                                            *
*  @email    yumm@anmit.com                                                  *
*  @version  0.1                                                             *
*  @date     2017/10/24                                                      *
*                                                                            *
*----------------------------------------------------------------------------*
*  Remark         : Description                                              *
*----------------------------------------------------------------------------*
*  Change History :                                                          *
*  <Date>     | <Version> | <Author>       | <Description>                   *
*----------------------------------------------------------------------------*
*  2017/10/24 | 0.1.0     | 于明明          | 添加注释                         *
*----------------------------------------------------------------------------*
*                                                                            *
*****************************************************************************/


//
// Created by yumm on 2017/10/24.
//

#ifndef DPDK_FIREWALL_SU_COMM_H
#define DPDK_FIREWALL_SU_COMM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef likely
#define likely(x)      __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)    __builtin_expect(!!(x), 0)
#endif

#include <stdint.h>
#include <pthread.h>

#include "glib.h"


#ifdef __cplusplus
}
#endif

#endif //DPDK_FIREWALL_SU_COMM_H
