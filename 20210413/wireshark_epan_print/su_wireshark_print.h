/*****************************************************************************
*                                                                            *
*  Copyright (C) 2017 www.anmit.com All rights reserved.                     *
*                                                                            *
*  @file     wireshark_print                                                 *
*  @brief                                                                    *
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

#ifndef DPDK_FIREWALL_WIRESHARK_PRINT_H
#define DPDK_FIREWALL_WIRESHARK_PRINT_H

#ifdef __cplusplus
extern "C" {
#endif

#define WS_MSVC_NORETURN

#include "glib.h"
#include "su_comm.h"
#include "su_protocol.h"
#include "epan/epan_dissect.h"

#define WIRESHARK_PRINT_DETAIL 0

int write_pdml_proto_tree_level(epan_dissect_t *edt, char *buf, const struct su_protocol_define_t *protocol, GSList **kv);
void su_wireshark_print_init(void);

#ifdef __cplusplus
}
#endif

#endif //DPDK_FIREWALL_WIRESHARK_PRINT_H
