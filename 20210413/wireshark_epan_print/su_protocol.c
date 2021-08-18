/*****************************************************************************
*                                                                            *
*  Copyright (C) 2014 www.anmit.com All rights reserved.                     *
*                                                                            *
*  @file     protocol_define                                                 *
*  @brief    协议定义文件                                                      *
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
*  2017/10/24  | 0.1.0     | 于明明          | 添加注释                        *
*----------------------------------------------------------------------------*
*                                                                            *
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "glib.h"

#include "su_protocol.h"

int get_key_index(const struct su_protocol_define_t *protocol, const char *key) {
    gpointer index;
    gpointer key_temp;

    if (g_hash_table_lookup_extended(protocol->key_map, key, &key_temp, &index)) {
        return GPOINTER_TO_INT(index);
    }

    return -1;
}
