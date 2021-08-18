
/*******************************************************************************************
*文件:    sqldb.h
*描述:    数据库配置
*
*作者:    张冬波
*日期:    2015-03-12
*修改:    创建文件                            ------>     2015-03-12
*         添加SQLITE支持                      ------>     2018-09-29
*
*******************************************************************************************/
#ifndef __SQLDB_H__
#define __SQLDB_H__

#include "datatype.h"

#ifdef __cplusplus
extern "C" {
#endif

const pchar SQLDB_NAME = "susqlroot";
const pchar SQLDB_PWD = "suanmitsql";

#ifdef SQLDB_LITE
#ifdef __CYGWIN__
const pchar SQLDB_DB = "c:\\su-anmit\\.suanmit.db";
#else
const pchar SQLDB_DB = "/var/log/.suanmit.db";
#endif

#else
const pchar SQLDB_ADDR = "localhost";
const pchar SQLDB_DB = "sudb";

#endif

#ifdef __cplusplus
}
#endif

#endif
