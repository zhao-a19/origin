/*******************************************************************************************
*文件:    util-debug.h
*描述:
*
*作者:    张冬波
*日期:    2016-05-05
*修改:    创建文件                            ------>     2016-05-05
*
*******************************************************************************************/
#ifndef __UTIL_DEBUG_H__
#define __UTIL_DEBUG_H__

#include <stdio.h>
#include <stdint.h>
#include "pcre.h"

#include "debugout.h"

//程序日志，##用法可以忽略可变参数
#define SCLogInfo(format, ...) do{PRINT_INFO_HEAD; print_info(format, ##__VA_ARGS__);}while(0)
#define SCLogDebug(format, args...) do{PRINT_DBG_HEAD; print_dbg(format, ##args);}while(0)
#define SCLogError(l, format, ...) do{PRINT_ERR_HEAD; print_err(format, ##__VA_ARGS__);}while(0)
#define SCLogWarning(l, format, ...) do{PRINT_ERR_HEAD; print_err(format, ##__VA_ARGS__);}while(0)
//#define DEBUG __DEBUG_MORE__

#define SCEnter(...)  do{SCLogDebug("Entering ... >>");}while(0)

#define SCReturn      do{SCLogDebug("Returning ... <<");return;}while(0)

#define SCReturnInt(x)                  do{SCLogDebug("Returning: %"PRIdMAX" ... <<", (intmax_t)x); \
                                        return x;}while(0)

#define SCReturnUInt(x)                 do{SCLogDebug("Returning: %"PRIuMAX" ... <<", (uintmax_t)x); \
                                        return x;}while(0)

#define SCReturnDbl(x)                  do{SCLogDebug("Returning: %f ... <<", x); \
                                        return x;}while(0)

#define SCReturnChar(x)                 do{SCLogDebug("Returning: %c ... <<", x); \
                                        return x;}while(0)

#define SCReturnCharPtr(x)              do {                                              \
                                          if ((x) != NULL) {                              \
                                                  SCLogDebug("Returning: %s ... <<", x);  \
                                          } else {                                        \
                                                  SCLogDebug("Returning: NULL ... <<");   \
                                          }                                               \
                                        return x;} while(0)

#define SCReturnCT(x, type)             do {SCLogDebug("Returning var of type %s ... <<", type);  \
                                        return x;} while(0)

#define SCReturnPtr(x, type)            do {SCLogDebug("Returning pointer %p of %s ... <<", x, type);  \
                                        return x;} while(0)

inline int SCLogDebugEnabled(void) {return 1;}

#endif

