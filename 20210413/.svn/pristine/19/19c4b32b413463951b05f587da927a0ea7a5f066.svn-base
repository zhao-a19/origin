/*******************************************************************************************
*文件:    zdb_porting.h
*描述:    移植suricata-3.0.1关于DCERPC协议解析
*         必须包含在suricata-common.h的文件首部
*         util-unittest.h和util-debug.h需要根据系统改写
*         config.h需要由原始工程的configure生成，注：需要在同一平台运行
*
*作者:    张冬波
*日期:    2016-05-05
*修改:    创建文件                            ------>     2016-05-05
*         修改交叉编译错误                    ------>     2016-09-21
*         error: expected declaration specifiers or ‘...’ before ‘__locale_t’
*
*******************************************************************************************/
#ifndef __ZDB_PORTING_H__
#define __ZDB_PORTING_H__

//pcap使用
#include <sys/types.h>

//研华环境time.h报错
#include <xlocale.h>

#include "datatype.h"

//影响util-atomic.h的使用
#define CPPCHECK 1

//suricatat.h

/* Engine stage/status*/
enum {
    SURICATA_INIT = 0,
    SURICATA_RUNTIME,
    SURICATA_DEINIT
};

#endif
