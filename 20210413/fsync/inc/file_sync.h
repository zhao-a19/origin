/*******************************************************************************************
*文件:    file_sync.h
*描述:    文件同步模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10

*1.合并差异化扫描函数。                                        ------>     2020-02-24
*2.修改双向文件同步删除返回值                                  ------> 2020-03-01
*3.封装全量扫描与增量扫描                                      ------> 2020-03-05
*4.精简函数入参                                                ------> 2020-03-13
*5.删除清除发送列表函数                                        ------> 2020-03-18
*******************************************************************************************/

#ifndef __FILESYNC_H__
#define __FILESYNC_H__

#include "global_define.h"
#include "record_manager.h"
#include "FCLogManage.h"
#include "smb_sync.h"


#define FSYNC_DELETE_SUCCESS 2
#define FSYNC_SEND_SUCCESS   1
#define FSYNC_NOT_SEND       0
#define FSYNC_SEND_FAILED   -1
#define FSYNC_DELETE_FAILED -2


bool create_task(fs_rule_t *rule);





#endif //__FILESYNC_H__