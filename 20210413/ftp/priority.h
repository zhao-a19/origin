
/*******************************************************************************************
*文件:    priority.h
*描述:    多线程传输优先级处理
*
*作者:    张昆鹏
*日期:    2017-06-16
*修改:    创建文件                            ------>      2017-06-16
*修改:    优化优先级处理                      ------>  2017-07-07
*
*******************************************************************************************/
#ifndef __PRIORITY_H__
#define __PRIORITY_H__

#include <pthread.h>

#include "datatype.h"

#ifdef __cplusplus

extern "C" {

#endif


void priority_init(int32 cnt);
void priority_task_init(pthread_t tid, int32 level);
void priority_createpthread(void);
void priority_end(pthread_t tid);
int32 priority_pthread(pthread_attr_t *attr, int32 level);
int32 priority_end_task(int32 num);
int32 _priority_set(int32 num);
int32 priority_set(bool enable);


#ifdef __cplusplus

}
#endif

#endif


