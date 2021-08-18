/*******************************************************************************************
*文件: FCThread.h
*描述: 线程封装类
*作者: 王君雷
*日期:
*修改:
*        线程ID使用pthread_t类型                                    ------> 2018-08-07
*******************************************************************************************/
#ifndef __FC_THREAD_H__
#define __FC_THREAD_H__

#include <string.h>
#include <errno.h>
#include <pthread.h>

class CThread
{
public:
    CThread(void);
    virtual ~CThread(void);

public:
    int ThCreate(void *(*ThreadPro)(void *), void *para = NULL);
    int ThDelete(void);

private:
    pthread_t th_id;//线程ID
    pthread_attr_t attr;//线程属性结构
};

#endif
