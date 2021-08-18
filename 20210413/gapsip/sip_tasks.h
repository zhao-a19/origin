/*******************************************************************************************
*文件:    sip_tasks.h
*描述:    SIP服务任务
*
*作者:    张冬波
*日期:    2018-04-20
*修改:    创建文件                          ------>     2018-04-20
*
*
*******************************************************************************************/
#include "datatype.h"
#include "FCLogManage.h"

#ifndef __SIP_TASKS_H__
#define __SIP_TASKS_H__

#define SIP_TASKMAX     50      //支持的最大服务数

typedef enum {
    SIP_TASKE = 1,  //外网端
    SIP_TASKI,      //内网端
} SIPMODE;

typedef struct _siptask {
    //SIPMODE flag;

    char name[100];
    char srvip[40];
    char srvport[10];
    uint32 SN;          //参数编号,不可重复
    bool disabled;

} sip_task, *psip_task;

void sip_init(void);
int32 sip_createtask(psip_task sip_arg);

#endif

