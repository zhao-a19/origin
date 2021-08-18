/*******************************************************************************************
*文件:  StartxmppInst.h
*描述:  开启xmpp任务实例
*作者:  王君雷
*日期:  2020-08-17
*修改:
*******************************************************************************************/
#ifndef __START_XMPP_INST_H__
#define __START_XMPP_INST_H__

#include <stdio.h>
#include <unistd.h>
#include "FCSysRulesBS.h"
#include "filename.h"
#include "common.h"

#define XMPP_ADDR_MAX 2048
#define XMPP_ADDR_INT_FILE    "/etc/init.d/xmpp_int.cfg"
#define XMPP_ADDR_EXT_FILE    "/etc/init.d/xmpp_ext.cfg"
#define XMPP_ADDR_TMP_FILE    "/tmp/xmpp_tmp.cfg"
#define XMPP_FILE_HEAD_LEN 5
#define XMPP_FILE_DATA_LEN 40
#define XMPP_FROM 1
#define XMPP_TO 2
#define XMPP_ONE_DAY_S (24 * 60 * 60)

#define XMPP_NOT_FILE -1      //非xmpp传输文件
#define XMPP_FILE_SUCCESS 0   //xmpp传输文件
#define XMPP_FILE_FAILD 1     //xmpp传输文件失败
#define XMPP_PLATFORM 10     //xmpp平台类型个数
#define XMPP_IP_LEN 20
#define XMPP_S 0
#define XMPP_R 1
#define XMPP_S_F_NUM 2

/**
 * [StartxmppInst 启动xmpp处理实例]
 * @param  rule  [规则指针]
 * @param  tip   [代理IP]
 * @param  midip [中间跳转IP]
 * @param  dip   [目的IP]
 * @param  appno [应用编号]
 * @return       [成功返回0]
 */
int StartxmppInst(CSYSRULES *rule, char *tip, char *midip, char *dip, int appno);

//海关环境scp ip 和from ip对应关系
typedef struct {
    char from[XMPP_ADDR_MAX];
    char src[XMPP_ADDR_MAX];
} xmppsf, *pxmppsf;
//需要传递给线程使用的参数
typedef struct {
    int seqno;
    int infd;
    char sip[IP_STR_LEN];
    char tip[IP_STR_LEN];
    char midip[IP_STR_LEN];
    char dip[IP_STR_LEN];
    char tport[PORT_STR_LEN];
    int appno;
    CSYSRULES *rule;
    char authname[AUTH_NAME_LEN];
    char ch_cmd[MAX_CMD_NAME_LEN];
    char ch_param[MAX_PARA_NAME_LEN];
    int expire_time;
    xmppsf src_from[XMPP_S_F_NUM];
} xmppPara;

//需要传递给线程使用的参数
typedef struct {
    bool is_del;
    uint64 starttime;
    char from[XMPP_ADDR_MAX];
    char to[XMPP_ADDR_MAX];
} xmppfileinfo, *pxmppfileinfo;

#define MAX_PARAM_NUM 3 //命令参数个数
enum XMPP_PARAM {
    XMPP_STATUS = 0,
    XMPP_TYPE,
    XMPP_MESSAGE
};
#endif
