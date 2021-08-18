/*******************************************************************************************
*文件:  srtlist.h
*描述:  通过输入框、下拉框添加的路由列表
*作者:  王君雷
*日期:  2020-08-31
*修改:
*******************************************************************************************/
#ifndef __S_RT_LIST__H__
#define __S_RT_LIST__H__

#include "define.h"

#define NOT_SPECIFY_CARD "999" //不指定网卡出口时使用的字符串

//在WEB界面通过下拉框方式添加的路由信息
class SPINNERRLIST {
public:
    char dstip[IP_STR_LEN];    //目的网段地址
    char dstmask[MASK_STR_LEN];//目的网段掩码  或 前缀长度
    char gw[IP_STR_LEN];       //下一跳
    char dev[20];              //出口接口 eth0 等
    int metric;                //跃点数
    int iptype;                //IP类型 ipv4 or ipv6

public:
    SPINNERRLIST(void);
    ~SPINNERRLIST(void);
    const char* combineRoute(char* chcmd);
};

#endif
