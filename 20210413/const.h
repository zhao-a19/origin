/*******************************************************************************************
*文件:  const.h
*描述:  系统常量信息
*作者:  王君雷
*日期:
*修改:
*       组播使用英语multicast代理拼音                                ------> 2018-02-05
*       与SIP相关的宏移动到文件sip_struct.h中                        ------> 2018-07-13
*       WEB代理最大任务支持数由10放大到20                            ------> 2018-07-18
*       临界值相关宏移出到critical.h,读写标识移入                    ------> 2018-12-21
*******************************************************************************************/
#ifndef __CONST_H__
#define __CONST_H__

//协议读写标识
enum {
    PROTO_READ = 0,
    PROTO_WRITE = 1,
    PROTO_RW = 2,
    PROTO_RWNULL = -1,
};

const int E_OK = 1;
const int E_FALSE = -1;                 //一般错误
const int E_OPENFILE_ERROR = -99;       //打开文件出错
const int E_SYSRULE_EXIST = -133;       //系统规则存在
const int E_SYSRULE_NO_EXIST  = -134;   //系统规则不存在
const int E_SYSRULE_FULL  = -135;       //系统规则已经满

const char ALLIP[20] = "0.0.0.0";
const char ALLMAC[20] = "00:00:00:00:00:00";
const char IPV6ALLIP[] = "::";


#endif
