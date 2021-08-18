/*******************************************************************************************
*文件: au_define.h
*描述: 授权服务相关使用到的一些宏
*作者: 王君雷
*日期: 2018-10-15
*修改:
*******************************************************************************************/
#ifndef __AU_DEFINE_H__
#define __AU_DEFINE_H__

#ifndef CMD_BUF_LEN
#define CMD_BUF_LEN 1024
#endif

#ifndef BZERO
#define BZERO(ch) memset(&(ch), 0, sizeof(ch))
#endif

#endif
