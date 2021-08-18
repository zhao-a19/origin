/*******************************************************************************************
*文件:  FCVirusAPI.h
*描述:  查毒接口
*作者:  王君雷
*日期:  2016-03
*修改:
*      把病毒库查杀服务的本地套接字路径放到gap_config.h中               ------> 2018-08-07
*******************************************************************************************/
#ifndef __FC_VIRSEAPI_H__
#define __FC_VIRSEAPI_H__

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gap_config.h"

const int E_OK = 1;
const int E_FALSE = -1;

const int C_FILE_NOCODE = 300;   //文件未编码
const int C_FILE_BASE64CODE = 301;//文件用BASE64编码
const int C_FILE_QTCODE = 302;   //文件QT编码
//KVEngine
const int C_MAX_PATH  = 300;
const int C_INITS_NUM = 1;   //要初始化的Instance数
const int C_MAX_INITS = 30;  //系统允许的最大Instance数

const int E_FINDED_VIRUS = -400;
const int E_KV_SUCCESS = 401;
const int E_KV_FALSE = -401;

int FileSearchVirus(char *chFileName, int iCodeType = C_FILE_NOCODE, char *virusname = "");

#endif
