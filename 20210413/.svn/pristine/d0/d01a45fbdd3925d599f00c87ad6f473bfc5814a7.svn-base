/*******************************************************************************************
*文件:    datatype.h
*描述:    基本数据类型定义
*
*作者:    张冬波
*日期:    2014-11-13
*修改:    创建文件                    ------>     2014-11-13
*         添加unix标准头文件          ------>     2014-11-28
*         添加DWORD宏定义             ------>     2015-03-25
*         添加临时数据空间最大值      ------>     2015-04-13
*         修改指针定义                ------>     2015-05-04
*         修改32位定义                ------>     2015-12-22
*         64位系统编译兼容性          ------>     2017-03-08
*
*******************************************************************************************/

#ifndef __DATATYPE_H__
#define __DATATYPE_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>     //unix system

typedef long long int64;
typedef long long *pint64;
typedef unsigned long long uint64;
typedef unsigned long long *puint64;

typedef int int32;
typedef int *pint32;
typedef unsigned int uint32;
typedef unsigned int *puint32;

typedef short int16;
typedef short *pint16;
typedef unsigned short uint16;
typedef unsigned short *puint16;

typedef char int8;
typedef char *pint8;
typedef unsigned char uint8;
typedef unsigned char *puint8;

typedef char *pchar;
typedef const char *cpchar;

typedef char CHAR;
typedef float FLOAT;
typedef float *pfloat;

typedef double DOUBLE;
typedef double *pdouble;

typedef unsigned int uint;

#define MAKEDWORD(h, l) (((uint32)(h))<<16|(((uint32)(l))&(0xffffuL)))
#define LOWORD(w) ((uint16)(((uint32)(w))&(0xffffuL)))
#define HIWORD(w) ((uint16)((((uint32)(w))>>16)&(0xffffuL)))

#define MIN(a,b) ((a) > (b) ? (b) : (a))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define SWAP(a,b) {a = (a)+(b); b = (a)-(b); a = (a)-(b);}

#define TMPBUFFMAX (8192)

//指针长度
#if __WORDSIZE == 64
typedef unsigned long ptr_t;        //64位
#else
typedef unsigned int ptr_t;         //32位
#endif
#define ptr_diff(p1, p2) (size_t)((ptr_t)((p1)-(p2)))

#endif

