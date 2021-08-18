/*******************************************************************************************
*文件: update_parser.h
*描述: 升级包解析
*作者: 王君雷
*日期: 2018-10-10
*修改：
*      添加both目录，可以同时升级内外网文件                             ------> 2020-02-20 wjl
*******************************************************************************************/

#ifndef __UPDATE_PARSER_H__
#define __UPDATE_PARSER_H__

#include "update_make.h"

#define UPDATE_PASR_TMPTAR  "/tmp/update.parsertmp" //解析升级包时 创建的临时tar文件
#define UPDATE_PASR_TMPDIR  "/tmp/update.dir/"      //解压临时tar文件时使用的临时目录
#define UPDATE_PASR_STAT    "/tmp/upk.info"
#define RESTART               "/etc/init.d/restart"
#define CMDPROXY              "/initrd/abin/cmdproxy"


typedef bool (*FILE_POLICY)(const char *orgpath, FILE_HEAD &filehead); //处理文件的策略方式
bool print_updatepack(const char *filename);
bool uppack_updatepack(const char *filename, TOTAL_HEAD &totalhead, char *chsysver = NULL);
bool update_mkdir(const char *filepath);
bool unpack_tmptar();
bool check_updatepack_size(const char *filename, bool hassysver);
bool scandir_file(FILE_POLICY fun);
bool get_modname(const char *fname);

#endif
