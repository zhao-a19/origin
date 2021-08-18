/*******************************************************************************************
*文件:    sysdir.h
*描述:    目录配置管理
*
*作者:    张冬波
*日期:    2015-01-05
*修改:    创建文件                            ------>     2015-01-05
*         增加模块启动路径，修改调试输出路径  ------>     2015-04-27
*         添加关键字过滤配置文件              ------>     2015-07-08
*         添加数据目录sudata通过web查看       ------>     2016-08-11
*         添加对客户端工具的支持              ------>     2016-11-07
*         调整目录树，将所有文件保存路径统一为sudata方便磁盘清理
*                                             ------>     2017-02-14
*         注意sudata为用户可通过页面查看文件信息路径
*                                             ------>     2017-03-02
*         添加对WEBSERVICE的支持              ------>     2018-05-02
*
*******************************************************************************************/
#ifndef __SYSDIR_H__
#define __SYSDIR_H__

#include "datatype.h"
#include "debugout.h"

//配置文件
const pchar DConfigFile = "/etc/init.d/DConfig.cfg";
const pchar ConfigFile = "/etc/init.d/Config.cfg";
const pchar BConfigFile = "/etc/init.d/BConfig.cfg";
const pchar KeysFile = "/etc/init.d/Key.cfg";
const pchar SysVerFile = "/initrd/ver/.versions";
const pchar SysModules = "/initrd/abin/";
const pchar DNSfile = "/etc/resolv.conf";

//系统目录
static struct _dirtype {
    const pchar path;
    const pchar type;

} ModleDIR[] = {
    {"/initrd/", " -p -m 660"},                 //系统根目录，必须位于第一位
    {"/initrd/data/sudata/", " -p -m 660"},
    {"/initrd/data/sudata/ftp/", " -p"},
    {"/initrd/data/sudata/mail/", " -p"},
    {"/initrd/data/tmp/", " -p"},
    {"/initrd/data/.bak/", " -p"},
    {"/initrd/ver/", " -p"},
    {"/initrd/data/mnttmp/", " -p"},
    {"/initrd/log/", " -p"},

    {"/initrd/viruslib/", "-m 660"},            //病毒动态库

    {"/initrd/data/sudata/cifs/", " -p"},       //FSHA模块子目录
    {"/initrd/data/sudata/cifs/", " -p"},       //smb与cifs统一
    {"/initrd/data/sudata/nfs/", " -p"},


    {"/etc/init.d/", " -m 770"},

    {"/initrd/data/sudata/homes/", " -p -m 660"},      //客户端
    {"/initrd/data/sudata/webserver/", " -p -m 660"},   //webservice

    {"/initrd/data/.dbg/", "  -p -m 777"},      //最尾端
    {"/initrd/data/.err/", "  -p -m 777"},      //最尾端
    {NULL, NULL}
};

#define DDIR_ROOT    1
#define DDIR_FTP     2
#define DDIR_MAIL    3
#define DDIR_TMP     4

#define DDIR_MNT     7
#define DDIR_LOG     8
#define DDIR_VIRUS   9

#define DDIR_CLIENT  14
#define DDIR_WEBS    15

#define DDIR_DBG     16

#define DDIR_NULL    18

#endif

