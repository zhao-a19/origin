/*******************************************************************************************
*文件:    parse_conf.h
*描述:    规则解析模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10

*1.在支持ftp nfs协议的情况下，兼容旧配置参数
*******************************************************************************************/
#include "global_define.h"


#ifndef __PARSECONF_H__
#define __PARSECONF_H__


int get_rule_num(const char *file_name);

int protocol_str_to_int(const char *protocol);

const char *protocol_int_to_str(int protocol);

int get_all_task_ID(const char *file_name, int all_rule_num, GList **id_list);

int get_all_rules_num(const char *file_name);

int get_oneway_diff(GKeyFile *keyfile, fs_oneway_t *oneway_task, const char *group_name);

int get_bothway_diff(GKeyFile *key_file, fs_bothway_t *bothway_task, const char *group_name);

int get_common_info(fs_rule_t *rule, const char *group_name, GKeyFile *keyfile);

int get_server_info(fs_server_t *srv_task, GKeyFile *keyfile, const char *group_name, const char *ptc_key, const char *usr_key,
                    const char *pwd_key, const char *real_ippath_key, const char *map_ippath_key,const char *subpath_key,
                    const char *port_key);

int get_sys_info(const char *file_name, SYSINFO *sys_info);

int get_rule_info(SYSINFO *sys_info, const char *file_name, fs_rule_t *rule, int rule_num);

int set_rule_info(fs_rule_t *rule, int rule_num);

int set_server_path(const char *group_name, const char *task_name, const char *host_name, fs_server_t *server);

void splice_path(const char *parent_path, const char *sub_path, char *full_path);


#endif //__PARSECONF_H_