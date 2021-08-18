/*******************************************************************************************
*文件:    parse_conf.cpp
*描述:    规则解析模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------> 2019-11-10
*1.取消对线程数的读取，改为动态分配业务线程                    ------> 2020-03-03
*2.修改部分读取配置文件日志等级                                ------> 2020-03-05
*3.任务名称生成方式由base64替换为哈希计算                      ------> 2020-03-26
*4.支持ftp nfs协议情况下兼容旧配置文件                         ------> 2020-05-29
*5.修复syslog及前台日志开关逻辑                                ------> 2020-07-23
*******************************************************************************************/
#include "parse_conf.h"
#include "common_func.h"

/*******************************************************************************************
*功能:      获取规则数
*参数:      file_name           ----> 配置文件路径名
*                            
*           返回值              ----> >0 策略数 , -1 失败
*
*注释:
*******************************************************************************************/
int get_rule_num(const char *file_name) {
    int tmpint = 0;
    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();

    g_key_file_load_from_file(keyfile, file_name, G_KEY_FILE_NONE, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("load fsync configure = %s failed !", file_name);
        g_error_free(key_error);
        g_key_file_free(keyfile);
        return -1;
    }
    tmpint = g_key_file_get_integer(keyfile, "SYS", "TaskNum", &key_error);
    if (key_error) {
        tmpint = -1;
        PRINT_ERR_HEAD;
        print_err("parse TaskNum failed !");
        g_error_free(key_error);
    } else {
        PRINT_INFO_HEAD;
        print_info("parse TaskNum = %d", tmpint);
    }
    g_key_file_free(keyfile);
    return tmpint;
}

/*******************************************************************************************
*功能:      获取全部测规则数
*参数:      file_name           ----> 配置文件路径名
*
*           返回值              ----> >0 策略数 , -1 失败
*
*注释:
*******************************************************************************************/
int get_all_rules_num(const char *file_name) {

    char buf[8] = {0};
    int tmpint = -1;
    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();

    g_key_file_load_from_file(keyfile, file_name, G_KEY_FILE_NONE, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("load fsync configure = %s failed !", file_name);
        g_error_free(key_error);
        g_key_file_free(keyfile);
        return -1;
    }
    char *tmp_str = g_key_file_get_string(keyfile, "MAIN", "Num", &key_error);

    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("parse TaskNum failed !");
        g_error_free(key_error);
        return -1;
    }
    if (!del_special_char(tmp_str, buf)) {
        tmpint = -1;
        PRINT_ERR_HEAD;
        print_err("get str ' for %s failed", tmp_str);
    } else {
        tmpint = atoi(buf);
        PRINT_INFO_HEAD;
        print_info("parse all Num = %d", tmpint);
    }

    g_free(tmp_str);
    g_key_file_free(keyfile);

    return tmpint;
}

/*******************************************************************************************
*功能:      获取全部测规则ID
*参数:      file_name           ----> 配置文件路径名
*           all_rule_num        ----> 规则个数
*           id_list             ----> 规则ID列表
*           返回值               ----> >0 策略数 , -1 失败
*
*注释:
*******************************************************************************************/
int get_all_task_ID(const char *file_name, int all_rule_num, GList **id_list) {

    char group_name[FSYNC_NAME_MAX_LEN] = {0};
    char buf[FSYNC_NAME_MAX_LEN] = {0};
    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();
    g_key_file_load_from_file(keyfile, file_name, G_KEY_FILE_NONE, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("load fsync configure = %s failed !", file_name);
        g_error_free(key_error);
        g_key_file_free(keyfile);
        return -1;
    }

    int ret = 0;
    for (int i = 0; i < all_rule_num; i++) {
        memset(buf, 0, sizeof(buf));
        sprintf(group_name, "TASK%d", i);
        //ID值生成的taskname加入列表
        char *tmp_str = g_key_file_get_string(keyfile, group_name, "ID", &key_error);
        if (key_error) {
            g_error_free(key_error);
            key_error = NULL;
            PRINT_ERR_HEAD;
            print_err("parse file = %s ,group = %s ,key = ID failed!", file_name, group_name);
        } else {
            if (!del_special_char(tmp_str, buf)) {
                ret = -1;
                PRINT_ERR_HEAD;
                print_err("parse for key = ID failed!");
                break;
            }
            g_free(tmp_str);
            char *id_name = (char *) calloc(FSYNC_NAME_MAX_LEN, sizeof(char));
            sprintf(id_name, "task%s", buf);
            *id_list = g_list_prepend(*id_list, id_name);
            PRINT_DBG_HEAD;
            print_dbg("make task name = %s", id_name);
        }

        //策略名哈希值生成的taskname加入列表
        memset(buf, 0, sizeof(buf));
        tmp_str = g_key_file_get_string(keyfile, group_name, "name", &key_error);
        if (key_error) {
            ret = -1;
            g_error_free(key_error);
            key_error = NULL;
            PRINT_ERR_HEAD;
            print_err("parse file = %s ,group = %s ,key = name failed!", file_name, group_name);
            break;
        }
        if (!del_special_char(tmp_str, buf)) {
            ret = -1;
            PRINT_ERR_HEAD;
            print_err("parse for key = name failed!");
            break;
        }
        g_free(tmp_str);
        char *hash_name = (char *) calloc(FSYNC_NAME_MAX_LEN, sizeof(char));
        sprintf(hash_name, "task%u", g_str_hash(buf));
        *id_list = g_list_prepend(*id_list, hash_name);
        PRINT_DBG_HEAD;
        print_dbg("make task name = %s", hash_name);

    }

    g_key_file_free(keyfile);

    return ret;
}

int protocol_str_to_int(const char *protocol) {

    if (strcmp(protocol, "nfs") == 0) {
        return FSYNC_NFS_PROTOCOL;
    } else if (strcmp(protocol, "cifs") == 0) {
        return FSYNC_CIFS_PROTOCOL;
    } else if (strcmp(protocol, "ftp") == 0) {
        return FSYNC_FTP_PROTOCOL;
    } else if (strcmp(protocol, "sftp") == 0) {
        return FSYNC_SFTP_PROTOCOL;
    } else if (strcmp(protocol, "ftps") == 0) {
        return FSYNC_FTPS_PROTOCOL;
    } else {
        PRINT_ERR_HEAD;
        print_err("protocol = %s not suppose !", protocol);
        return -1;
    }

}

const char *protocol_int_to_str(int protocol) {

    switch (protocol) {
        case FSYNC_CIFS_PROTOCOL:
            return "cifs";
        case FSYNC_NFS_PROTOCOL:
            return "nfs";
        case FSYNC_FTP_PROTOCOL:
            return "ftp";
        case FSYNC_SFTP_PROTOCOL:
            return "sftp";
        case FSYNC_FTPS_PROTOCOL:
            return "ftps";
        default: PRINT_ERR_HEAD;
            print_err("not support protocol");
            return "err";
    }
}

/*******************************************************************************************
*功能:      获取单向特殊规则
*参数:       key_file           ----> 关键文件
*           oneway_task        ----> 单向特殊选项结构体
*           group_name         ----> 组名
*                    
*                            
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_oneway_diff(GKeyFile *keyfile, fs_oneway_t *oneway_task, const char *group_name) {
    GError *key_error = NULL;
    oneway_task->del_source = g_key_file_get_integer(keyfile, group_name, "Del", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read Del failed !", group_name);
        return -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,Del = %d", group_name, oneway_task->del_source);
    }


    oneway_task->rename_flag = g_key_file_get_integer(keyfile, group_name, "RenameDest", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read RenameDest failed !", group_name);
        return -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,RenameDest = %d", group_name, oneway_task->rename_flag);
    }

    return 0;
}

/*******************************************************************************************
*功能:      获取双向特殊规则
*参数:       key_file           ----> 关键文件
*           bothway_task       ----> 单向特殊选项结构体
*           group_name         ----> 组名
*                    
*                            
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_bothway_diff(GKeyFile *keyfile, fs_bothway_t *bothway_task, const char *group_name) {
    GError *key_error = NULL;
    bothway_task->std_area = g_key_file_get_integer(keyfile, group_name, "StdArea", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read StdArea failed ,default:0", group_name);
        bothway_task->std_area = 0;
        g_error_free(key_error);
        key_error = NULL;
        //return -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,StdArea = %d", group_name, bothway_task->std_area);
    }

    bothway_task->sync_del = g_key_file_get_integer(keyfile, group_name, "BidirectionalDel", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read BidirectionalDel failed!", group_name);
        return -1;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,BidirectionalDel = %d", group_name, bothway_task->sync_del);
    }

    return 0;
}

/*******************************************************************************************
*功能:      获取通用规则信息
*参数:      rule               ----> 策略信息(值结果)
*           group_name         ----> 组名
*           key_file           ----> 关键文件
*                    
*                            
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_common_info(fs_rule_t *rule, const char *group_name, GKeyFile *keyfile) {
    GError *key_error = NULL;
    char *tmp_str = NULL;
    int ret = 0;

    //获取策略名称
    tmp_str = g_key_file_get_string(keyfile, group_name, "TaskName", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("read [%s] TaskName failed !", group_name);
        g_error_free(key_error);
        key_error = NULL;
        goto _exit;
    } else {
        if (del_special_char(tmp_str, rule->rule_name)) {
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,Taskname = %s", group_name, rule->rule_name);
            g_free(tmp_str);
        } else {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,Taskname = %s", group_name, tmp_str);
            g_free(tmp_str);
            return -1;
        }
    }

    //获取策略ID
    tmp_str = g_key_file_get_string(keyfile, group_name, "ID", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("read [%s] ID failed !", group_name);
        g_error_free(key_error);
        key_error = NULL;
        unsigned int hash = g_str_hash(rule->rule_name);
        if (hash == 0) {
            goto _exit;
        } else {
            sprintf(rule->task_name, "task%u", hash);
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,Task name = %s", group_name, rule->task_name);
        }
    } else {
        if (strspn(tmp_str, "0123456789") == strlen(tmp_str)) {  //非md5sum生成
            sprintf(rule->task_name, "task%s", tmp_str);
        } else {
            unsigned int hash = g_str_hash(rule->rule_name);
            if (hash == 0) {
                goto _exit;
            } else {
                sprintf(rule->task_name, "task%u", hash);
            }
        }
        g_free(tmp_str);
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,Task name = %s", group_name, rule->task_name);
    }


    //获取扫描间隔
    rule->scan_time = g_key_file_get_integer(keyfile, group_name, "SyncCycle", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read SyncCycle failed!", group_name);
        g_error_free(key_error);
        key_error = NULL;
        goto _exit;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,SyncCycle = %d", group_name, rule->scan_time);
    }

    //获取临时文件后缀
    tmp_str = g_key_file_get_string(keyfile, group_name, "TempFile", &key_error);
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read TempFile failed !", group_name);
        goto _exit;
    } else if (strlen(tmp_str) > 0) {
        sprintf(rule->tmp_extname, ".%s", tmp_str);
        g_free(tmp_str);
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,TempFile = %s", group_name, rule->tmp_extname);
    } else {
        rule->tmp_extname[0] = '\0';
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,TempFile len = 0", group_name);
    }

    //获取延迟检查时间
    rule->delay_time = g_key_file_get_integer(keyfile, group_name, "AfterTime", &key_error);
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        rule->delay_time = 0;
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read AfterTime failed ,default: 0", group_name);
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,AfterTime = %d", group_name, rule->delay_time);
    }

    //获取日志记录开关
    rule->log_flag = g_key_file_get_integer(keyfile, group_name, "RecordLog", &key_error);
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read RecordLog failed !", group_name);
        goto _exit;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,RecordLog = %d", group_name, rule->log_flag);
    }

    //获取文件后缀过滤开关
    rule->filter_flag = g_key_file_get_integer(keyfile, group_name, "FilterFlag", &key_error);
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read FilterFlag failed !", group_name);
        goto _exit;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,FilterFlag = %d", group_name, rule->filter_flag);
    }

    if (rule->filter_flag != 0) {
        //获取后缀列表
        tmp_str = g_key_file_get_string(keyfile, group_name, "FilterList", &key_error);
        if (key_error) {
            g_error_free(key_error);
            key_error = NULL;
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,read FilterList failed !", group_name);
            goto _exit;
        } else {
            sprintf(rule->filter_list, ",%s,", tmp_str);
            g_free(tmp_str);
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,FilterList = %s", group_name, rule->filter_list);
        }
    }

    //获取同步方向
    rule->sync_area = g_key_file_get_integer(keyfile, group_name, "Area", &key_error);
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read Area failed !", group_name);
        goto _exit;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,Area = %d", group_name, rule->sync_area);
    }

    //获取同步记录删除开关
    rule->del_record = g_key_file_get_integer(keyfile, group_name, "DelRecord", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read DelRecoder failed ,default:0", group_name);
        rule->del_record = 0;
        g_error_free(key_error);
        key_error = NULL;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,DelRecoder = %d", group_name, rule->del_record);
    }

    _exit:
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        ret = -1;
    }
    return ret;
}

/*******************************************************************************************
*功能:      获取服务器规则信息
*参数:      srv_task            ----> 服务器任务结构(值结果)
*           key_file           ----> 关键文件
*           group_name         ----> 组名
*           ptc_key            ----> 协议配置项关键字
*           usr_key            ----> 用户配置项关键字
*           pwd_key            ----> 密码配置项关键字
*           real_ippath_key    ----> 真实IP路径关键字
*           map_ippath_key     ----> 映射IP路径关键字
*           subpath_key        ----> 子路径关键字
*           port_key           ----> 端口配置项关键字
*                    
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_server_info(fs_server_t *srv_task, GKeyFile *keyfile, const char *group_name, const char *ptc_key,
                    const char *usr_key, const char *pwd_key, const char *real_ippath_key, const char *map_ippath_key,
                    const char *subpath_key, const char *port_key) {
    int ret = 0;
    char *tmp_str = NULL;
    GError *key_error = NULL;
    char real_ippath[FSYNC_PATH_MAX_LEN] = {0};
    char map_ippath[FSYNC_PATH_MAX_LEN] = {0};
    //获取协议
    tmp_str = g_key_file_get_string(keyfile, group_name, ptc_key, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read %s failed !", group_name, ptc_key);
        goto _exit;
    } else {
        srv_task->protocol = protocol_str_to_int(tmp_str);
        if (srv_task->protocol < 0) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,%s = %s ,not suppose !", group_name, ptc_key, tmp_str);
            goto _exit;
        }
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,%s = %s ,int type = %d", group_name, ptc_key, tmp_str, srv_task->protocol);
        g_free(tmp_str);
    }

    if (srv_task->protocol != FSYNC_NFS_PROTOCOL) {
        //获取用户名
        tmp_str = g_key_file_get_string(keyfile, group_name, usr_key, &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,read %s failed !", group_name, usr_key);
            goto _exit;
        } else {
            strcpy(srv_task->user, tmp_str);
            g_free(tmp_str);
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,%s = %s", group_name, usr_key, srv_task->user);
        }

        //获取密码
        tmp_str = g_key_file_get_string(keyfile, group_name, pwd_key, &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,read %s failed !", group_name, pwd_key);
            g_error_free(key_error);
        } else {
            strcpy(srv_task->pwd, tmp_str);
            g_free(tmp_str);
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,%s = %s ", group_name, pwd_key, srv_task->pwd);
        }
    }

    //获取主机实际IP路径
    tmp_str = g_key_file_get_string(keyfile, group_name, real_ippath_key, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read %s failed !", group_name, real_ippath_key);
        goto _exit;
    } else {
        strcpy(real_ippath, tmp_str);
        g_free(tmp_str);
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,%s = %s", group_name, real_ippath_key, real_ippath);
    }
    //获取真实IP
    if (get_str(real_ippath, "//", "/", srv_task->real_ip)) {
        PRINT_DBG_HEAD;
        print_dbg("group = [%s] ,real remote_ip = %s", group_name, srv_task->real_ip);
    } else {
        PRINT_ERR_HEAD;
        print_err("get real remote_ip from %s failed", real_ippath);
        goto _exit;
    }
    //获取共享目录
    if ((srv_task->protocol & FSYNC_FILE_SYSTEM) != FSYNC_FTP_TYPE) {
        strcpy(srv_task->share_path, real_ippath + strlen(srv_task->real_ip) + 3);
        PRINT_DBG_HEAD;
        print_dbg("group = [%s] ,share path = %s", group_name, srv_task->share_path);
    }

    //获取网闸实际使用路径
    tmp_str = g_key_file_get_string(keyfile, group_name, map_ippath_key, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read %s failed !", group_name, map_ippath_key);
        goto _exit;
    } else {
        strcpy(map_ippath, tmp_str);
        g_free(tmp_str);
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,%s = %s", group_name, map_ippath_key, map_ippath);
    }
    //获取使用IP
    if (get_str(map_ippath, "//", "/", srv_task->use_ip)) {
        PRINT_DBG_HEAD;
        print_dbg("group = [%s] ,use remote_ip = %s", group_name, srv_task->use_ip);
    } else {
        PRINT_ERR_HEAD;
        print_err("get real remote_ip from %s failed", real_ippath);
        goto _exit;
    }

    //获取端口
    srv_task->port = g_key_file_get_integer(keyfile, group_name, port_key, &key_error);
    if (key_error) {
        if (srv_task->protocol == FSYNC_CIFS_PROTOCOL) {
            srv_task->port = 445;
        } else if (srv_task->protocol == FSYNC_NFS_PROTOCOL) {
            srv_task->port = 2049;
        } else if (srv_task->protocol == FSYNC_SFTP_PROTOCOL) {
            srv_task->port = 22;
        } else {
            srv_task->port = 21;
        }
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read %s failed ,default:445", group_name, port_key);
        g_error_free(key_error);
        key_error = NULL;
    } else {
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,%s = %d", group_name, port_key, srv_task->port);
    }

    //获取子路径
    tmp_str = g_key_file_get_string(keyfile, group_name, subpath_key, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("group = [%s] ,read %s failed", group_name, subpath_key);
        g_error_free(key_error);
        key_error = NULL;
    } else {
        strcpy(srv_task->sub_path, tmp_str);
        g_free(tmp_str);
        PRINT_INFO_HEAD;
        print_info("group = [%s] ,%s = %s", group_name, subpath_key, srv_task->sub_path);
    }

    //对ftp和sftp添加默认子路径
    if ((srv_task->protocol & FSYNC_FILE_SYSTEM) == FSYNC_FTP_TYPE) {
        if ((strlen(srv_task->sub_path) == 0) && (srv_task->protocol == FSYNC_FTP_PROTOCOL)) {
            strcpy(srv_task->sub_path, "./");
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,ftp %s = %s", group_name, subpath_key, srv_task->sub_path);
        }
        if ((strlen(srv_task->sub_path) == 0) && (srv_task->protocol == FSYNC_SFTP_PROTOCOL)) {
            strcpy(srv_task->sub_path, "./");
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,sftp %s = %s", group_name, subpath_key, srv_task->sub_path);
        }
    }


    _exit:
    if (key_error) {
        ret = -1;
        g_error_free(key_error);
    }
    return ret;
}


/*******************************************************************************************
*功能:      获取系统设置信息
*参数:       sys_info           ----> 系统设置信息
*           file_name          ----> 配置文件名
*
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_sys_info(const char *file_name, SYSINFO *sys_info) {

    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();

    g_key_file_load_from_file(keyfile, file_name, G_KEY_FILE_NONE, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("load global configure = %s failed:%s!", file_name, key_error->message);
        g_error_free(key_error);
        key_error = NULL;
        return -1;
    }

    sys_info->syslog_flag = g_key_file_get_integer(keyfile, "SYSTEM", "LogType", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("global syslog flag failed ,default:0!");
        g_error_free(key_error);
        key_error = NULL;
        sys_info->syslog_flag = FSYNC_TURN_OFF;
    } else {
        PRINT_INFO_HEAD;
        print_info("global syslog flag = %d ", sys_info->syslog_flag);
    }

    sys_info->record_flag = g_key_file_get_integer(keyfile, "SYSTEM", "RecordLog", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("global record flag failed ,default:0!");
        g_error_free(key_error);
        key_error = NULL;
        sys_info->record_flag = FSYNC_TURN_OFF;
    } else {
        PRINT_INFO_HEAD;
        print_info("global record flag = %d ", sys_info->record_flag);
    }

    sys_info->virus_flag = g_key_file_get_integer(keyfile, "SYSTEM", "CKVirus", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("global virus flag failed ,default:0!");
        g_error_free(key_error);
        key_error = NULL;
        sys_info->virus_flag = FSYNC_TURN_OFF;
    } else {
        PRINT_INFO_HEAD;
        print_info("global virus flag = %d ", sys_info->virus_flag);
    }
    sys_info->keyword_flag = g_key_file_get_integer(keyfile, "SYSTEM", "FilterFlag", &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("global check keyword flag failed ,default:0!");
        g_error_free(key_error);
        key_error = NULL;
        sys_info->keyword_flag = FSYNC_TURN_OFF;
    } else {
        PRINT_INFO_HEAD;
        print_info("global check keyword flag = %d ", sys_info->keyword_flag);
    }

    g_key_file_free(keyfile);

    return 0;
}

/*******************************************************************************************
*功能:      获取规则信息
*参数:       sys_info           ----> 系统设置信息
*           file_name          ----> 配置文件名
*           rule               ----> 规则(值结果)
*           rule_num           ----> 规则数
*                    
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int get_rule_info(SYSINFO *sys_info, const char *file_name, fs_rule_t *rule, int rule_num) {
    int ret = 0;
    char group_name[FSYNC_NAME_MAX_LEN] = {0};
    GError *key_error = NULL;
    GKeyFile *keyfile = g_key_file_new();


    g_key_file_load_from_file(keyfile, file_name, G_KEY_FILE_NONE, &key_error);
    if (key_error) {
        PRINT_ERR_HEAD;
        print_err("load fsync configure = %s failed:%s !", file_name, key_error->message);
        goto _exit;
    }

    for (int i = 0; i < rule_num; i++) {
        rule[i].task_count = rule_num;
        sprintf(group_name, "TASK%d", i);
        rule[i].task_id = i;
        PRINT_INFO_HEAD;
        print_info("task id = %d", rule[i].task_id);

        rule[i].virus_flag = sys_info->virus_flag;
        rule[i].keyword_flag = sys_info->keyword_flag;

        //获取通用规则
        ret = get_common_info(&(rule[i]), group_name, keyfile);
        if (ret != 0) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,get common info failed !", group_name);
            goto _exit;
        }

        rule[i].syslog_flag = (rule[i].log_flag != FSYNC_TURN_OFF) && (sys_info->record_flag != FSYNC_TURN_OFF);
        PRINT_INFO_HEAD;
        print_info("rule[%d].syslog_flag = %s", i, rule[i].syslog_flag ? "true" : "false");
        //分析前台日志开关是否开启
        if (sys_info->syslog_flag != FSYNC_TURN_OFF) {
            rule[i].log_flag = FSYNC_TURN_ON;
            PRINT_INFO_HEAD;
            print_info("rule[%d].log_flag = %d ,(g_record_flag = %d)", i, rule[i].log_flag, sys_info->record_flag);
        } else {
            rule[i].log_flag = rule[i].log_flag & sys_info->record_flag;
            PRINT_INFO_HEAD;
            print_info("rule[%d].log_flag = %d ,(g_record_flag = %d)", i, rule[i].log_flag, sys_info->record_flag);
        }

        //获取单双向同步差异化参数
        if ((rule[i].sync_area == FSYNC_INT_TO_OUT) || (rule[i].sync_area == FSYNC_OUT_TO_INT)) {
            rule[i].diff_info = (fs_oneway_t *) malloc(sizeof(fs_oneway_t));
            if (get_oneway_diff(keyfile, (fs_oneway_t *) (rule[i].diff_info), group_name) != 0) {
                PRINT_ERR_HEAD;
                print_err("group = [%s] ,read fs_oneway_t info failed!", group_name);
                goto _exit;
            }
        } else {
            rule[i].diff_info = (fs_bothway_t *) malloc(sizeof(fs_bothway_t));
            if (get_bothway_diff(keyfile, (fs_bothway_t *) (rule[i].diff_info), group_name) != 0) {
                PRINT_ERR_HEAD;
                print_err("group = [%s] ,read fs_bothway_t info failed!", group_name);
                goto _exit;
            }
        }

        //获取内网服务器主机的文件系统、用户名、密码、实际IP、映射IP、端口、主目录、子路径
        ret = get_server_info(&(rule[i].int_srv), keyfile, group_name, "InFileSys", "InUser", "InPWD", "InPath",
                              "InPath", "InSubPath", "InPort");
        if (ret != 0) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,get innet server info failed !", group_name);
            goto _exit;
        }

        //获取外网服务器主机的文件系统、用户名、密码、实际IP、映射IP、端口、主目录、子路径
        ret = get_server_info(&(rule[i].out_srv), keyfile, group_name, "OutFileSys", "OutUser", "OutPWD", "OutPath",
                              "OutMapPath", "OutSubPath", "OutPort");
        if (ret != 0) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,get outnet server info failed !", group_name);
            goto _exit;
        }

        //获取内网备份开关
        rule[i].int_bak_flag = g_key_file_get_integer(keyfile, group_name, "InBackupFlag", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,read InBackupFlag failed !", group_name);
            goto _exit;
        } else {
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,InBackupFlag = %d", group_name, rule[i].int_bak_flag);
        }

        if (rule[i].int_bak_flag == FSYNC_TURN_ON) {
            //获取内网备份服务器主机的文件系统、用户名、密码、实际IP、映射IP、端口、主目录、子路径
            ret = get_server_info(&(rule[i].int_bak), keyfile, group_name, "InBackupFileSys", "InBackupUser",
                                  "InBackupPWD", "InBackupDir", "InBackupDir", "InBackSubPath", "InBackupPort");
            if (ret != 0) {
                PRINT_ERR_HEAD;
                print_err("group = [%s] ,get innet backup server info failed !", group_name);
                goto _exit;
            }
        }

        //获取外网备份开关
        rule[i].out_bak_flag = g_key_file_get_integer(keyfile, group_name, "OutBackupFlag", &key_error);
        if (key_error) {
            PRINT_ERR_HEAD;
            print_err("group = [%s] ,read OutBackupFlag failed !", group_name);
            goto _exit;
        } else {
            PRINT_INFO_HEAD;
            print_info("group = [%s] ,OutBackupFlag = %d", group_name, rule[i].out_bak_flag);
        }
        if (rule[i].out_bak_flag == FSYNC_TURN_ON) {
            //获取外网备份服务器主机的文件系统、用户名、密码、实际IP、映射IP、端口、主目录、子路径
            ret = get_server_info(&(rule[i].out_bak), keyfile, group_name, "OutBackupFileSys", "OutBackupUser",
                                  "OutBackupPWD", "OutBackupDir", "OutBakMapPath", "OutBackSubPath", "OutBackupPort");
            if (ret != 0) {
                PRINT_ERR_HEAD;
                print_err("group = [%s] ,read outnet backup server info failed !", group_name);
                goto _exit;
            }
        }
    }

    _exit:
    if (key_error) {
        g_error_free(key_error);
        key_error = NULL;
        ret = -1;
    }
    g_key_file_free(keyfile);
    return ret;
}

/*******************************************************************************************
*功能:      设置规则信息
*参数:      rule               ----> 规则(值结果)
*           rule_num           ----> 规则数
*                    
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int set_rule_info(fs_rule_t *rule, int rule_num) {

    char group_name[FSYNC_NAME_MAX_LEN] = {0};

    for (int i = 0; i < rule_num; i++) {

        rule[i].task_stat = FSYNC_KEEP_RUN;

        sprintf(group_name, "TASK%d", i);
        //设置扫描路径
        set_server_path(group_name, rule[i].task_name, "intsrv", &rule[i].int_srv);
        set_server_path(group_name, rule[i].task_name, "outsrv", &rule[i].out_srv);
        if (rule[i].int_bak_flag == FSYNC_TURN_ON) {
            set_server_path(group_name, rule[i].task_name, "intbak", &rule[i].int_bak);
        }
        if (rule[i].out_bak_flag == FSYNC_TURN_ON) {
            set_server_path(group_name, rule[i].task_name, "outbak", &rule[i].out_bak);
        }

        //业务线程分配
        rule[i].pthread_count = FSYNC_PTHREAD_TOTAL_COUNT / rule_num;
        if (rule[i].pthread_count > FSYNC_PTHREAD_COUNT) {
            rule[i].pthread_count = FSYNC_PTHREAD_COUNT;
        } else if (rule[i].pthread_count < 1) {
            rule[i].pthread_count = 1;
        }
        PRINT_INFO_HEAD;
        print_info("[%s] pthread count = %d ", group_name, rule[i].pthread_count);
    }

    return 0;
}

/*******************************************************************************************
*功能:      设置扫描路径
*参数:      group_name         ----> 组名
*           task_name          ----> 任务名称
*           host_name          ----> 主机名称
*           server             ----> 服务器信息
*                    
*           返回值              ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int set_server_path(const char *group_name, const char *task_name, const char *host_name, fs_server_t *server) {

    if ((server->protocol & FSYNC_FILE_SYSTEM) != FSYNC_FTP_TYPE) {
        //生成内网本地挂载路径
        sprintf(server->mount_path, "/tmp/%s/%s", task_name, host_name);
        //生成内网本地扫描路径
        splice_path(server->mount_path, server->sub_path, server->scan_path);
    } else {
        if ((server->protocol == FSYNC_FTP_PROTOCOL) || (server->protocol == FSYNC_FTPS_PROTOCOL)) {
            if (strlen(server->sub_path) == 0) {
                strcpy(server->scan_path, "./");
            } else {
                strcpy(server->scan_path, server->sub_path);
            }
        } else {
            if ((server->sub_path[0] == '/') || (strncmp(server->sub_path, "./", 2)) == 0) {
                strcpy(server->scan_path, server->sub_path);
            } else {
                sprintf(server->scan_path, "./%s", server->sub_path);
            }
        }

    }
    PRINT_DBG_HEAD;
    print_dbg("[%s] %s scan_path = %s", group_name, host_name, server->scan_path);

    return 0;
}

/*******************************************************************************************
*功能:      重组扫描目录
*参数:      parent_path           ----> 配置文件名
*          sub_path             ----> 子路径
*          full_path            ----> 扫描目录
*
*           返回值              ----> >0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
void splice_path(const char *parent_path, const char *sub_path, char *full_path) {
#define DIR_MAX_DEEP 100
    if (strlen(sub_path) < 1) {
        strcpy(full_path, parent_path);
        return;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    char dir_sum[DIR_MAX_DEEP][FSYNC_NAME_MAX_LEN] = {{0}};
    memset(dir_sum, 0, sizeof(dir_sum));
    int tmp = 0;

    sprintf(dir_bak, "%s/%s", parent_path, sub_path);

    for (int i = 0; i < DIR_MAX_DEEP; i++) {
        strcpy(dir_sum[i], basename(dir_bak));
        dirname(dir_bak);
        if ((strcmp("/", dir_sum[i]) == 0) || (strcmp(".", dir_sum[i]) == 0) || (strcmp("..", dir_sum[i]) == 0) ||
            (strcmp("./", dir_sum[i]) == 0)) {
            memset(dir_sum[i], 0, sizeof(dir_sum[i]));
            break;
        } else {
            tmp = i;
        }
    }

    for (int i = tmp; i >= 0; i--) {
        strcat(full_path, "/");
        strcat(full_path, dir_sum[i]);
    }

}


