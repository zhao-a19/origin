/*******************************************************************************************
*文件:    common_func.cpp
*描述:    通用模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10
*1.修改mkdir_r创建目录方式                                      ------> 2020-02-26
*2.修复后缀检测函数的bug                                        ------> 2020-03-01
*3.目的端文件打开失败增加失败重试机制                           ------> 2020-03-01
*4.添加设置线程栈大小函数                                       ------> 2020-03-03
*5.修改递归删除函数,添加创建/还原临时文件后缀函数               ------> 2020-03-10
*6.添加设置传输任务信息函数，修改rmove_r函数                    ------> 2020-03-13
*7.添加字符串哈希计算函数                                       ------> 2020-03-26
*******************************************************************************************/
#include "common_func.h"

/*******************************************************************************************
*功能:      递归删除目录及文件
*参数:      path                  ----> 目录路径
*
*           返回值                ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/


/*******************************************************************************************
*功能:      文件后缀检测 
*参数:      check_type            ----> 检测类型(黑白名单过滤类型)
*           file_name             ----> 文件名
*           file_list             ----> 后缀清单
*           返回值                 ----> true 允许 , false 拒绝
*
*注释:
*******************************************************************************************/
bool suffix_check(int check_type, const char *file_name, const char *filter_list) {

    bool find_record = false;
    int split_char = '.';
    const char *tmp_p = NULL;
    char suffix_name[FSYNC_NAME_MAX_LEN] = {0};
    char select_name[FSYNC_NAME_MAX_LEN] = {0};

    if ((tmp_p = strrchr(file_name, split_char)) == NULL) {
        strcpy(suffix_name, "*");
    } else {
        strcpy(suffix_name, ++tmp_p);
    }
    sprintf(select_name, ",%s,", suffix_name);
    capital_to_lowercase(select_name);
    PRINT_DBG_HEAD;
    print_dbg("reslove file = %s suffix name = %s ,select_name = %s", file_name, suffix_name, select_name);


    if (strstr(filter_list, select_name) != NULL) {
        find_record = true;
    }

    if (check_type == 1) {   //白名单
        return find_record;
    } else {                 //黑名单
        return !find_record;
    }

}

/*******************************************************************************************
*功能:      时间转字符串 
*参数:       times                 ----> 时间
*           timebuf               ----> 时间字符串(值结果参数)
*           timesize              ----> timebuf 大小
*           format                ----> 时间格式
*           返回值                 ----> timebuf指针 成功 , NULL 失败
*
*注释:
*******************************************************************************************/
const char *time2str(time_t times, char *timebuf, int timesize, const char *format) {
    static char timetmp[100];
    struct tm s_tm;

    if (timebuf == NULL) {
        timebuf = timetmp;
        timesize = sizeof(timetmp);
    }
    if (timesize <= 0) {
        return NULL;
    }
    memset(timebuf, 0, timesize);

    if (times == (time_t) (-1)) {
        times = time(NULL);
    }
    localtime_r(&times, &s_tm);

    if (is_strempty(format)) {
        strftime(timebuf, timesize, "%Y-%m-%d %H:%M:%S", &s_tm);
    } else {
        strftime(timebuf, timesize, format, &s_tm);
    }
    return (const char *) timebuf;
}

/*******************************************************************************************
*功能:      字符串转时间 
*参数:       times                 ----> 时间
*           format                ----> 时间格式
*           返回值                 ----> 时间 成功 , -1 失败
*
*注释:
*******************************************************************************************/
time_t str2time(const char *times, const char *format) {
    if (is_strempty(times)) return (time_t) (-1);
    struct tm tms;
    memset(&tms, 0, sizeof(tms));
    if (is_strempty(format)) {
        if (strptime(times, "%Y-%m-%d %H:%M:%S", &tms) == (strlen(times) + times)) {
            return mktime(&tms);
        }
    } else {
        if (strptime(times, format, &tms) == (strlen(times) + times)) {

            return mktime(&tms);
        }
    }

    return (time_t) (-1);
}

/*******************************************************************************************
*功能:      备份重命名
*参数:      source_name            ----> 源文件名
*           target_name           ----> 目标名
*           id                    ----> 备份编号
*           返回值                 ----> 时间 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int make_back_name(char *path_name, int id) {
    char *tmp_p = NULL;
    int split_char = '.';
    char file_name[FSYNC_PATH_MAX_LEN] = {0};
    char suffix_name[FSYNC_NAME_MAX_LEN] = {0};
    strcpy(file_name, path_name);

    tmp_p = strrchr(basename(path_name), split_char);
    if (tmp_p != NULL) {
        tmp_p = strrchr(basename(file_name), split_char);
        strcpy(suffix_name, tmp_p);
        *tmp_p = '\0';
        sprintf(path_name, "%s(%d)%s", file_name, id, suffix_name);
    } else {
        sprintf(path_name, "%s(%d)", file_name, id);
    }

    PRINT_DBG_HEAD;
    print_dbg("new target file = %s", path_name);

    return 0;
}

/*******************************************************************************************
*功能:       文件病毒检查接口
*参数:       chFileName            ----> 本地文件绝对路径
*           virusname             ----> 返回病毒名称
*
*           返回值                 ----> 0 无毒 , 1有病毒 -1 失败
*
*注释:
*******************************************************************************************/

int check_virus(char *chFileName, char *virusname) {
    char buf[1024] = {0};
    int recvlen = 0;
    int fd = 0;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    PRINT_DBG_HEAD
    print_dbg("search virus begin [%s]", chFileName);

    if (chFileName == NULL || virusname == NULL) {
        PRINT_ERR_HEAD
        print_err("para err");
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERR_HEAD
        print_err("socket fail(%s)", strerror(errno));
        return -1;
    }

    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s", UNIX_VIRUS_PATH);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        PRINT_ERR_HEAD
        print_err("connect fail(%s)", strerror(errno));
        return -1;
    }

    if (send(fd, chFileName, strlen(chFileName), 0) <= 0) {
        PRINT_ERR_HEAD
        print_err("send fail(%s) filename[%s]", strerror(errno), chFileName);
        close(fd);
        return -1;
    }

    if ((recvlen = recv(fd, buf, sizeof(buf), 0)) <= 0) {
        PRINT_ERR_HEAD
        print_err("recv fail(%s) filename[%s], recvlen[%d]", strerror(errno), chFileName, recvlen);
        close(fd);
        return -1;
    }

    close(fd);

    PRINT_DBG_HEAD
    print_dbg("search virus over filename[%s] result[%d]", chFileName, buf[0]);

    //传输协议：1有病毒  0没病毒 2检查失败
    if (buf[0] == '1') {
        memcpy(virusname, buf + 1, recvlen - 1);
        //有病毒
        return IS_VIRUS;
    } else if (buf[0] == '2') {
        //检查失败
        return VIRUS_FAIL;
    } else {
        //无毒
        return NOT_VIRUS;
    }
}

/*******************************************************************************************
*功能:        判断str1之间是否存在str2
*参数:        str1                        ---->  字符串1
*            len1                        ---->  字符串1长度
*            str2                        ---->  字符串2
*            len2                        ---->  字符串2长度
*            返回值                       ---->  true 存在 false 不存在
*注释:
*******************************************************************************************/
bool find_str(const char *str1, int len1, const char *str2, int len2) {
    if (len2 == 0) {
        return true;
    }
    if (len2 > len1) {
        return false;
    }

    for (int i = 0; i <= (len1 - len2); i++) {
        if (strncasecmp((str1 + i), str2, len2) == 0) {
            return true;
        }
    }
    return false;
}

/*******************************************************************************************
*功能:        列表移入队列
*参数:        source_list                 ----> 源列表
*            target_queue                ----> 目标队列
*
*            返回值                       ---->  true
*注释:
*******************************************************************************************/
bool move_list_queue(GList **source_list, GAsyncQueue *target_queue) {
    for (GList *p_elem = *source_list; p_elem != NULL; p_elem = *source_list) {
        g_async_queue_push(target_queue, p_elem->data);
        *source_list = g_list_delete_link(*source_list, p_elem);
    }
    return true;
}

/*******************************************************************************************
*功能:        字符串大写转小写
*参数:       str                        ---->  字符串
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool capital_to_lowercase(char *str) {

    for (int i = 0; str[i] != '\0'; i++) {
        if ('A' <= str[i] && str[i] <= 'Z') {
            str[i] += 32;
        }
    }

    return true;
}

/*******************************************************************************************
*功能:       设置线程栈大小
*参数:       stack_size                   ----> 线程栈大小
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool set_stack_size(unsigned long stack_size) {

    bool bret = true;
    rlimit stack_info;
    memset(&stack_info, 0, sizeof(stack_info));

    getrlimit(RLIMIT_STACK, &stack_info);
    PRINT_DBG_HEAD;
    print_dbg("get stack_size:rlmit_cur = %lu ,rlmit_max = %lu", stack_info.rlim_cur, stack_info.rlim_max);

    stack_info.rlim_cur = stack_size;
    stack_info.rlim_max = stack_size;
    if (setrlimit(RLIMIT_STACK, &stack_info) == 0) {
        bret = true;
        PRINT_DBG_HEAD;
        print_dbg("set stack_size:rlmit_cur = %lu ,rlmit_max = %lu", stack_info.rlim_cur, stack_info.rlim_max);
    } else {
        bret = false;
        PRINT_ERR_HEAD;
        print_err("set stack_size:rlimit failed:%s", strerror(errno));
    }

    return bret;
}



/*******************************************************************************************
*功能:      关键字检查
*参数:       send_msg           ----> 任务发送信息
*           source_file        ----> 源文件
*           source_stat        ----> 源文件信息
*           str_buf            ----> 字符串缓冲区
*           buf_len            ----> 缓冲区长度
*           keyword_str        ----> 关键字
*
*           返回值              ----> true 成功, false 失败
*
*注释:
*******************************************************************************************/
bool check_keyword(fs_send_t *send_msg, const char *source_file, struct stat *source_stat, const char *str_buf, int buf_len,
                   char *keyword_str) {
    bool bret = true;
    bool find_keyword = false;
    const char *list_str = NULL;
    int key_str_len = 0;
    int *next_arr = NULL;

    for (GList *utf_elem = send_msg->keyword_list; utf_elem != NULL; utf_elem = utf_elem->next) {
        list_str = ((fs_keyword_t *) (utf_elem->data))->keyword;
        key_str_len = ((fs_keyword_t *) (utf_elem->data))->str_len;
        next_arr = ((fs_keyword_t *) (utf_elem->data))->next;
        if(index_kmp(str_buf,buf_len,list_str,key_str_len,next_arr) >= 0){
            find_keyword = true;
        }

        //find_keyword = find_str(str_buf, buf_len, list_str, strlen(list_str));
        if (find_keyword) {
            recorder_t *recorder = init_recorder(FSYNC_MYSQL_HOST);
            int keyword_row = recorder->select_data(recorder, send_msg->rule->task_name, KEYWORD_FILE_TYPE, source_file,
                                                    NULL, NULL, NULL);
            if(((fs_keyword_t *) (utf_elem->data))->code_type != UTF_CODE_TYPE) {
                char src_str[FSYNC_NAME_MAX_LEN] = {0};
                strcpy(src_str,list_str);
                code_convert("gb2312","utf-8",src_str,FSYNC_NAME_MAX_LEN/2,keyword_str,FSYNC_NAME_MAX_LEN);
            } else {
                strcpy(keyword_str, list_str);
            }
            PRINT_DBG_HEAD;
            print_dbg("find keyword = %s in file = %s", list_str, source_file);

            if (keyword_row > 0) {
                recorder->update_data(recorder, send_msg->rule->task_name, KEYWORD_FILE_TYPE, source_file,
                                      source_stat->st_mtime, source_stat->st_size, keyword_str);
            } else {
                recorder->insert_data(recorder, send_msg->rule->task_name, KEYWORD_FILE_TYPE, source_file,
                                      source_stat->st_mtime, source_stat->st_size, keyword_str);
            }

            recorder->close_db(recorder);
            bret = false;
            break;
        }
    }

    return bret;
}

/*******************************************************************************************
*功能:       读取文本中的关键字
*参数:       file_path                        ---->  文件路径名称
*           keyword_list                     ---->  存储关键字的列表
*
*           返回值                            ---->  true 成功, false 失败
*注释:
*******************************************************************************************/
bool read_keyword(const char *file_path, GList **keyword_list,int code_type) {

    char buf[FSYNC_PATH_MAX_LEN] = {0};

    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD;
        print_err("open keyword file = %s failed:%s", file_path, strerror(errno));
        return false;
    }

    while ((fgets(buf, sizeof(buf), fp)) != NULL) {
        fs_keyword_t *tmp_info = (fs_keyword_t *) calloc(1, sizeof(fs_keyword_t));

        for (int i = 0; i < strlen(buf); i++) {
            if ((buf[i] == '\r') || (buf[i] == '\n')) {
                buf[i] = '\0';
                break;
            }
        }

        tmp_info->code_type = code_type;
        strcpy(tmp_info->keyword, buf);
        tmp_info->str_len = strlen(tmp_info->keyword);
        get_next(tmp_info->keyword, tmp_info->str_len, tmp_info->next);
        *keyword_list = g_list_prepend(*keyword_list, tmp_info);
        PRINT_INFO_HEAD;
        print_info("read keyword = %s", tmp_info->keyword);
        memset(buf, 0, sizeof(buf));
    }

    fclose(fp);
    return true;
}

/*******************************************************************************************
*功能:      递归创建目录
*参数:      dir_path                        ----> 路径
*           mode                           ----> 权限
*
*           返回值                          ----> 0 成功 ,-1 失败
*注释:
*******************************************************************************************/
int mkdir_r(const char *dir_path, int mode) {

    int ret = 0;
    int i = 0;
    if (access(dir_path, F_OK) == 0) {
        return 0;
    }

    char dir_bak[FSYNC_PATH_MAX_LEN] = {0};
    while (1) {
        i++;
        if (dir_path[i] == '\0') {
            strncpy(dir_bak, dir_path, i);
            if (access(dir_bak, F_OK) != 0) {
                mkdir(dir_bak, mode);
            }
            break;
        } else if (dir_path[i] == '/') {
            strncpy(dir_bak, dir_path, i);
            if (access(dir_bak, F_OK) != 0) {
                mkdir(dir_bak, mode);
            }
        }
    }


    if (access(dir_path, F_OK) != 0) {
        PRINT_ERR_HEAD;
        print_err("mkdir = %s failed!", dir_path);
        ret = -1;
    } else {
        PRINT_DBG_HEAD;
        print_dbg("mkdir = %s success!", dir_path);
        ret = 0;
    }

    return ret;
}

/*******************************************************************************************
*功能:       路径拼接
*参数:       parent_path                        ----> 父路径
*            sub_path                           ----> 子路径
*
*           返回值                              ---->  full_path 成功, NULL 失败
*注释:
*******************************************************************************************/
const char *deal_path(const char *parent_path, const char *sub_path, char *full_path) {

    if (parent_path[strlen(parent_path) - 1] == '/') {
        if (sub_path[0] == '/') {
            sprintf(full_path, "%s%s", parent_path, sub_path + 1);
        } else {
            sprintf(full_path, "%s%s", parent_path, sub_path);
        }
    } else {
        if (sub_path[0] == '/') {
            sprintf(full_path, "%s%s", parent_path, sub_path);
        } else {
            if (sub_path[0] != '\0') {
                sprintf(full_path, "%s/%s", parent_path, sub_path);
            } else {
                strcpy(full_path, parent_path);
            }
        }
    }

    return full_path;
}

/*******************************************************************************************
*功能:       获取next数组
*参数:       key_str                        ----> 关键字符串
*            len                           ----> 字符串长度
*            next                          ----> next数组
*
*           返回值                          ----> void
*注释:
*******************************************************************************************/
void get_next(const char *key_str, int len, int *next) {

    next[0] = -1;//-1代表没有重复子串
    int k = -1;
    for (int q = 1; q <= len; q++) {
        while ((k > -1) && (key_str[k + 1] != key_str[q])) {
            k = next[k];
        }

        if (key_str[k + 1] == key_str[q]) {
            k++;
            if (key_str[q] != key_str[k]) {
                next[q] = k;
            } else {
                next[q] = next[k];
            }

        }
    }
    return;
}

/*******************************************************************************************
*功能:       从主串中匹配子串
*参数:       main_str                           ----> 主串
*            main_len                          ----> 主串长度
*            key_str                           ----> 子串
*            key_len                           ----> 子串长度
*            next                              ----> next数组
*
*           返回值                              ---->  >=0 成功, -1 失败
*注释:
*******************************************************************************************/
int index_kmp(const char *main_str, int main_len, const char *key_str, int key_len,int *next) {

    int k = -1;
    int i = 0;

    for (; i < main_len; i++) {
        while ((k > -1) && (key_str[k + 1] != main_str[i])) {
            k = next[k];
        }

        if (key_str[k + 1] == main_str[i]) {
            k++;
        }

        if (k == key_len - 1) {
            return (i - key_len + 1);
        }
    }
    return -1;
}
/*******************************************************************************************
*功能:        提取字符串
*参数:        str1                        ---->  源字符串
*            str_head                    ----> 需提取字符串开头
*            str_end                     ----> 需提取字符串结尾
*            str2                        ----> 提取后的字符串
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool get_str(const char *str1, const char *str_head, const char *str_tail, char *str2) {
    
    const char *p_start = NULL;
    const char *p_end = NULL;
    char buf[FSYNC_PATH_MAX_LEN] = {0};
    if ((p_start = strstr(str1, str_head)) == NULL) {
        PRINT_ERR_HEAD;
        print_err("in srv_path = %s not find str = %s", str1, str_head);
        return false;
    }
    p_start += strlen(str_head);

    if ((p_end = strstr(p_start, str_tail)) == NULL) {
        PRINT_ERR_HEAD
        print_err("in buf = %s not find str = %s", buf, str_tail);
        return false;
    }
    int len = p_end - p_start;
    strncpy(str2, p_start, len);
    str2[len] = '\0';
    PRINT_DBG_HEAD;
    print_dbg("get str = %s", str2);

    return true;
}

/*******************************************************************************************
*功能:     提取字符串忽略两端单双引号
*参数:      str1                        ---->  源字符串
*            str2                        ----> 提取后的字符串
*
*            返回值                       ---->  true 成功 false 失败
*注释:
*******************************************************************************************/
bool del_special_char(const char *str1, char *str2) {

    bool bret = true;

    if (strchr(str1, '"') != NULL) {
        bret = get_str(str1, "\"", "\"", str2);
    } else if (strchr(str1, '\'') != NULL) {
        bret = get_str(str1, "'", "'", str2);
    } else {
        strcpy(str2, str1);
    }

    return bret;
}
/*******************************************************************************************
*功能:       判断字符编码是否为gbk
*参数:       data                            ----> 字符串
*
*           返回值                            ---->  true GBK , false非GBK
*注释:
*******************************************************************************************/
bool check_str_gbk(const char *str_buf,long str_len) {

    unsigned int nbytes = 0;      //GBK可用1-2个字节编码,中文两个 ,英文一个
    unsigned char chr = *str_buf;
    bool all_ascii = true;         //如果全部都是ASCII,
    for (unsigned int i = 0; str_buf[i] != '\0'; ++i) {
        chr = *(str_buf + i);
        if ((chr & 0x80) != 0 && nbytes == 0) {// 判断是否ASCII编码,如果不是,说明有可能是GBK
            all_ascii = false;
        }
        if (nbytes == 0) {
            if (chr >= 0x80) {
                if (chr >= 0x81 && chr <= 0xFE) {
                    nbytes = +2;
                } else {
                    return false;
                }
                nbytes--;
            }
        } else {
            if (chr < 0x40 || chr > 0xFE) {
                return false;
            }
            nbytes--;
        }
    }
    if (nbytes != 0) {   //违返规则
        return false;
    }
    if (all_ascii) { //如果全部都是ASCII, 也是GBK
        return true;
    }
    return true;
}

bool check_str_utf8(const void *str_buf, long str_len) {
    bool is_utf8 = true;
    unsigned char *start = (unsigned char *) str_buf;
    unsigned char *end = (unsigned char *) str_buf + str_len;
    while (start < end) {
        if (*start < 0x80) {  // (10000000): 值小于0x80的为ASCII字符
            start++;
        } else if (*start < (0xC0)) { // (11000000): 值介于0x80与0xC0之间的为无效UTF-8字符
            is_utf8 = false;
            break;
        } else if (*start < (0xE0)) { // (11100000): 此范围内为2字节UTF-8字符
            if (start >= end - 1) {
                break;
            }
            if ((start[1] & (0xC0)) != 0x80) {
                is_utf8 = false;
                break;
            }
            start += 2;
        } else if (*start < (0xF0)) { // (11110000): 此范围内为3字节UTF-8字符
            if (start >= end - 2) {
                break;
            }

            if ((start[1] & (0xC0)) != 0x80 || (start[2] & (0xC0)) != 0x80) {
                is_utf8 = false;
                break;
            }

            start += 3;
        } else {
            is_utf8 = false;
            break;
        }
    }
    return is_utf8;
}

bool check_file_utf8(const char *file_name) {

    bool is_utf8 = true;
    char buf[1024] = {0};
    FILE *pfd = fopen(file_name, "r");
    while (fgets(buf, sizeof(buf), pfd) != NULL) {
        if (!check_str_utf8(buf, strlen(buf))) {
            PRINT_DBG_HEAD;
            print_dbg("file = %s include str =  %s not utf8", file_name, buf);
            is_utf8 = false;
            break;
        }
    }
    fclose(pfd);

    return is_utf8;
}
/*******************************************************************************************
*功能:      字符串转码
*参数:       from_charset          ----> 源编码
*           to_charset            ----> 目标编码
*           in_buf                ----> 源字符串
*           in_len                ----> 源字符串长度
*           out_buf               ----> 输出字符串
*           out_len               ----> 输出缓冲区长度
*           返回值                 ----> 0 成功 , -1 失败
*
*注释:
*******************************************************************************************/
int code_convert(const char *from_charset, const char *to_charset, char *in_buf, size_t in_len, char *out_buf, size_t out_len) {
    iconv_t cd;
    int ret = 0;
    char **pin = &in_buf;
    char **pout = &out_buf;

    cd = iconv_open(to_charset, from_charset);
    if (cd == 0) {
        PRINT_ERR_HEAD
        print_err("open iconv failed:%s", strerror(errno));
        return -1;
    }
    memset(out_buf, 0, out_len);
    if (iconv(cd, pin, &in_len, pout, &out_len) == -1) {
        PRINT_ERR_HEAD;
        print_err("exec iconv failed:%s", strerror(errno));
        ret = -1;
    }

    iconv_close(cd);

    return ret;
}

/*******************************************************************************************
*功能:        文本转码成utf8
*参数:       file_name                        ----> 文件路径名称
*           new_name                         ---->  转码后的路径文件名
*
*           返回值                            ---->  0 成功 ,-1 失败
*注释:
*******************************************************************************************/
int iconv_conf(const char *file_name, const char *new_name) {

    int ret = 0;
    char in_buf[1024] = {0};
    char out_buf[2048] = {0};

    FILE *sfd = fopen(file_name, "rb");
    if (sfd == NULL) {
        PRINT_ERR_HEAD;
        print_err("open file name = %s failed:%s !", file_name, strerror(errno));
        return -1;
    }
    FILE *tfd = fopen(new_name, "wb");
    if (tfd == NULL) {
        PRINT_ERR_HEAD;
        print_err("open new file  = %s failed:%s !", file_name, strerror(errno));
        fclose(sfd);
        return -1;
    }
    while (fgets(in_buf, sizeof(in_buf), sfd) != NULL) {

        if (check_str_gbk(in_buf,strlen(in_buf))) {
            ret = code_convert("gb2312", "utf-8", in_buf, sizeof(in_buf), out_buf, sizeof(out_buf));
        } else {
            strcpy(out_buf, in_buf);
        }
        fwrite(out_buf, sizeof(char), strlen(out_buf), tfd);
    }

    fclose(sfd);
    fclose(tfd);
    return ret;
}