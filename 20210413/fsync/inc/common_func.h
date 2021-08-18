/*******************************************************************************************
*文件:    common_func.h
*描述:    通用模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10
*1.添加设置线程栈大小函数                                       ------> 2020-03-03
*2.添加创建还原临时后缀函数                                     ------> 2020-03-10
*3.添加设置传输任务信息函数                                     ------> 2020-03-13
*4.添加字符串哈希计算函数                                       ------> 2020-03-26
*******************************************************************************************/
#ifndef __COMMON_FUNC_H__
#define __COMMON_FUNC_H__

#include <iconv.h>
#include "global_define.h"
#include "gap_config.h"
#include "record_manager.h"

#define TIME_OUT 10
const int C_FILE_NOCODE = 300;   //文件未编码
const int C_FILE_BASE64CODE = 301;//文件用BASE64编码
const int C_FILE_QTCODE = 302;   //文件QT编码
//KVEngine
const int C_MAX_PATH = 300;
const int C_INITS_NUM = 1;   //要初始化的Instance数
const int C_MAX_INITS = 30;  //系统允许的最大Instance数

#define IS_VIRUS 1
#define NOT_VIRUS 0
#define VIRUS_FAIL -1

#define UTF_CODE_TYPE 0
#define GBK_CODE_TYPE 1


#define is_strempty(p) (((p) == NULL) || (*((char*)(p)) == 0))


bool suffix_check(int check_type, const char *file_name, const char *filter_list);

const char *time2str(time_t times, char *timebuf, int timesize, const char *format = NULL);

time_t str2time(const char *times, const char *format = NULL);

int make_back_name(char *path_name, int id);

int code_convert(const char *from_charset, const char *to_charset, char *in_buf, size_t in_len, char *out_buf, size_t out_len);

int check_virus(char *chFileName, char *virusname = NULL);

bool find_str(const char *str1, int len1, const char *str2, int len2);

bool move_list_queue(GList **source_list, GAsyncQueue *target_queue);

bool capital_to_lowercase(char *str);

bool set_stack_size(unsigned long stack_size);

bool check_keyword(fs_send_t *send_msg, const char *source_file, struct stat *source_stat, const char *str_buf, int buf_len,
                   char *keyword_str);

bool read_keyword(const char *file_path, GList **keyword_list,int code_type);

int mkdir_r(const char *dir_path, int mode);

bool rmdir_r(const char *path);

const char *deal_path(const char *parent_path, const char *sub_path, char *full_path);

void get_next(const char *key_str, int len, int *next);

int index_kmp(const char *main_str, int main_len, const char *key_str, int key_len,int *next);

bool get_str(const char *str1, const char *str_head, const char *str_end, char *str2);

bool del_special_char(const char *str1, char *str2);

bool check_str_gbk(const char * str_buf,long str_len);

bool check_str_utf8(const void *str_buf, long str_len);

bool check_file_utf8(const char *file_name);

int iconv_conf(const char *file_name, const char *new_name);
#endif //__COMMON_FUNC_H__