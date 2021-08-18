/*******************************************************************************************
*文件:  enfile.cpp
*描述:  策略自动备份校验码生成工具
*作者:  李亮
*日期:  2021-05-21
*
*修改:
*******************************************************************************************/
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "FCMD5.h"
#include "debugout.h"

loghandle glog_p = NULL;

/**
 * [get_file_size 获取文件大小]
 * @param  file         [输入参数 文件名]
 * @return              [成功返回文件大小, 否则-1]
 */
static int get_file_size(const char *file)
{
    struct stat stat_buf;
    int ret = 0;

    ret = stat(file, &stat_buf);
    if (0 != ret) {
        return -1;
    }

    return stat_buf.st_size;
}

/**
 * [md5sum_str 计算文件md5]
 * @param  file         [输入参数 文件名]
 * @param  digest       [输出参数 MD5字符串]
 * @return              [成功返回0, 否则-1]
 */
static int get_enc_str(const char *file, char *buf)
{
    char tmp[64] = "";          /* 临时缓冲区 */
    char md5[33] = "";          /* md5 值 */
    int filesize = 0;
    int ret = -1;
    int i = 0;

    ret = md5sum_str(file, md5);
    if (ret != 0) {
        PRINT_ERR_HEAD
        print_err("get md5 error[%s]", file);
        return -1;
    }

    filesize = get_file_size(file);
    if (filesize == -1) {
        PRINT_ERR_HEAD
        print_err("get file size error[%s]", file);
        return -1;
    }

    snprintf(tmp, sizeof(tmp), "su-[%s]-%10d-1z2y", md5, filesize);

    if (!md5sum_buff(tmp, strlen(tmp), NULL, (unsigned char *)md5)) {
        PRINT_ERR_HEAD
        print_err("get md5 error[%s]", tmp);
        return -1;
    }

    strcpy(buf, md5);
    for (i = 0; i < 8; i++)
        strncat(buf, &md5[i * 4 + 3], 1);

    PRINT_INFO_HEAD
    print_info("encode str:[%s]", buf);

    /* 长度必须40 */
    if (strlen(buf) != 40) {
        PRINT_ERR_HEAD
        print_err("encode str len error[%d]", strlen(buf));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    char buf[41] = "";
    int ret = 0;

    if (argc != 2) {
        PRINT_ERR_HEAD
        print_err("%d", argc);

        printf("error\n");
        return -1;
    }

    if (0 != get_enc_str(argv[1], buf)) {
        PRINT_ERR_HEAD
        print_err("get encode str error");

        printf("error\n");
        return -1;
    }

    printf("%s\n", buf);
    return 0;
}
