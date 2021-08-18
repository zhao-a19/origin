/*******************************************************************************************
*文件: update_marktool.cpp
*描述: 制作升级包、打印升级包工具
*作者: 王君雷
*日期: 2018-10-10
*修改：
**      添加both目录，可以同时升级内外网文件                             ------> 2020-02-20 wjl
*       修改usage提示信息，添加arm64用法说明                            ------> 2020-05-18
*      支持飞腾平台                                                     ------> 2020-07-27
*      支持tar包首部 2KB异或混淆，解包兼容旧版upk包                     ------> 2021-02-19 zza
*      加强调用参数判断,无实质性的改动                                  ------> 2021-03-04 wjl
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "update_make.h"
#include "update_parser.h"
#include "debugout.h"

int g_infcnt = 0, g_outfcnt = 0 , g_osfcnt = 0, g_bothfcnt = 0;
loghandle glog_p = NULL;
int IS_XOR = 0;

#define NONE                 "\e[0m"
#define RED                  "\e[0;31m"
#define GREEN                "\e[0;32m"
#define UNDERLINE            "\e[4m"
#define BOLD                 "\e[1m"

/**
 * [usage 使用方法说明]
 * @param name [程序名称]
 */
void usage(const char *name)
{
    printf("Usage(%d):%s [OPTION] ...\n", THIS_TOOL_VER, name);
    printf("Make or print upgrade package.\n\n");
    printf(GREEN "   -m file.upk sysver upver platver xor\n" NONE);
    printf("\tMake update package. "
           BOLD UNDERLINE"file.upk"NONE" is the upgrade package we want to make. You can change the name you need. "
           BOLD UNDERLINE"sysver"NONE" is the gap system soft version, which is 1 to 10 bytes of characters. "
           "If it is less than 10 bytes, the program will automatically add '0' at the top. "
           "For example, if input is 3, the program will convert to 0000000003. "
           "The purpose of the option "BOLD UNDERLINE"upver"NONE" is to prevent the upgrading of low version programs. "
           "The range is 0 to 255. "
           "If the value of the option in the upgrade package is less than the value that is written in "BOLD"update"NONE
           ", the upgrade operation is not allowed. "BOLD UNDERLINE"platver"NONE" is platform version, 0:i686, 1:SW_64, "
           "2:X86_64, 3:ARM_64, 4:FT. "BOLD UNDERLINE"xor"NONE" is select whether the head is XOR, parameter: -x or null\n");
    printf(GREEN"   -p file.upk\n" NONE);
    printf("\tPrint update package. "BOLD UNDERLINE"file.upk"NONE" is the upgrade package we want to print. "
           "You can learn the details of upgrading packages by printing.\n\n");
    printf("Report bugs to <wangjunlei@anmit.com>.\n");
}

int main(int argc, char **argv)
{
    _log_init_(glog_p, update_marktool);

    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    int ret = -1;
    if ((strcmp(argv[1], "-m") == 0) && (argc == 6)) {
        if (make_updatepack(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]))) {
            printf("make pack ok\n");
            ret = 0;
        } else {
            printf("make pack fail\n");
        }

    } else if ((strcmp(argv[1], "-p") == 0) && (argc == 3)) {
        if (print_updatepack(argv[2])) {
            printf("print pack ok\n");
            ret = 0;
        } else {
            printf("print pack fail\n");
        }
    } else if ((argc == 7)
               && (strcmp(argv[1], "-m") == 0)
               && (strcmp(argv[6], "-x") == 0)) {
        IS_XOR = 1;
        if (make_updatepack(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]))) {
            printf("make pack ok\n");
            ret = 0;
        } else {
            printf("make pack fail\n");
        }
    } else {
        usage(argv[0]);
    }

    return ret;
}

