/*******************************************************************************************
*文件:  stop.c
*描述:  停止后台程序
*作者:  王君雷
*日期:
*修改:
*      格式化代码，统一使用unix风格，utf8格式                   ------> 2018-08-28
*      支持蜂鸣器时才包含sys/io.h文件                           ------> 2020-05-15
*******************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include "define.h"

#ifdef SUPPORT_SPEACKER
#include <sys/io.h>
#endif

int main(int argc, char **argv)
{
    system(STOP_IN_BUSINESS);

#ifdef SUPPORT_SPEACKER
    //关闭蜂鸣器
    iopl(3);
    outb(0xb6, 0x43);
#endif

    printf("Stop OK!\n");
    return 0;
}
