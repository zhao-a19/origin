/*      支持飞腾平台                                                     ------> 2020-07-27
 *      使用NOHUP_RUN宏                                                 ------> 2020-09-20
 */
#include <stdlib.h>
#include <stdio.h>

#if (SUOS_V==2000)
#define NOHUP_RUN "nohup"
#else
#define NOHUP_RUN "busybox nohup"
#endif

int main(int argc, char **argv)
{
    char chcmd[1024] = {0};

    system("killall virusmain >/dev/null 2>&1 ");
    sprintf(chcmd, "%s /initrd/abin/virusmain >/dev/null &", NOHUP_RUN);
    system(chcmd);
    printf("StartVir OK!\n");

    return 0;
}
