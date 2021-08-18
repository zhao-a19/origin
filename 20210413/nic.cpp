/*******************************************************************************************
*文件:  nic.cpp
*描述:  网卡相关操作
*作者:  王君雷
*日期:  2020-06-22
*修改:
*******************************************************************************************/
#include <errno.h>
#include "nic.h"
#include "debugout.h"

/**
 * [GetNetICValue 获取网卡流量统计信息]
 * @param  dname  [网卡名称]
 * @param  cvalue [网卡统计信息 出参]
 * @return        [失败返回负值]
 */
int GetNetICValue(char *dname, SNDEVINFO *cvalue)
{
    char buf[300] = {0};

    FILE *fp = fopen("/proc/net/dev", "r");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen error[/proc/net/dev:%s]", strerror(errno));
        return -1;
    }

    while (!feof(fp)) {
        memset(buf, 0 ,sizeof(buf));
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            if (strstr(buf, dname) != NULL) {
                sscanf(buf, "%*s%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu%llu",
                       &cvalue->rbyte, &cvalue->rpkt, &cvalue->rerrs, &cvalue->rdrop, &cvalue->rfifo,
                       &cvalue->rframe, &cvalue->rcompressed, &cvalue->multicast, &cvalue->sbyte,
                       &cvalue->spkt, &cvalue->serrs, &cvalue->sdrop, &cvalue->sfifo, &cvalue->scolls,
                       &cvalue->scarrier, &cvalue->scompressed);
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);

    PRINT_ERR_HEAD
    print_err("get net info fail, not find[%s]", dname);
    return -1;
}
