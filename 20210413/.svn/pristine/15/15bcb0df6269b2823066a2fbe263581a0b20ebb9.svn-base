/*******************************************************************************************
*文件:  srtlist.cpp
*描述:  通过输入框、下拉框添加的路由列表
*作者:  王君雷
*日期:  2020-08-31
*修改:
*******************************************************************************************/
#include "debugout.h"
#include "srtlist.h"

SPINNERRLIST::SPINNERRLIST(void)
{
    memset(dstip, 0, sizeof(dstip));
    memset(dstmask, 0, sizeof(dstmask));
    memset(gw, 0, sizeof(gw));
    memset(dev, 0, sizeof(dev));
    metric = 0;
    iptype = IP_TYPE4;
}

SPINNERRLIST::~SPINNERRLIST(void)
{
}

/**
 * [SPINNERRLIST::combineRoute 组装route语句]
 * @param  chcmd [route语句存放缓冲区]
 * @return       [返回route语句缓冲区指针]
 */
const char* SPINNERRLIST::combineRoute(char* chcmd)
{
    if (iptype == IP_TYPE6) {
        sprintf(chcmd, "route -A inet6 add '%s'/'%s' gw '%s' metric %d ",
                dstip, dstmask, gw, metric);
    } else {
        sprintf(chcmd, "route add -net '%s' netmask '%s' gw '%s' metric %d ",
                 dstip, dstmask, gw, metric);
    }

    if (strcmp(dev, NOT_SPECIFY_CARD) != 0) {
        strcat(chcmd, "dev ");
        strcat(chcmd, "'");
        strcat(chcmd, dev);
        strcat(chcmd, "'");
    } else {
        PRINT_DBG_HEAD
        print_dbg("spinner route list not specified card");
    }

    PRINT_DBG_HEAD
    print_dbg("spinner rlist[%s]", chcmd);
    return chcmd;
}
