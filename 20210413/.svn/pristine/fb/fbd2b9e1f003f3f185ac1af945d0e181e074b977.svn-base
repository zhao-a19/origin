/*******************************************************************************************
*文件:  network.h
*描述:  应用层以下的协议分析处理
*作者:  王君雷
*日期:  2018-04-03
*修改:
*        创建文件                                                  ------> 2018-04-03
*        添加函数get_ipv6_ext_headerlen                            ------> 2019-01-22
*        函数get_ipv6_ext_headerlen的最后一个参数改用指针，不需要知道
*        传输层协议时可以传NULL                                    ------> 2019-02-16
*******************************************************************************************/
#include "network.h"
#include "debugout.h"

/**
 * [get_ipv6_ext_headerlen 获取ipv6首部及扩展首部长度 把传输层的协议通过proto传出]
 * @param  sdata [ipv6数据包]
 * @param  slen  [数据包长度]
 * @param  proto [协议 出参]
 * @return       [成功返回>0 失败返回负值]
 */
#define SET_PROTO(proto,nh) if (proto!=NULL){ *proto = nh;}
int get_ipv6_ext_headerlen(unsigned char *sdata, int slen, unsigned char *proto)
{
    int len = _ipv6headlen(sdata);
    unsigned char nexthd = IPV6_PROTO(sdata);
    PEXT_HOP_BY_HOP phop = NULL;
    PEXT_DESTINATIONS_OPT pdst = NULL;
    PEXT_ROUTING_HEADER proute = NULL;
    PEXT_FRAGMENT_HEADER pfrag = NULL;
    PEXT_AUTH_HEADER pauth = NULL;
    PEXT_MIPV6 pmipv6 = NULL;

_tag:

    if (len > slen) {
        PRINT_ERR_HEAD
        print_err("len [%d] > slen[%d] while get ipv6 ext headerlen", len, slen);
        return -1;
    }

    switch (nexthd) {
    case TCP:
    case UDP:
    case ICMPV6:
        SET_PROTO(proto, nexthd);
        PRINT_DBG_HEAD
        print_dbg("find next header %d, len is %d", nexthd, len);
        break;
    case HOP_BY_HOP:
        phop = (PEXT_HOP_BY_HOP)(sdata + len);
        nexthd = phop->next_header;
        len += 1;
        len += phop->hdr_ext_len;
        PRINT_DBG_HEAD
        print_dbg("find hopbyhop header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case DESTINATIONS_OPT:
        pdst = (PEXT_DESTINATIONS_OPT)(sdata + len);
        nexthd = pdst->next_header;
        len += 1;
        len += pdst->hdr_ext_len;
        PRINT_DBG_HEAD
        print_dbg("find destinations opt header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case ROUTING_HEADER:
        proute = (PEXT_ROUTING_HEADER)(sdata + len);
        nexthd = proute->next_header;
        len += 1;
        len += proute->hdr_ext_len;
        PRINT_DBG_HEAD
        print_dbg("find routing header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case FRAGMENT_HEADER:
        pfrag = (PEXT_FRAGMENT_HEADER)(sdata + len);
        nexthd = pfrag->next_header;
        len += sizeof(EXT_FRAGMENT_HEADER);
        PRINT_DBG_HEAD
        print_dbg("find fragment header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case AUTH_HEADER:
        pauth = (PEXT_AUTH_HEADER)(sdata + len);
        nexthd = pauth->next_header;
        len += 1;
        len += pauth->hdr_ext_len;
        PRINT_DBG_HEAD
        print_dbg("find auth header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case ESP:
        len = -1;
        SET_PROTO(proto, nexthd);
        PRINT_INFO_HEAD
        print_info("find esp header, nexthd is %d, len is %d", nexthd, len);
        break;
    case MIPV6:
        pmipv6 = (PEXT_MIPV6)(sdata + len);
        nexthd = pmipv6->next_header;
        len += 1;
        len += pmipv6->hdr_ext_len;
        PRINT_DBG_HEAD
        print_dbg("find mipv6 header, nexthd is %d, len is %d", nexthd, len);
        goto _tag;
    case NO_NEXT_HEADER:
        len = -1;
        PRINT_ERR_HEAD
        print_err("no next header find[%d]. slen = %d", nexthd, slen);
        break;
    default:
        len = -1;
        PRINT_ERR_HEAD
        print_err("unknown ipv6 nexthd[%d]. slen = %d", nexthd, slen);
        break;
    }

    return len;
}
