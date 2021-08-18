/*******************************************************************************************
*文件:    msgcfg.h
*描述:    优化消息队列处理
*
*作者:    张冬波
*日期:    2016-12-26
*修改:    创建文件                            ------>     2016-12-26
*         消息队列支持CYGWIN                  ------>     2018-09-26
*
*******************************************************************************************/
#ifndef __MSG_CFG_H__
#define __MSG_CFG_H__

//#define _MSG_ONE_ 1
#include "datatype.h"
#include <pthread.h>
#ifdef __CYGWIN__
#include "winsysv.h"
#else
#include <sys/msg.h>
#include <sys/ipc.h>
#include "winsysv.h"
#endif

static const uint32 m_maxUNIQ = 65500;                  //消息序号最大值
static const uint16 _UNI_PACKETSIZE = (7 * 1024);       //发送or接收包一次最大数据量，系统配置8.5KB

#define _PACKET_MD5_    0       //数据包MD5校验
#define _MD5LEN_        32

//报文结构
#pragma pack(push, 1)
//#pragma pack(1)      //gcc 3.x不支持
typedef struct  _uni_packet {
    uint8 ver;
    uint8 idx[3];
    uint8 total[3];
    struct timeval timestamp;
    uint32 UNIQ;
    uint8 reserved[12];
    uint16 length;
    struct {
        uint32 randomkey;
        //puint8 data;          //数据填充保留
        uint8 datakey[32];
    } payload;
    uint8 md5[_MD5LEN_];
} UNI_PACKET, *PUNI_PACKET;
#pragma pack(pop)

#define _PACKET_VER 0x10        //当前版本号
#define _PACKET_GAP 0xCD
#define _OFFSET_RAND(s) ((ptr_t)(&(((PUNI_PACKET)(s))->payload)))
#define _OFFSET_DATA(s) (_OFFSET_RAND(s) + sizeof(uint32))
#define _OFFSET_DATAKEY(s, l) (_OFFSET_DATA(s)+l)
#define _OFFSET_MD5(s, l) (_OFFSET_DATAKEY(s, l)+32)
#define _OFFSETR_DATAKEY(s, l) ((ptr_t)(s) + l - (32+_MD5LEN_))
#define _OFFSETR_MD5(s, l) ((ptr_t)(s) + l - _MD5LEN_)

//包号处理
inline void _uniqinc(uint32 &uniq)
{
    //值得范围（1 -- m_maxUNIQ)
    uniq++;
    if (uniq > m_maxUNIQ) {
        uniq = 1;
    }
}
inline void _uniqdec(uint32 &uniq)
{
    //值得范围（1 -- m_maxUNIQ)
    uniq--;
    if (uniq == 0) {
        uniq = m_maxUNIQ;
    }
}

static int32 _getint(uint8 data[3])
{
    int32 i = 0;

    //little ending
    //memcpy(&i, data, 3);
    i = data[2];
    i = (i << 8) | data[1];
    i = (i << 8) | data[0];
    i &= 0xFFFFFF;

    return i;
}

static int32 _getint(void *data, uint8 size)
{
    int32 i = 0;

    memcpy(&i, data, size);

    return i;
}

#ifdef _MSG_ONE_
//数据记录在数据堆空间
typedef struct msgsbuf {
    long mtype;
    uint8 mdata[sizeof(puint8) + sizeof(int32)];     //数据堆地址+Len
} SUQUEUE, *PSUQUEUE;

//外部函数
extern bool checkmd5_packet1(puint8 packet, int32 size, PUNI_PACKET s_packet);
extern void *_queuefunc_(void *arg);

#else
//数据记录栈，消息队列
typedef struct msgsbuf {
    long mtype;
    uint8 mdata[_UNI_PACKETSIZE];                   //数据内容
} SUQUEUE, *PSUQUEUE;

#endif

#endif
