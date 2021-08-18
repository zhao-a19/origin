/*******************************************************************************************
*文件:    crc.h
*描述:    CRC算法，移植自网络
*作者:    张冬波
*日期:    2014-11-25
*修改:    创建文件                            ------>     2015-11-25
*         增加CRC16算法                       ------>     2016-08-02
*
*******************************************************************************************/
#ifndef __CRC_H__
#define __CRC_H__

#include "datatype.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * [GetCRC32 description]
 * @param  buf [数据源]
 * @param  len [数据长度]
 * @return     [校验值]
 */
uint32 GetCRC32(const puint8 buf, uint32 len);

/**
 * [GetCRC16_CCITT description]
 * @param  buf [数据源]
 * @param  len [数据长度]
 * @return     [校验值]
 */
uint16 GetCRC16_CCITT(const puint8 buf, uint32 len);
#define GetCRC16 GetCRC16_CCITT

/**
 * [GetCRC16_DNP description]
 * @param  buf [数据源]
 * @param  len [数据长度]
 * @return     [校验值]
 */
uint16 GetCRC16_DNP(const puint8 buf, uint32 len);

#ifdef __cplusplus
}
#endif

#endif

