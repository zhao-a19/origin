/*******************************************************************************************
*文件:    sip_record.h
*描述:    SIP通道记录
*
*作者:    张冬波
*日期:    2018-04-24
*修改:    创建文件                          ------>     2018-04-24
*
*******************************************************************************************/
#ifndef __SIP_REC_H__
#define __SIP_REC_H__
#include "datatype.h"

#ifdef __cplusplus
extern "C" {
#endif

//控制记录状态
#define SIP_NOREC   1

/**
 * [sipload 读取记录]
 * @param  recpath [记录文件路径]
 * @return         [记录总数]
 */
int32 sipload(const pchar recpath = NULL);

/**
 * [sipsave 保存记录]
 * @param  recpath [记录文件路径]
 * @return         [记录总数，-1失败]
 */
int32 sipsave(const pchar recpath = NULL);

/**
 * [sipgetone 读取一条记录，结合sipload使用]
 * @param  idx  [记录索引]
 * @param  data [记录内容]
 * @return      [记录索引，-1失败]
 */
int32 sipgetone(int32 idx, void *data);

/**
 * [sipaddone 添加一条记录]
 * @param  data [记录内容]
 * @return      [true成功]
 */
bool sipaddone(void *data);
bool sipaddone2(void *data);

/**
 * [sipdelone 删除记录]
 * @param  data   [记录内容]
 * @param  bclear [true清除所有]
 * @return        [true成功]
 */
bool sipdelone(void *data, bool bclear = false);
bool sipdelone2(void *data);

#ifdef __cplusplus
}
#endif

#endif
