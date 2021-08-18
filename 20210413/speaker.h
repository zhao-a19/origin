/*******************************************************************************************
*文件:  speaker.h
*描述:  蜂鸣器响接口
*作者:  王君雷
*日期:  2018-12-07
*修改:
*******************************************************************************************/
#ifndef __SPEAKER_H__
#define __SPEAKER_H__

void log_play(unsigned int *freq, unsigned int *time);
void log_stop(void);
void speaker_key_error(void);
void speaker_disk_warn(void);

#endif
