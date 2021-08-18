/*******************************************************************************************
*文件:  speaker.cpp
*描述:  蜂鸣器响接口
*作者:  王君雷
*日期:  2018-12-07
*修改:
*      使用宏控制是否支持蜂鸣器功能                                      ------> 2020-05-15
*******************************************************************************************/
#include <string.h>
#include <stdio.h>
#include "speaker.h"
#include "debugout.h"
#include "define.h"

#ifdef SUPPORT_SPEACKER
#include <sys/io.h>
#endif

/**
 * [log_speaker 告警]
 * @param freq  [description]
 * @param delay [description]
 */
void log_speaker(unsigned int freq, unsigned int delay)
{
#ifdef SUPPORT_SPEACKER
    static int flag = 0, bit;
    if (flag == 0) {
        flag = 1;
        iopl(3);
    }
    outb(0xb6, 0x43);
    outb((freq & 0xff), 0x42);
    outb((freq >> 8), 0x42);
    bit = inb(0x61);
    outb(3 | bit, 0x61);
    usleep(10000 * delay);
    outb(0xfc | bit, 0x61);
#endif
}

/**
 * [log_play 告警]
 * @param freq [description]
 * @param time [description]
 */
void log_play(unsigned int *freq, unsigned int *time)
{
    for (int i = 0; freq[i] != 0; i++) {
        log_speaker(freq[i], time[i]);
    }
}

/**
 * [log_stop 停止告警]
 */
void log_stop(void)
{
#ifdef SUPPORT_SPEACKER
    iopl(3);
    outb(0xb6, 0x43);
#endif
}

/**
 * [speaker_key_error key检查失败 鸣笛告警]
 */
void speaker_key_error()
{
    unsigned int freq_alert[] = {2800, 900, 2000, 0};
    unsigned int time_alert[] = {25, 25, 25};

    log_play(freq_alert, time_alert);
    log_stop();
}

/**
 * [speaker_disk_warn 磁盘空间紧张 鸣笛告警]
 */
void speaker_disk_warn()
{
    unsigned int freq_alert[] = {2000, 2400, 0};
    unsigned int time_alert[] = {25, 30};

    log_play(freq_alert, time_alert);
    log_stop();
}


