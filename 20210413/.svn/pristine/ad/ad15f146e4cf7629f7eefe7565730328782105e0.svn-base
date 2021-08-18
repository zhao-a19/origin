/*******************************************************************************************
*文件:  lcdbase.h
*描述:  LCD展示基类
*作者:  王君雷
*日期:  2019-04-10
*修改:
*******************************************************************************************/
#ifndef __LCD_BASE_H__
#define __LCD_BASE_H__
#include "gap_config.h"

#define SHOW_SLEEP 5        //过几秒滚动一个界面
#define LCD_MAX_LINE_LEN 16 //LCD每行最多能展示出的字符数

class LCDBASE
{
public:
    LCDBASE(void);
    virtual ~LCDBASE(void);

    virtual bool init(void) = 0;
    virtual void show(const char *info) = 0;
    virtual void show(const char *info1, const char *info2) = 0;

protected:
    static void set_speed(int fd, int speed);
    static bool set_parity(int fd, int databits, int stopbits, int parity);
private:

protected:
    int m_fd;
};

#endif
