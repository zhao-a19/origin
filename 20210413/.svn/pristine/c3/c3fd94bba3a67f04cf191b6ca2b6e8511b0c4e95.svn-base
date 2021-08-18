/*******************************************************************************************
*文件:  lcdnexcom.h
*描述:  星汉液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*******************************************************************************************/
#ifndef __LCD_NEXCOM_H__
#define __LCD_NEXCOM_H__
#include "lcdbase.h"

class LCDNEXCOM: public LCDBASE
{
public:
    LCDNEXCOM(void);
    virtual ~LCDNEXCOM(void);
    virtual bool init(void);
    virtual void show(const char *info);
    virtual void show(const char *info1, const char *info2);
private:
    int write_char(char c);

private:
    unsigned char buff_write_clear[2];
    //unsigned char buff_write_reset[2];
    //unsigned char buff_write_direction_left[2];
    //unsigned char buff_write_direction_right[2];
    //unsigned char buff_write_hide_cursor[2];
    //unsigned char buff_write_show_cursor[2];
    //unsigned char buff_write_move_cursor_left_one[2];
    //unsigned char buff_write_move_cursor_right_one[2];
    //unsigned char buff_write_move_lcd_left_one[2];
    //unsigned char buff_write_move_lcd_right_one[2];
    unsigned char buff_write_cursor_location[3];
    //unsigned char buff_write_lcd_light[2];
    //unsigned char buff_write_lcd_dark[2];
    unsigned char buff_write_display[2];
    unsigned char buff_write_stop[1];
};

#endif
