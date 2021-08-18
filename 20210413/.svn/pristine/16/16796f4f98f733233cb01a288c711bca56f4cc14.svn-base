/*******************************************************************************************
*文件:  lcdnexcom.cpp
*描述:  星汉液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*       使用宏LCD_TTY_DEV，解决arm64平台使用的tty不一样的问题                 ------> 20200515
*******************************************************************************************/
#include <fcntl.h>
#include <errno.h>
#include "lcdnexcom.h"
#include "debugout.h"

LCDNEXCOM::LCDNEXCOM(void)
{
    buff_write_clear[0] = 0xf8;
    buff_write_clear[1] = 0x01;
    //buff_write_reset[0] = 0xf8;
    //buff_write_reset[1] = 0x02;
    buff_write_display[0] = 0xf8;
    buff_write_display[1] = 0x03;
    buff_write_stop[0] = 0xa0;
    //buff_write_direction_left[0] = 0xf8;
    //buff_write_direction_left[1] = 0x05;
    //buff_write_direction_right[0] = 0xf8;
    //buff_write_direction_right[1] = 0x06;
    //buff_write_hide_cursor[0] = 0xf8;
    //buff_write_hide_cursor[1] = 0x0c;
    //buff_write_show_cursor[0] = 0xf8;
    //buff_write_show_cursor[1] = 0x0f;
    //buff_write_move_cursor_left_one[0] = 0xf8;
    //buff_write_move_cursor_left_one[1] = 0x10;
    //buff_write_move_cursor_right_one[0] = 0xf8;
    //buff_write_move_cursor_right_one[1] = 0x14;
    //buff_write_move_lcd_left_one[0] = 0xf8;
    //buff_write_move_lcd_left_one[1] = 0x18;
    //buff_write_move_lcd_right_one[0] = 0xf8;
    //buff_write_move_lcd_right_one[1] = 0x1c;
    buff_write_cursor_location[0] = 0xf8;
    buff_write_cursor_location[1] = 0x80;
    buff_write_cursor_location[2] = 0x40;
    //buff_write_lcd_light[0] = 0xf8;
    //buff_write_lcd_light[1] = 0x28;
    //buff_write_lcd_dark[0] = 0xf8;
    //buff_write_lcd_dark[1] = 0x2c;
}

LCDNEXCOM::~LCDNEXCOM(void)
{
}

/**
 * [LCDNEXCOM::init 初始化]
 * @return  [成功返回true]
 */
bool LCDNEXCOM::init(void)
{
    m_fd = open(LCD_TTY_DEV, O_RDWR);
    if (m_fd <= 0) {
        PRINT_ERR_HEAD
        print_err("open %s fail[%s]", LCD_TTY_DEV, strerror(errno));
        return false;
    }
    set_speed(m_fd, 9600);
    return true;
}

/**
 * [LCDNEXCOM::write_char 发送函数]
 * @param  c [要发送的字符]
 * @return   [成功返回>0]
 */
int LCDNEXCOM::write_char(char c)
{
    return write(m_fd, &c, 1);
}

/**
 * [LCDNEXCOM::show 展示信息 展示在液晶屏第一行]
 * @param info [待展示的内容]
 */
void LCDNEXCOM::show(const char *info)
{
    write(m_fd, buff_write_clear, 2);
    write(m_fd, buff_write_display, 2);
    write(m_fd, info, strlen(info));
    write(m_fd, buff_write_stop, 1);
    sleep(SHOW_SLEEP);
}

/**
 * [LCDNEXCOM::show 展示信息 info1展示在液晶屏第一行 info2展示在液晶屏第二行]
 * @param info1 [第一行]
 * @param info2 [第二行]
 */
void LCDNEXCOM::show(const char *info1, const char *info2)
{
    int info2len = strlen(info2);
    int showtimes = 0;
    int remainder = info2len % LCD_MAX_LINE_LEN;
    const char *ptr = NULL;
    int len = 0;

    if (remainder == 0) {
        showtimes = info2len / LCD_MAX_LINE_LEN;
    } else {
        showtimes = info2len / LCD_MAX_LINE_LEN + 1;
    }

    for (int i = 0; i < showtimes; ++i) {
        ptr = info2 + i * LCD_MAX_LINE_LEN;
        len = LCD_MAX_LINE_LEN;
        if ((i == showtimes - 1) && (remainder != 0)) {
            len = remainder;
        }
        write(m_fd, buff_write_clear, 2);
        write(m_fd, buff_write_display, 2);
        write(m_fd, info1, strlen(info1));
        write(m_fd, buff_write_cursor_location, 3);
        write(m_fd, buff_write_display, 2);
        write(m_fd, ptr, len);
        write(m_fd, buff_write_stop, 1);
        sleep(SHOW_SLEEP);
    }
}
