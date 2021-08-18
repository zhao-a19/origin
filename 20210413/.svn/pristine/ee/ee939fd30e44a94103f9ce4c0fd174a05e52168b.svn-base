/*******************************************************************************************
*文件:  lcdrld.h
*描述:  瑞立德液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*       使用宏LCD_TTY_DEV，解决arm64平台使用的tty不一样的问题                 ------> 20200515
*******************************************************************************************/
#include <fcntl.h>
#include <errno.h>
#include "lcdrld.h"
#include "debugout.h"

LCDRLD::LCDRLD(void)
{
}

LCDRLD::~LCDRLD(void)
{
}

/**
 * [LCDRLD::init 初始化]
 * @return  [成功返回true]
 */
bool LCDRLD::init(void)
{
    m_fd = open(LCD_TTY_DEV, O_RDWR);
    if (m_fd <= 0) {
        PRINT_ERR_HEAD
        print_err("open %s fail[%s]", LCD_TTY_DEV, strerror(errno));
        return false;
    }
    set_speed(m_fd, 9600);
    if (!set_parity(m_fd, 8, 1, 's')) {
        PRINT_ERR_HEAD
        print_err("flag rld set parity fail");
        return false;
    }
    return true;
}

/**
 * [LCDRLD::clear_lcd 清屏]
 * @return  [成功返回0]
 */
int LCDRLD::clear_lcd(void)
{
    write_char(0xAA);
    write_char(0x10);
    return 0;
}

/**
 * [LCDRLD::show_data 瑞立德液晶屏展示内容]
 * @param  y     [展示在第几行]
 * @param  cview [内容]
 * @param  clen  [内容长度]
 * @return       [成功返回0]
 */
int LCDRLD::show_data(char y, const char *cview, int clen)
{
    write_char(0xaa);
    write_char(0x20);
    if (y == '0') {
        write_char(0x00);
    } else {
        write_char(0x01);
    }

    write_char(0x00);
    write_char(0xaa);
    write_char(0x25);
    for (int i = 0; i < clen; i++) {
        write_char(cview[i]);
    }
    write_char(0X0d);
    return 0;
}

/**
 * [LCDRLD::write_char 星汉液晶屏调用发送函数]
 * @param  c [要发送的字符]
 * @return   [成功返回>0]
 */
int LCDRLD::write_char(char c)
{
    return write(m_fd, &c, 1);
}

/**
 * [LCDRLD::show 展示信息 展示在液晶屏第一行]
 * @param info [待展示的内容]
 */
void LCDRLD::show(const char *info)
{
    clear_lcd();
    show_data('0', info, strlen(info));
    sleep(SHOW_SLEEP);
}

/**
 * [LCDRLD::show 展示信息 info1展示在液晶屏第一行 info2展示在液晶屏第二行]
 * @param info1 [第一行]
 * @param info2 [第二行]
 */
void LCDRLD::show(const char *info1, const char *info2)
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
        clear_lcd();
        show_data('0', info1, strlen(info1));
        show_data('1', ptr, len);
        sleep(SHOW_SLEEP);
    }
}
