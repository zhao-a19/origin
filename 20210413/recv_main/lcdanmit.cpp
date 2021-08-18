/*******************************************************************************************
*文件:  lcdanmit.cpp
*描述:  anmit液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*       使用宏LCD_TTY_DEV，解决arm64平台使用的tty不一样的问题                 ------> 20200515
*******************************************************************************************/
#include <fcntl.h>
#include <errno.h>
#include "lcdanmit.h"
#include "debugout.h"

LCDANMIT::LCDANMIT(void)
{
}

LCDANMIT::~LCDANMIT(void)
{
}

/**
 * [LCDANMIT::show 展示信息 展示在液晶屏第一行]
 * @param info [待展示的内容]
 */
void LCDANMIT::show(const char *info)
{
    clear_lcd();
    show_data('0', info, strlen(info));
    sleep(SHOW_SLEEP);
}

/**
 * [LCDANMIT::show 展示信息 info1展示在液晶屏第一行 info2展示在液晶屏第二行]
 * @param info1 [第一行]
 * @param info2 [第二行]
 */
void LCDANMIT::show(const char *info1, const char *info2)
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

/**
 * [LCDANMIT::init 初始化]
 * @return  [成功返回true]
 */
bool LCDANMIT::init(void)
{
    m_fd = open(LCD_TTY_DEV, O_RDWR);
    if (m_fd <= 0) {
        PRINT_ERR_HEAD
        print_err("open %s fail[%s]", LCD_TTY_DEV, strerror(errno));
        return false;
    }
    set_speed(m_fd, 115200);
    if (!set_parity(m_fd, 8, 1, 's')) {
        PRINT_ERR_HEAD
        print_err("flag anmit set parity fail");
        return false;
    }
    close_cur(m_fd);
    return true;
}

/**
 * [LCDANMIT::close_cur]
 * @param  fd [描述符]
 * @return    [成功返回0]
 */
int LCDANMIT::close_cur(int fd)
{
    unsigned char buff[16];
    int ilen = 0;
    //关闭光标
    buff[0] = 'P';
    buff[1] = '7';
    buff[2] = 'A';
    buff[3] = '1';
    buff[4] = '1';
    buff[5] = '0';
    ilen = set_vc_end(buff, 6);
    write(fd, buff, ilen);
    read(fd, buff, 5);
    if (strncmp((char *)buff, "PR2S$", 5) != 0) {
        PRINT_ERR_HEAD
        print_err("close cur return -1");
        return -1;
    }
    return 0;
}

/**
 * [LCDANMIT::set_vc_end description]
 * @param  vstr [description]
 * @param  vlen [description]
 * @return      [description]
 */
int LCDANMIT::set_vc_end(unsigned char vstr[], int vlen)
{
    unsigned short vv = 0;
    int i;
    for (vv = vstr[0], i = 1; i < vlen; i++) {
        vv ^= vstr[i];
    }
    vstr[vlen] = 0x30 + (vv >> 4);
    vstr[vlen + 1] = 0x30 + (vv & 0x0F);
    vstr[vlen + 2] = '$';
    return vlen + 3;
}

/**
 * [LCDANMIT::clear_lcd 清屏]
 * @return  [成功返回0]
 */
int LCDANMIT::clear_lcd(void)
{
    unsigned char buff[16];
    int ilen = 0;
    //清屏
    buff[0] = 'P';
    buff[1] = '7';
    buff[2] = 'C';
    buff[3] = '1';
    buff[4] = '1';
    buff[5] = '1';
    ilen = set_vc_end(buff, 6);
    write(m_fd, buff, ilen);
    read(m_fd, buff, 5);
    if (strncmp((char *)buff, "PR2S$", 5) != 0) {
        PRINT_ERR_HEAD
        print_err("anmit clear lcd return -1");
        return -1;
    }
    return 0;
}

/**
 * [LCDANMIT::show_data anmit液晶屏展示内容]
 * @param  y     [展示在第几行]
 * @param  cview [内容]
 * @param  clen  [内容长度]
 * @return       [成功返回0]
 */
int LCDANMIT::show_data(char y, const char *cview, int clen)
{
    unsigned char buff[64] = {0};

    int ab = 0;
    if (clen < 10) {
        ab = 40;
    } else {
        ab = clen + 30;
    }
    char abc[10] = {0};
    char a[10] = {0};
    char b[10] = {0};
    sprintf(abc, "%d", ab);
    a[0] = abc[0];
    b[0] = abc[1];
    buff[1] = atoi(a) * 0x10 + atoi(b);
    //显示数据
    buff[0] = 'P';
    //buff[1]='0'+clen;
    buff[2] = 'M';
    buff[3] = '0';
    buff[4] = y;
    int ilen = 0;
    if (clen < 10) {
        strcpy((char *)buff + 5, cview);
        for (int i = 0; i < 10 - clen; i++) {
            strcat((char *)buff, " ");
        }
        ilen = set_vc_end(buff, 15);
    } else {
        strcpy((char *)buff + 5, cview);
        ilen = set_vc_end(buff, 5 + clen);
    }

    write(m_fd, buff, ilen);
    read(m_fd, buff, 5);
    if (strncmp((char *)buff, "PR2S$", 5) != 0) {
        PRINT_ERR_HEAD
        print_err("show data anmit return -1.buff[%s]", buff);
        return -1;
    }
    return 0;
}
