/*******************************************************************************************
*文件:  lcdanmit.h
*描述:  anmit液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*******************************************************************************************/
#ifndef __LCD_ANMIT_H__
#define __LCD_ANMIT_H__
#include "lcdbase.h"

class LCDANMIT: public LCDBASE
{
public:
    LCDANMIT(void);
    virtual ~LCDANMIT(void);
    virtual bool init(void);
    virtual void show(const char *info);
    virtual void show(const char *info1, const char *info2);
private:
    static int close_cur(int fd);
    static int set_vc_end(unsigned char vstr[], int vlen);
    int clear_lcd(void);
    int show_data(char y, const char *cview, int clen);
};

#endif
