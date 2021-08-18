/*******************************************************************************************
*文件:  lcdrld.h
*描述:  瑞立德液晶屏
*作者:  王君雷
*日期:  2019-04-10
*修改:
*******************************************************************************************/
#ifndef __LCD_RLD_H__
#define __LCD_RLD_H__

#include "lcdbase.h"

class LCDRLD: public LCDBASE
{
public:
    LCDRLD(void);
    virtual ~LCDRLD(void);
    virtual bool init(void);
    virtual void show(const char *info);
    virtual void show(const char *info1, const char *info2);
private:
    int write_char(char c);
    int clear_lcd(void);
    int show_data(char y, const char *cview, int clen);
};

#endif
