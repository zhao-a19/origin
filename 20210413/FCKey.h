/*******************************************************************************************
*文件:  FCKey.h
*描述:  key操作相关类
*作者:  王君雷
*日期:  2016-04-15
*修改:
*       使用zlog;把获取硬件信息相关函数移动到其他文件里                ------> 2018-09-09
*       把生成随机字符、计算字符串md5等移到公共工具中，他处也可使用    ------> 2018-09-19
*******************************************************************************************/
#ifndef __FC_KEY_H__
#define __FC_KEY_H__

#include <time.h>
#define KEY_FILE      "/etc/httpd/extra/mime.conf"
#define CLI_TOOL_FILE "/initrd/abin/clitool"

class KEY
{
public:
    KEY(const char *keyfile, int ethno);
    virtual ~KEY(void);
    bool build_key();
    bool read_key(char *chout);
    bool calc_md5(char *chout);

    static bool md5(const char *ch, int chlen, char *chout);
    static bool md5_ck(const char *ch, int chlen, char *chout, const char *chin);
    static bool md5_ck(const time_t tm, const char *chin);
    static bool md5(const time_t tm, char *chout);
    static bool file_exist(const char *file);
private:

private:
    char m_keyfile[512];
    char m_md5val[33];
    int m_ethno;
};

#endif
