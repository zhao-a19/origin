/*******************************************************************************************
*文件:  keyword_mg.h
*描述:  关键字过滤管理
*作者:  王君雷
*日期:  2020-10-13
*修改:
*******************************************************************************************/
#ifndef __KEY_WORD_MG_H__
#define __KEY_WORD_MG_H__
using namespace std;
#include <string>
#include <vector>

class KeywordMG
{
public:
    KeywordMG(void);
    virtual ~KeywordMG(void);
    int readConf(void);
    int setRule(void);
    int size(void);
private:
    int readKey(const char *filename, vector<string> &vec);

private:
    bool m_filter;   //是否开启过滤
    bool m_recordlog;
    vector<string> m_key;
    vector<string> m_keyutf8;
};

#endif
