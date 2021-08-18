/*******************************************************************************************
*文件:  rule_restore.h
*描述:  使用iptables-restore命令快速使iptables生效 管理工具
*作者:  王君雷
*日期:  2020-10-12
*修改:
*******************************************************************************************/
#ifndef __RULE_RESTORE_H__
#define __RULE_RESTORE_H__

#include <list>
#include <string>
using namespace std;

class RuleRestoreMG
{
public:
    RuleRestoreMG(void);
    virtual ~RuleRestoreMG(void);
    bool init(const char *tname, bool v6);
    bool init(const char *tname, const char *chainname, bool v6);
    void clear(void);
    bool run(void);
    bool push_back(const char *chcmd);

private:
    bool m_v6;
    char m_tabname[40];  //表名 如nat filter
    char m_chainname[40];//链名
    char m_tmpfname[128];//临时文件名称
    list<string> m_rule_lst;
};

#endif
