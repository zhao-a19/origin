/*******************************************************************************************
*文件:  rule_restore.cpp
*描述:  使用iptables-restore命令快速使iptables生效 管理工具
*作者:  王君雷
*日期:  2020-10-12
*修改:
*******************************************************************************************/
#include <errno.h>
#include "rule_restore.h"
#include "debugout.h"
#include "define.h"

RuleRestoreMG::RuleRestoreMG(void)
{
    memset(m_tabname, 0, sizeof(m_tabname));
}

RuleRestoreMG::~RuleRestoreMG(void)
{

}

/**
 * [RuleRestoreMG::init 初始化]
 * @param  tname [表名]
 * @param  v6    [是否为IPv6]
 * @return       [成功返回true]
 */
bool RuleRestoreMG::init(const char *tname, bool v6)
{
    if ((tname != NULL) && (strlen(tname) < sizeof(m_tabname))) {
        strcpy(m_tabname, tname);
        m_v6 = v6;
        sprintf(m_tmpfname, "/tmp/rule_%s_%s", tname, v6 ? "6" : "4");
        return true;
    }
    PRINT_ERR_HEAD
    print_err("init fail[%s]", tname);
    return false;
}

/**
 * [RuleRestoreMG::init 初始化]
 * @param  tname     [表名]
 * @param  chainname [链名]
 * @param  v6        [是否为IPv6]
 * @return           [成功返回true]
 */
bool RuleRestoreMG::init(const char *tname, const char *chainname, bool v6)
{
    if ((tname != NULL) && (strlen(tname) < sizeof(m_tabname))
        && (chainname != NULL) && (strlen(chainname) < sizeof(m_chainname))) {
        strcpy(m_tabname, tname);
        strcpy(m_chainname, chainname);
        m_v6 = v6;
        sprintf(m_tmpfname, "/tmp/rule_%s_%s_%s", tname, chainname, v6 ? "6" : "4");
        return true;
    }
    PRINT_ERR_HEAD
    print_err("init fail[%s][%s]", tname, chainname);
    return false;
}

/**
 * [RuleRestoreMG::clear 清空规则]
 */
void RuleRestoreMG::clear(void)
{
    m_rule_lst.clear();
}

/**
 * [RuleRestoreMG::run 执行iptables规则]
 * @return  [成功返回true]
 */
bool RuleRestoreMG::run(void)
{
    PRINT_INFO_HEAD
    print_info("run begin...");

    char *commit = "COMMIT\n";
    char chcmd[CMD_BUF_LEN] = {0};

    if (m_rule_lst.empty()) {
        PRINT_INFO_HEAD
        print_info("rule lst empty");
        return true;
    }
    remove(m_tmpfname);
    FILE *fp = fopen(m_tmpfname, "w");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen %s fail %s", m_tmpfname, strerror(errno));
        return false;
    }

    fwrite("*", 1, 1, fp);
    fwrite(m_tabname, strlen(m_tabname), 1, fp);
    fwrite("\n", 1, 1, fp);

    list<string>::iterator iter;
    for (iter = m_rule_lst.begin(); iter != m_rule_lst.end(); ++iter) {
        int len = strlen(iter->c_str());
        fwrite((iter->c_str()), len, 1, fp);
    }
    fwrite(commit, strlen(commit), 1, fp);
    fclose(fp);

    sprintf(chcmd, "%s -n < %s", m_v6 ? "ip6tables-restore" : "iptables-restore", m_tmpfname);
    system(chcmd);
    PRINT_INFO_HEAD
    print_info("run over[%s]", chcmd);
    return true;
}

/**
 * [RuleRestoreMG::push_back 添加一条规则]
 * @param  chcmd [规则命令]
 * @return       [成功返回true]
 */
bool RuleRestoreMG::push_back(const char *chcmd)
{
    if (chcmd != NULL) {
        m_rule_lst.push_back(chcmd);
        return true;
    }
    PRINT_ERR_HEAD
    print_err("para null[%s]", chcmd);
    return false;
}
