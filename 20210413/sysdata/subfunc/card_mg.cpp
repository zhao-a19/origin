/*******************************************************************************************
*文件:  card_mg.cpp
*描述:  策略使用到的网卡汇总管理
*作者:  王君雷
*日期:  2020-10-22
*修改:
*******************************************************************************************/
#include <algorithm>
#include "card_mg.h"
#include "debugout.h"

CardMG::CardMG(void)
{
    m_total = sizeof(m_card) / sizeof(m_card[0]);
    PRINT_INFO_HEAD
    print_info("total num is %d", m_total);
}

CardMG::~CardMG(void)
{

}

/**
 * [CardMG::clear 清空网卡汇总信息]
 */
void CardMG::clear(void)
{
    for (int i = 0; i < m_total; ++i) {
        m_card[i].vec_in.clear();
        m_card[i].vec_out.clear();
    }
}

/**
 * [CardMG::clear 清空某模块的网卡汇总信息]
 * @param modnum [模块编号]
 */
void CardMG::clear(int modnum)
{
    if ((modnum >= 0) && (modnum < m_total)) {
        m_card[modnum].vec_in.clear();
        m_card[modnum].vec_out.clear();
        PRINT_INFO_HEAD
        print_info("modnum[%d] clear", modnum);
    } else {
        PRINT_ERR_HEAD
        print_err("modnum[%d] error. total[%d]", modnum, m_total);
    }
}

/**
 * [CardMG::add 添加网卡信息]
 * 保证同一模块统计时忽略重复的 不同模块有可能重复
 * @param modnum  [模块编号]
 * @param incard  [内网卡号]
 * @param outcard [外网卡号]
 */
void CardMG::add(int modnum, int incard, int outcard)
{
    if ((modnum >= 0) && (modnum < m_total)) {
        if (incard >= 0) {
            push(m_card[modnum].vec_in, incard);
        }
        if (outcard >= 0) {
            push(m_card[modnum].vec_out, outcard);
        }
        PRINT_INFO_HEAD
        print_info("add card modnum %d, incard %d, outcard %d", modnum, incard, outcard);
    } else {
        PRINT_ERR_HEAD
        print_err("modnum[%d] error. total[%d]", modnum, m_total);
    }
}

/**
 * [CardMG::add 添加网卡信息]
 * @param modnum [模块编号]
 * @param card   [网卡号]
 * @param isout  [是否为外网]
 */
void CardMG::add(int modnum, int card, bool isout)
{
    if ((modnum >= 0) && (modnum < m_total)) {
        if (card >= 0) {
            push(isout ? m_card[modnum].vec_out : m_card[modnum].vec_in, card);
            PRINT_INFO_HEAD
            print_info("modnum[%d] %s add %d", modnum, isout ? "outnet" : "innet", card);
        } else {
            PRINT_ERR_HEAD
            print_err("modnum[%d] card error[%d]", modnum, card);
        }
    } else {
        PRINT_ERR_HEAD
        print_err("modnum[%d] error. total[%d]", modnum, m_total);
    }
}

/**
 * [CardMG::getTotal 获取模块总数]
 * @return  [模块总数]
 */
int CardMG::getTotal(void)
{
    return m_total;
}

/**
 * [CardMG::getMod 获取模块结构信息]
 * @param  modnum [模块编号]
 * @return        [模块结构]
 */
MOD_CARD *CardMG::getMod(int modnum)
{
    if ((modnum >= 0) && (modnum < m_total)) {
        return &(m_card[modnum]);
    } else {
        PRINT_ERR_HEAD
        print_err("modnum[%d] error. total[%d]", modnum, m_total);
        return NULL;
    }
}

/**
 * [CardMG::analysis 汇总整理网卡信息]
 */
void CardMG::analysis(void)
{
    m_vec_in.clear();
    m_vec_out.clear();
    for (int i = 0; i < m_total; ++i) {
        MOD_CARD *pmod = &m_card[i];
        for (int j = 0; j < pmod->vec_in.size(); ++j) {
            push(m_vec_in, pmod->vec_in[j]);
        }
        for (int j = 0; j < pmod->vec_out.size(); ++j) {
            push(m_vec_out, pmod->vec_out[j]);
        }
    }
}

/**
 * [CardMG::push 把网卡放进vector 如果重复就不放了]
 * @param vec  [vector]
 * @param card [网卡]
 */
void CardMG::push(vector<int> &vec, int card)
{
    vector<int>::iterator it = find(vec.begin(), vec.end(), card);
    if (it == vec.end()) {
        vec.push_back(card);
    } else {
        PRINT_INFO_HEAD
        print_info("ignore card %d", card);
    }
}

/**
 * [CardMG::getInVec 获取内网汇总整理的网卡信息]
 */
vector<int> &CardMG::getInVec(void)
{
    return m_vec_in;
}

/**
 * [CardMG::getOutVec 获取外网汇总整理的网卡信息]
 */
vector<int> &CardMG::getOutVec(void)
{
    return m_vec_out;
}

/**
 * [CardMG::getInVec 获取汇总网卡组中下标为id的网卡号 内网]
 * @param  id [下标编号]
 * @return    [网卡号]
 */
int CardMG::getInVec(int id)
{
    return m_vec_in[id];
}

/**
 * [CardMG::getOutVec 获取汇总网卡组中下标为id的网卡号 外网]
 * @param  id [下标编号]
 * @return    [网卡号]
 */
int CardMG::getOutVec(int id)
{
    return m_vec_out[id];
}

/**
 * [CardMG::show 展示信息]
 */
void CardMG::show(void)
{
    showMod();
    showAnalysis();
}

/**
 * [CardMG::showMod 按模块展示信息]
 */
void CardMG::showMod(void)
{
    for (int i = 0; i < m_total; ++i) {
        MOD_CARD *pmod = &m_card[i];
        PRINT_INFO_HEAD
        print_info("MODNUM[%-2d] modname[%-10s] card info:===================", i, g_modinfo[i].name);
        for (int j = 0; j < pmod->vec_in.size(); ++j) {
            PRINT_INFO_HEAD
            print_info("in card: %d", pmod->vec_in[j]);
        }
        for (int j = 0; j < pmod->vec_out.size(); ++j) {
            PRINT_INFO_HEAD
            print_info("out card: %d", pmod->vec_out[j]);
        }
    }
}

/**
 * [CardMG::showAnalysis 展示汇总之后的信息]
 */
void CardMG::showAnalysis(void)
{
    PRINT_INFO_HEAD
    print_info("analysis card info(innet):===================");
    for (int i = 0; i < m_vec_in.size(); ++i) {
        PRINT_INFO_HEAD
        print_info("in card: %d", m_vec_in[i]);
    }

    PRINT_INFO_HEAD
    print_info("analysis card info(outnet):===================");
    for (int i = 0; i < m_vec_out.size(); ++i) {
        PRINT_INFO_HEAD
        print_info("out card: %d", m_vec_out[i]);
    }
}

