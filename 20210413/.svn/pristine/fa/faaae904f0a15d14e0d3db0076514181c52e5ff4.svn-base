/*******************************************************************************************
*文件:  keyword_mg.cpp
*描述:  关键字过滤管理
*作者:  王君雷
*日期:  2020-10-13
*修改:
*       程序优化，当关键字的GBK编码与UTF8编码相同时，只设置一次iptables      ------> 2020-12-10
*******************************************************************************************/
#include <errno.h>
#include <semaphore.h>
#include "keyword_mg.h"
#include "readcfg.h"
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"
#include "FCDelSpace.h"
#include "simple.h"
#include "rule_restore.h"

extern sem_t *g_iptables_lock;
extern vector<string> g_vec_FilterKey;
extern vector<string> g_vec_FilterKeyUTF8;
extern bool g_ckkey;

KeywordMG::KeywordMG(void)
{
    m_recordlog = false;
    m_filter = false;
    m_key.clear();
    m_keyutf8.clear();
}

KeywordMG::~KeywordMG(void)
{
    m_key.clear();
    m_keyutf8.clear();
}

/**
 * [KeywordMG::readConf 读取配置]
 * @return  [成功返回0]
 */
int KeywordMG::readConf(void)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSSET_CONF, "r") != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("OpenFile[%s] fail", SYSSET_CONF);
        return -1;
    }

    int tmpint = 0;
    READ_INT(fileop, "SYSTEM", "FilterFlag", tmpint, false, _out);
    g_ckkey = m_filter = (tmpint == 1);

    tmpint = 0;
    READ_INT(fileop, "SYSTEM", "RecordLog", tmpint, false, _out);
    m_recordlog = (tmpint == 1);

    fileop.CloseFile();

    m_key.clear();
    m_keyutf8.clear();

    if (m_filter) {
        readKey(KEY_CONF, g_vec_FilterKey);
        readKey(KEYUTF8_CONF, g_vec_FilterKeyUTF8);
        if (g_vec_FilterKeyUTF8.size() != g_vec_FilterKey.size()) {
            PRINT_INFO_HEAD
            print_info("filterkey size[%d], filterkeyutf8 size[%d]",
                       (int)g_vec_FilterKey.size(), (int)g_vec_FilterKeyUTF8.size());
            g_vec_FilterKeyUTF8.clear();
        }
        m_key = g_vec_FilterKey;
        m_keyutf8 = g_vec_FilterKeyUTF8;
    }
    return 0;
_out:
    fileop.CloseFile();
    return -1;
}

/**
 * [KeywordMG::readKey 读取内容审查关键字]
 * @param  filename [文件名称]
 * @param  vec      [存放读取到的关键字的vector]
 * @return          [成功返回0 失败返回负值]
 */
int KeywordMG::readKey(const char *filename, vector<string> &vec)
{
    vec.clear();

    char buf[1024] = {0};
    char buf_o[1024] = {0};

    //打开文件
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("open file[%s] fail.[%s]", filename, strerror(errno));
        return -1;
    }

    //循环读取
    while ((fgets(buf, sizeof(buf), fp)) != NULL) {
        a_trim(buf_o, buf);
        if (strlen(buf_o) > MAX_FILTER_KEY_LEN) {
            PRINT_ERR_HEAD
            print_err("key too long[%s],max size support is[%d].ignore it",
                      buf_o, MAX_FILTER_KEY_LEN);
        } else {
            vec.push_back(string(buf_o));
            PRINT_DBG_HEAD
            print_dbg("key[%s]", buf_o);
        }
        BZERO(buf);
        BZERO(buf_o);
    }

    //关闭文件
    fclose(fp);
    return 0;
}

/**
 * [KeywordMG::setRule 设置关键字过滤相关规则]
 * @return  [成功返回0]
 */
int KeywordMG::setRule(void)
{
    PRINT_INFO_HEAD
    print_info("set rule begin");

    char chcmd[CMD_BUF_LEN] = {0};

    RuleRestoreMG rulemgv4;
    RuleRestoreMG rulemgv6;
    rulemgv4.init("filter", "FILTER_KEYWORD", false);
    rulemgv6.init("filter", "FILTER_KEYWORD", true);

    sem_wait(g_iptables_lock);
    system("iptables -F FILTER_KEYWORD");
    system("ip6tables -F FILTER_KEYWORD");
    sem_post(g_iptables_lock);

    bool utf8key = (m_key.size() == m_keyutf8.size());

    for (int i = 0; i < (int)m_key.size(); i++) {
        if (m_recordlog) {
            //通过查资料可知，--log-prefix之后的字符串最大支持29B，关键字的长度很容易超过该长度
            //使用函数encodekey对字符串计算出一个1B的校验值，再转换为16进制的字符串
            //最终--log-prefix之后的字段形如 FILTERLOG_2_E8
            sprintf(chcmd,
                    "-A FILTER_KEYWORD -m string --string \"%s\" --algo bm --from 40 -j LOG --log-level 7 "
                    "--log-prefix \"FILTERLOG_%d_%02X \"\n",
                    m_key[i].c_str(), i, encodekey(m_key[i].c_str()));
            rulemgv4.push_back(chcmd);
            rulemgv6.push_back(chcmd);
        }

        sprintf(chcmd, "-A FILTER_KEYWORD -m string --string \"%s\" --algo bm --from 40 -j DROP\n",
                m_key[i].c_str());
        rulemgv4.push_back(chcmd);
        rulemgv6.push_back(chcmd);
        if (utf8key && (m_key[i] != m_keyutf8[i])) {
            if (m_recordlog) {
                sprintf(chcmd,
                        "-A FILTER_KEYWORD -m string --string \"%s\" --algo bm --from 40 -j LOG --log-level 7 "
                        "--log-prefix \"FILTERLOG_%d_%02X \"\n",
                        m_keyutf8[i].c_str(), i, encodekey(m_key[i].c_str()));
                rulemgv4.push_back(chcmd);
                rulemgv6.push_back(chcmd);
            }
            sprintf(chcmd, "-A FILTER_KEYWORD -m string --string \"%s\" --algo bm --from 40 -j DROP\n",
                    m_keyutf8[i].c_str());
            rulemgv4.push_back(chcmd);
            rulemgv6.push_back(chcmd);
        }
    }
    rulemgv4.run();
    rulemgv6.run();
    PRINT_INFO_HEAD
    print_info("set rule over");
    return 0;
}

/**
 * [KeywordMG::size 关键字个数]
 * @return  [关键字个数]
 */
int KeywordMG::size(void)
{
    return m_key.size();
}
