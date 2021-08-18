
/*******************************************************************************************
*文件:    syscfg.cpp
*描述:    配置文件操作
*
*作者:    张冬波
*日期:    2015-01-05
*修改:    创建文件                            ------>     2015-01-05
*         修改map操作bug                      ------>     2015-01-07
*         支持Key默认大写                     ------>     2015-01-09
*         修改map删除键值但未同步写入文件bug  ------>     2015-02-05
*         修改键值不存在,导致非法内存访问bug  ------>     2015-04-29
*         修改配置文件写入bug, 添加调试信息   ------>     2016-02-27
*         修改key匹配bug，统一list和文件处理  ------>     2016-07-12
*         修改编译兼容性问题                  ------>     2016-09-22
*         支持大小写配置                      ------>     2016-12-16
*         支持注释行                          ------>     2017-02-09
*         修改读取数据空间使用bug             ------>     2018-07-25
*         修改ffindkey函数中KEY查找时错误     ------>     2020-07-21
          支持内容匹配比较处理                ------>     2020-10-07
*         反写配置文件添加单引号              ------>     2020-10-26
*         修改日志级别                        ------>     2020-10-27
*******************************************************************************************/
using namespace std;

#include "datatype.h"
#include "stringex.h"
#include "debugout.h"
#include "syscfg.h"
#include <string>
#include <ctype.h>

//#define _LINEMAX_   1500
#define _LINEMAX_  MAX_VALUE_LEN

//字符串处理
#define cfgstrupper(s) if(!m_case) strupper(s)
#define cfgstrncmp(s1, s2, n) (m_case ? strncmp(s1, s2, n) : strncasecmp(s1, s2, n))
#define cfgstrcmp(s1, s2) (m_case ? strcmp(s1, s2) : strcmp_nocase(s1, s2))

//注释, 行首字符为英文;号或者#号
#define _is_comment(l) ((*(l) == ';') || (*(l) == '#'))

//#define ptr_diff(s1,s2) (ptr_t)((s1)-(s2))

/*******************************************************************************************
*功能:    构造
*参数:    filepath            ---->   文件路径名
*         bcase               ---->   true 区分大小写关键字
*         readonly            ---->   true 只读方式
*
*注释:
*******************************************************************************************/
CSYSCFG::CSYSCFG()
{
    init();
}


CSYSCFG::CSYSCFG(const pchar filepath, bool readonly)
{
    init();

    if (!this->open(filepath, readonly)) {

        PRINT_DBG_HEAD;
        print_dbg("%s can't open!", filepath);
    }
}

CSYSCFG::CSYSCFG(const pchar filepath, bool bcase, bool readonly)
{
    init();
    setcase(bcase);

    if (!this->open(filepath, readonly)) {

        PRINT_DBG_HEAD;
        print_dbg("%s can't open!", filepath);
    }
}

/*******************************************************************************************
*功能:    内部参数初始化
*参数:
*
*注释:
*******************************************************************************************/
void CSYSCFG::init(void)
{
    fop = NULL;
    bferror = false;
    bfupdate = false;
    setcase(true);    //默认区分大小写

    memset(filename, 0, sizeof(filename));
    mapcfg.clear();
    while (1) {
        filevalue = (char *)malloc(MAX_VALUE_LEN);
        if (filevalue == NULL) {
            PRINT_ERR_HEAD
            print_err("malloc fail ,retry");
            sleep(1);
        } else {
            break;
        }
    }
}

/*******************************************************************************************
*功能:    析构
*参数:
*
*注释:
*******************************************************************************************/
CSYSCFG::~CSYSCFG()
{
    PRINT_DBG_HEAD;
    print_dbg("CSYSCFG END!");

    this->close();
    mapcfg.clear();
    if (filevalue != NULL) {
        free(filevalue);
        filevalue = NULL;
    }
}

/*******************************************************************************************
*功能:    打开文件
*参数:    filepath            ---->   文件路径名
*         readonly            ---->   true 只读方式
*         list                ---->   true 记录map
*         返回值              ---->   true 成功
*
*注释:
*******************************************************************************************/

bool CSYSCFG::open(const char *filepath, bool readonly, bool list)
{
    bool bret = false;

    close();

    if (filepath != NULL) {

        if (readonly) {
            fop = fopen(filepath, "rb");
        } else {
            fop = fopen(filepath, "ab+");       //写入方式，默认map记录
            list = true;
        }

        strcpy(filename, filepath);
        if (fop != NULL) {
            fseek(fop, 0, SEEK_SET);
            bret = true;
        }
    }

    PRINT_DBG_HEAD;
    print_dbg("open %s %s!", filepath, bret ? "success" : "failed");

    //记录所有键值到map
    if (list && bret) {
        int32 prepos;

        bferror = true;
        while (feof(fop) == 0) {
            //查抄开始标志
            if (ffindkey(NULL) == CSYSCFG::ERROR)    continue;

            while (feof(fop) == 0) {
                prepos = ftell(fop);
                if (ffinditem(NULL) > 0) {
                    bferror = false;
                    //插入记录
                    string newkey;
                    makekey(filekey, fileitem, newkey);

                    PRINT_DBG_HEAD;
                    print_dbg("key = %s, value = %s", newkey.c_str(), filevalue);
#if 1
                    pair<map<string, string>::iterator, bool> mapret;
                    mapret = mapcfg.insert(pair<string, string>(newkey, filevalue));
                    if (!mapret.second) {
                        PRINT_ERR_HEAD;
                        print_err("map insert(%s = %s)", newkey.c_str(), filevalue);
                    }
#else
                    mapcfg.insert(pair<string, string>(newkey, filevalue));
#endif
                } else {
                    fseek(fop, prepos, SEEK_SET);
                    ffindkey(NULL);
                }
            }
        }

//#if __DEBUG_INFO__
#if 0
        //测试用
        {
            //输出map全部记录
            map<string, string>::iterator i;
            int32 j;

            PRINT_INFO_HEAD;
            print_info("%s config counts = %d", filename, mapcfg.size());

            for (i = mapcfg.begin(), j = 1; i != mapcfg.end(); i++, j++) {
                PRINT_INFO_HEAD;
                print_info("CONFIG_%03d %s = %s", j, ((string)(i->first)).c_str(), ((string)(i->second)).c_str());
            }
        }

#endif

    }

    return bret;
}

/*******************************************************************************************
*功能:    关闭文件
*参数:    返回值              ---->   true 成功
*
*注释:
*******************************************************************************************/

bool CSYSCFG::close(void)
{
    this->write();
    if (fop != NULL) fclose(fop);

    fop = NULL;
    memset(filename, 0, sizeof(filename));
    mapcfg.clear();

    return true;
}

/*******************************************************************************************
*功能:    写文件
*参数:    返回值              ---->   true 成功
*
*注释:    map中的信息同步写入文件, 防止写入首尾空白符号
*
*******************************************************************************************/

bool CSYSCFG::write(void)
{
    if ((fop != NULL) && bfupdate) {
        PRINT_DBG_HEAD;
        print_dbg("write start");

        if (ftruncate(fileno(fop), 0) == 0) {

            //重写入文件内容
            map<string, string>::iterator i;
            string newkey;
            char key[CONTENT_MAX] = {0};

            //顺序写入
            for (i = mapcfg.begin(); i != mapcfg.end(); i++) {
                newkey = (string)i->first;
                splitkey(newkey, filekey, fileitem);
                strdelspace(filekey);
                strdelspace(fileitem);

                if (strcmp(key, filekey) != 0) {
                    fputs(filekey, fop);
                    fputs("\n", fop);
                    strcpy(key, filekey);

                    PRINT_DBG_HEAD;
                    print_dbg("write key = %s", key);
                }

                fputs(fileitem, fop);
                fputs("=", fop);

                strcpy(filevalue, ((string)i->second).c_str());
                strdelspace(filevalue);
                fputs(filevalue, fop);
                fputs("\n", fop);

                PRINT_DBG_HEAD;
                print_dbg("write item %s = %s", fileitem, filevalue);
            }

            fflush(fop);
            bfupdate = false;
            return true;
        }
    }
    return false;
}

/*******************************************************************************************
*功能:    读取当前文件名
*参数:    返回值              ---->   文件名指针， NULL（错误）
*
*注释:
*******************************************************************************************/

const pchar CSYSCFG::getfilename(void)
{

    if (strlen(filename) == 0)   return NULL;

    return (const pchar)filename;
}

/*******************************************************************************************
*功能:    读取数字
*参数:    key              ---->   主键
*         item             ---->   字段
*         value            ---->   整数
*         返回值           ---->   true 成功
*
*注释:
*******************************************************************************************/
bool CSYSCFG::getitem(const pchar key, const pchar item, int32 &value)
{
    return str2intex(getitem(key, item), &value);
}

/*******************************************************************************************
*功能:    读取字符
*参数:    key              ---->   主键
*         item             ---->   字段
*         返回值           ---->   字符串指针，NULL(错误)
*
*注释:    字符指针禁止修改其内容
*
*******************************************************************************************/
const pchar CSYSCFG::getitem(const pchar key, const pchar item)
{

    if ((key == NULL) || (item == NULL)) return NULL;

    PRINT_DBG_HEAD;
    print_dbg("KEY = %s, ITEM = %s", key, item);

    if (!mapcfg.empty()) {

        string newkey;
        map<string, string>::iterator i;

        makekey(key, item, newkey);
        i = mapcfg.find(newkey);
        if (i == mapcfg.end()) return NULL;

        //bug 2018-07-25
        strcpy(filevalue, (const pchar)((string)(i->second)).c_str());
        PRINT_DBG_HEAD;
        print_dbg("KEY = %s, ITEM = %s, DATA = %s", key, item, filevalue);

        return (const pchar)filevalue;

    } else if (!bferror) {
        if ((ffindkey(key, true) >= 0) && (ffinditem(item) > 0)) {

            PRINT_DBG_HEAD;
            print_dbg("KEY = %s, ITEM = %s, DATA = %s", key, item, filevalue);
            return (const pchar)filevalue;
        }

    }

    return NULL;
}

/*******************************************************************************************
*功能:    格式化map的key
*参数:    key              ---->   主键
*         item             ---->   字段
*         mapkey           ---->   map的格式key
*
*注释:    格式化定义[key].item
*
*******************************************************************************************/
#include <algorithm>
void CSYSCFG::makekey(const pchar key, const pchar item, string &mapkey)
{
    if ((key != NULL) && (item != NULL)) {

        if ((key[0] == '[') && (key[strlen(key) - 1] == ']')) {
            mapkey = key + string(".") + item;
        } else {
            mapkey = string("[") + key + "]." + item;
        }

        if (!m_case)  transform(mapkey.begin(), mapkey.end(), mapkey.begin(), ::toupper);
    }

}

void CSYSCFG::splitkey(string mapkey, pchar key, pchar item)
{
    if ((key != NULL) && (item != NULL)) {

        pchar p1 = (pchar)mapkey.c_str(), p2;

        if ((p2 = strstr(p1, "].")) != NULL) {
            uint32 len = ptr_diff((p2 + 1) , p1);
            strncpy(key, p1, len);
            key[len] = 0;

            strcpy(item, p2 + 2);

        }
    }
}

/*******************************************************************************************
*功能:    查找主键
*参数:    key              ---->   主键
*         rewind           ---->   返回文件首地址
*         返回值           ---->   文件位置， -1(失败)
*
*注释:
*
*******************************************************************************************/
int32 CSYSCFG::ffindkey(const pchar key, bool rewind)
{
    if (fop == NULL) return CSYSCFG::ERROR_F;

    char line[_LINEMAX_];
    int32 fpos = -1;

    if (rewind)  fseek(fop, 0, SEEK_SET);

    PRINT_DBG_HEAD;
    print_dbg("key = %s", key);

    while (feof(fop) == 0) {

        fpos = ftell(fop);
        memset(line, 0, sizeof(line));

        //键值匹对
        strdelspace(fgets(line, sizeof(line), fop));

        //注释判断
        if (_is_comment(line)) continue;

        if ((line[0] == '[') && (line[strlen(line) - 1] == ']')) {
            if (key != NULL) {
                //与list模式处理二义性，key支持自带[] 2016-07-12
                if ((key[0] == '[') && (key[strlen(key) - 1] == ']')) {
                    if (cfgstrncmp(line, key, strlen(key)) == 0) {
                        strcpy(filekey, line);
                        cfgstrupper(filekey);
                        break;
                    }
                } else if (cfgstrncmp(&line[1], key, strlen(line) - 2) == 0) {
                    strcpy(filekey, line);
                    cfgstrupper(filekey);
                    break;
                }
            } else {
                strcpy(filekey, line);
                cfgstrupper(filekey);
                break;
            }
        }

        fpos = -1;
        if (key == NULL) break;
    }

    if (fpos != -1) {
        PRINT_DBG_HEAD;
        print_dbg("key find = %s", filekey);
    }

    return fpos;
}

/*******************************************************************************************
*功能:    查找字段
*参数:    item             ---->   字段
*         返回值           ---->   文件位置， -1(失败)
*
*注释:
*
*******************************************************************************************/
int32 CSYSCFG::ffinditem(const pchar item)
{
    if (fop == NULL) return CSYSCFG::ERROR_F;

    char line[_LINEMAX_];
    char tmp[_LINEMAX_];
    pchar p;

    int32 fpos = -1;

    PRINT_DBG_HEAD;
    print_dbg("item = %s", item);

    while (feof(fop) == 0) {

        fpos = ftell(fop);
        memset(line, 0, sizeof(line));

        //键值匹对
        strdelspace(fgets(line, sizeof(line), fop));

        //注释判断
        if (_is_comment(line)) continue;

        if ((p = strchr(line, '=')) != NULL) {
            memset(tmp, 0, sizeof(tmp));
            strncpy(tmp, line, ptr_diff(p, line));

            strdelspace(tmp);
            cfgstrupper(tmp);
            if (item != NULL) {
                if (cfgstrcmp(tmp, item) == 0) {
                    strcpy(fileitem, tmp);
                    strdelspace(strcpy(filevalue, p + 1));
                    //strstrip_(strcpy(filevalue, p + 1), " \t\r\n'");
                    break;
                }

            } else {
                strcpy(fileitem, tmp);
                strdelspace(strcpy(filevalue, p + 1));
                //strstrip_(strcpy(filevalue, p + 1), " \t\r\n'");
                break;
            }

        }

        fpos = -1;
        if (item == NULL) {
            break;
        } else {
            //遇到[]结束
            strdelspace(line);
            if ((line[0] == '[') && (line[strlen(line) - 1] == ']')) break;

        }
    }

    if (fpos != -1) {
        PRINT_DBG_HEAD;
        print_dbg("item find %s = %s", fileitem, filevalue);
    }

    return fpos;
}

/*******************************************************************************************
*功能:    新建or更新字段
*参数:    key              ---->   主键
*         item             ---->   字段
*         valude           ---->   字符串
*         返回值           ---->   true 成功
*
*注释:    打开open(const pchar filepath, bool readonly, bool list)指定list=true
*
*******************************************************************************************/
bool CSYSCFG::setitem(const pchar key, const pchar item, const pchar value)
{
    if ((key == NULL) || (item == NULL)) return false;
    string newkey;

    PRINT_DBG_HEAD;
    print_dbg("KEY = %s, ITEM = %s, DATA = %s", key, item, value);

    makekey(key, item, newkey);
    if (delitem(key, item)) {
        PRINT_DBG_HEAD;
        print_dbg("delete key = %s", newkey.c_str());
    }

#if 1
    pair<map<string, string>::iterator, bool > mapret;
    mapret = mapcfg.insert(pair<string, string>(newkey, ((value == NULL) ? "" : value)));
    if (!mapret.second) {
        PRINT_ERR_HEAD;
        print_err("map insert(%s = %s)", newkey.c_str(), ((value == NULL) ? "" : value));
        return false;
    }
#else
    mapcfg.insert(pair<string, string>(newkey, ((value == NULL) ? "" : value)));
#endif

    PRINT_DBG_HEAD;
    print_dbg("KEY = %s, ITEM = %s, DATA = %s", key, item, value);

    bfupdate = true;            //记录更新
    return true;
}

/*******************************************************************************************
*功能:    新建or更新字段
*参数:    key              ---->   主键
*         item             ---->   字段
*         valude           ---->   字符串
*         hex              ---->   16进制
*         返回值           ---->   true 成功
*
*注释:
*
*******************************************************************************************/
bool CSYSCFG::setitem(const pchar key, const pchar item, int32 value, bool hex)
{
    char tmp[40] = {0};

    if (hex) {
        sprintf(tmp, "0x%x", value);
    } else {
        sprintf(tmp, "%u", value);
    }

    return setitem(key, item, tmp);
}

/*******************************************************************************************
*功能:    查找字段
*参数:    key              ---->   主键
*         item             ---->   字段
*         all              ---->   true 清空所有记录
*         返回值           ---->   true 成功
*
*注释:
*
*******************************************************************************************/
bool CSYSCFG::delitem(const pchar key, const pchar item, bool all)
{
    if ((key == NULL) || (item == NULL)) return false;

    bool bret = false;

    PRINT_DBG_HEAD;
    print_dbg("KEY = %s, ITEM = %s, ALL = %d", key, item, all);

    if (!mapcfg.empty()) {
        if (all) {
            mapcfg.clear();
            bret = true;
        } else {

            string newkey;
            map<string, string>::iterator i;

            makekey(key, item, newkey);
            i = mapcfg.find(newkey);
            if (i != mapcfg.end()) {
                mapcfg.erase(i);
                bret = true;
            }
        }

    }

    if (bret) {
        bfupdate = true;
        PRINT_DBG_HEAD;
        print_dbg("KEY = %s, ITEM = %s, ALL = %d", key, item, all);
    }

    return bret;
}

/*******************************************************************************************
*功能:    设置配置文件匹配规则
*参数:    bcase              ---->   true 区分大小写
*
*注释:    map方式必须在打开文件之前调用
*
*******************************************************************************************/
void CSYSCFG::setcase(bool bcase)
{
    m_case =  bcase;
}

const map<string, string> &CSYSCFG::getmap(void)
{
    return mapcfg;
}

/*******************************************************************************************
*功能:    比较内容是否一致
*参数:    obj              ---->   右值
*
*注释:   必须是map方式打开
*
*******************************************************************************************/
bool CSYSCFG::operator == (const CSYSCFG &obj)
{
    if (this == &obj) return true;

    PRINT_DBG_HEAD;
    print_dbg("equal name %s %s", filename, obj.filename);
    //if (strcmp(filename, obj.filename) != 0) return false;

    PRINT_DBG_HEAD;
    print_dbg("equal size %u %u", mapcfg.size(), obj.mapcfg.size());

    if (mapcfg.size() != obj.mapcfg.size()) return false;

    map<string, string> maptmp = obj.mapcfg;
    map<string, string>::iterator i, j;
    int32 n;

    for (i = mapcfg.begin(), n = 0; i != mapcfg.end(); i++, n++) {
        PRINT_DBG_HEAD;
        print_dbg("equal[%03d] %s = %s", n, ((string)(i->first)).c_str(), ((string)(i->second)).c_str());

        j = maptmp.find(i->first);
        if ((j != maptmp.end()) && (((string)(i->second)) == ((string)(j->second)))) continue;

        PRINT_DBG_HEAD;
        print_dbg("equal[%03d] %s = %s", n, ((string)(i->first)).c_str(), ((string)(i->second)).c_str());

        if (j != maptmp.end()) {
            PRINT_DBG_HEAD;
            print_dbg("equal %s = %s", ((string)(j->first)).c_str(), ((string)(j->second)).c_str());
        }

        return false;
    }

    PRINT_DBG_HEAD;
    print_dbg("equal[%d] %s %s", n, filename, obj.filename);
    return true;

}

bool CSYSCFG::operator != (const CSYSCFG &obj)
{
    return (*this == obj) ? false : true;
}

/**
 * [CSYSCFG::finddiff description]
 * @Author   张冬波
 * @DateTime 2020-10-07
 * @param    obj        [description]
 * @param    cmp        [比较内容，value=true 内容一致]
 * @param    other      [其他项的一致性，true]
 * @param    bfuzzy     [true 精准匹配]
 * @return              [整体的一致性，true=cmp.value]
 */
//other反应非map中的键值变化，返回值bret反应为map中的键值变化
bool CSYSCFG::finddiff(const CSYSCFG &obj, map<string, bool> &cmp, bool &other, bool bfuzzy)
{
    if (cmp.size() == 0) {
        PRINT_DBG_HEAD;
        print_dbg("equal empty");
        other = false;
        return false;
    }

    PRINT_DBG_HEAD;
    print_dbg("diff name %s %s", filename, obj.filename);

    PRINT_DBG_HEAD;
    print_dbg("diff %d, size %u:%u", bfuzzy, mapcfg.size(), obj.mapcfg.size());
    bool bret = true;
    other = true;

    map<string, bool>::iterator i;
    map<string, string> maptmp = obj.mapcfg;
    map<string, string>::iterator j, k;
    int32 n;

    if (!bfuzzy) {
        //精准比较
        for (i = cmp.begin(), n = 0; i != cmp.end(); i++, n++) {
            j = mapcfg.find(i->first);
            k = maptmp.find(i->first);

            i->second = false;
            if ((j != mapcfg.end()) && (k != maptmp.end())) {
                if ((((string)(j->second)) == ((string)(k->second)))) {//相同
                    i->second = true;
                }
            } else if ((j == mapcfg.end()) && (k == maptmp.end())) {
                i->second = true;
            }

            bret &= i->second;
            PRINT_DBG_HEAD;
            print_dbg("diff[%02d] %s = %d", n, ((string)(i->first)).c_str(), i->second);
        }

        //其他内容
        for (j = mapcfg.begin(); j != mapcfg.end(); j++) {
            if (cmp.find((string)(j->first)) != cmp.end()) continue;

            k = maptmp.find(j->first);
            if ((k != maptmp.end()) && ((string)(j->second) == (string)(k->second))) continue;
            other = false;

            if (k == maptmp.end()) {
                PRINT_DBG_HEAD;
                print_dbg("diff %s = %s not found", ((string)(j->first)).c_str(), ((string)(j->second)).c_str());
            } else {
                PRINT_DBG_HEAD;
                print_dbg("diff %s = %s, %s = %s", ((string)(j->first)).c_str(), ((string)(j->second)).c_str(),
                          ((string)(k->first)).c_str(), ((string)(k->second)).c_str());
            }
            break;//只要检索到非map中的项就退出
        }
    } else {
        //模糊比较，仅限主标签
        for (i = cmp.begin(); i != cmp.end(); i++) {
            i->second = true;
        }

        for (j = mapcfg.begin(); j != mapcfg.end(); j++) {
            for (i = cmp.begin(), n = 0; i != cmp.end(); i++, n++) {
                splitkey((string)(j->first), filekey, fileitem);
                if (((string)(j->first)).find((string)(i->first)) == 0) {
                    if (!i->second) break;

                    i->second = false;
                    k = maptmp.find(j->first);
                    if ((k != maptmp.end()) && ((string)(j->second) == (string)(k->second))) {
                        i->second = true;
                    }
                    bret &= i->second;
                    PRINT_DBG_HEAD;
                    print_dbg("diff[%02d] %s = %d", n, ((string)(i->first)).c_str(), i->second);
                    break;
                }
            }

            if ((i == cmp.end()) && other) {
                //其他内容
                k = maptmp.find(j->first);
                if ((k != maptmp.end()) && ((string)(j->second) == (string)(k->second))) continue;

                other = false;
                if (k == maptmp.end()) {
                    PRINT_DBG_HEAD;
                    print_dbg("diff %s = %s not found", ((string)(j->first)).c_str(), ((string)(j->second)).c_str());
                } else {
                    PRINT_DBG_HEAD;
                    print_dbg("diff %s = %s, %s = %s", ((string)(j->first)).c_str(), ((string)(j->second)).c_str(),
                              ((string)(k->first)).c_str(), ((string)(k->second)).c_str());
                }
            }
        }

    }

#if 0
    for (i = cmp.begin(), n = 0; i != cmp.end(); i++, n++) {
        PRINT_INFO_HEAD;
        print_info("diff[%02d] %s = %d", n, ((string)(i->first)).c_str(), (bool)(i->second));
    }

#endif

    PRINT_DBG_HEAD;
    print_dbg("diff %d = %d:%d", bfuzzy, bret, other);
    return bret;
}
