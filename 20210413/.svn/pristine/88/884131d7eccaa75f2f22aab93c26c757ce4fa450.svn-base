/*******************************************************************************************
*文件:    syscfg.h
*描述:    配置文件操作
*
*作者:    张冬波
*日期:    2015-01-05
*修改:    创建文件                            ------>     2015-01-05
*         取消map自定义排序，inster会失败     ------>     2015-01-07
*         删除错误引用头文件                  ------>     2015-11-24
*         修改文件路径错误                    ------>     2016-02-23
*         配置文件输入范围bug，最长内容限制条件和文件路径匹配
*                                             ------>     2017-03-30
*         扩大配置项的值长度到1M              ------>     2020-07-03 wjl
*         每行缓冲区大小最大值由1M改为10K        ------>  2020-07-30
*         每行缓冲区大小最大值由10K改为1M        ------>  2021-03-25
*         每行缓冲区大小最大值由1M改为512K,按文件交换要求------>  2021-03-29
*******************************************************************************************/
#ifndef __SYSCFG_H__
#define __SYSCFG_H__

#include "filename.h"

//map相关使用
#include <map>
#include <string>
using namespace std;

#define CONTENT_MAX 100

#define MAX_VALUE_LEN (1024 * 512)

class CSYSCFG
{
public:
    CSYSCFG();
    virtual ~CSYSCFG();
    CSYSCFG(const pchar filepath, bool readonly = true);                                    //构造函数并打开文件
    CSYSCFG(const pchar filepath, bool bcase, bool readonly);                               //构造函数并打开文件
    bool open(const char *filepath, bool readonly = true, bool list = false);               //打开文件，并插入map
    bool write(void);                                                                       //写入map信息到文件
    bool close(void);                                                                       //关闭文件
    const pchar getfilename(void);
    bool getitem(const pchar key, const pchar item, int32 &value);                          //读取一项配置信息
    const pchar getitem(const pchar key, const pchar item);

    bool setitem(const pchar key, const pchar item, int32 value, bool hex = false);         //写入一项配置信息
    bool setitem(const pchar key, const pchar item, const pchar value);
    bool delitem(const pchar key, const pchar item, bool all = false);                      //删除配置项

    void setcase(bool bcase);                                                               //打开/关闭大小写

    const map<string, string> &getmap(void);
    bool operator == (const CSYSCFG &obj);
    bool operator != (const CSYSCFG &obj);
    bool finddiff(const CSYSCFG &obj, map<string, bool> &cmp, bool &other, bool bfuzzy = false);
    void makekey(const pchar key, const pchar item, string &mapkey);                        //map键值格式化

    static const int32 ERROR_F = -1;  //文件错误
    static const int32 ERROR = -1;

protected:
    FILE *fop;                                                                              //文件句柄

private:
    bool bferror;                                                                           //文件格式错误
    bool bfupdate;                                                                          //写文件更新
    char filename[_FILEPATHMAX];                                                            //记录打开文件路径名
    char filekey[CONTENT_MAX];                                                              //记录最近一次有效的配置信息项
    char fileitem[CONTENT_MAX];
    //char filevalue[_FILEPATHMAX];
    //char filevalue[MAX_VALUE_LEN];
    char *filevalue;

    void init(void);                                                                        //初始化相关参数
    int32 ffindkey(const pchar key, bool rewind = false);                                   //文件查找键值
    int32 ffinditem(const pchar item);                                                      //文件查抄字段和值
    static void splitkey(string mapkey, pchar key, pchar item);

    //自定义map排序，"[...]"内容排序
    struct mapsort {
        bool operator()(const string &k1, const string &k2)
        {
            char Key1[CONTENT_MAX] = {0}, Key2[CONTENT_MAX] = {0};
            char item[CONTENT_MAX];

            splitkey(k1, Key1, item);
            splitkey(k2, Key2, item);
            return (strcmp(Key1, Key2) < 0);
        }
    };

    map<string, string> mapcfg;                                                    //文件所有配置信息map
    bool m_case;                                                                   //区分大小
};


#endif

