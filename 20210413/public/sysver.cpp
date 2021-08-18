
/*******************************************************************************************
*文件:    sysver.cpp
*描述:    版本管理
*
*作者:    张冬波
*日期:    2015-01-08
*修改:    创建文件                            ------>     2015-01-08
*         添加时间属性                        ------>     2015-01-15
*         添加写入时间                        ------>     2015-04-29
*
*******************************************************************************************/
#include "datatype.h"
#include "stringex.h"
#include "debugout.h"
#include "sysdir.h"
#include "sysver.h"
#include <sys/file.h>

static const pchar _VERSIONHEAD = "#:ANMIT UNIGAP VERSION\n#\n\n";
static const pchar _VERSIONMARK = ":|=";
static const uint16 _LINEMAX = 200;

//#define ptr_diff(s1,s2) (ptr_t)((s1)-(s2))

//文件控制锁
#define _LOCK(f) {flock(fileno(f), LOCK_EX);}
#define _UNLOCK(f) {flock(fileno(f), LOCK_UN);}

/*******************************************************************************************
*功能:    文件头检查
*参数:    fop                         ---->   文件句柄
*         返回值                      ---->   true 成功
*
*注释:
*
*******************************************************************************************/
static bool sysver_check(FILE *fop)
{
    if (fop != NULL) {

        char info[100] = {0};

        //int32 i = ftell(fop);

        fseek(fop, 0, SEEK_SET);
        fread(info, 1, strlen(_VERSIONHEAD), fop);
        //fseek(fop, i, SEEK_SET);

        PRINT_DBG_HEAD;
        print_dbg(info);

        return (strcmp(info, _VERSIONHEAD) == 0);
    }

    return false;
}

/*******************************************************************************************
*功能:    版本管理初始化
*参数:
*
*注释:    文件创建
*
*******************************************************************************************/
void sysver_init()
{
    FILE *fop;

    fop = fopen(SysVerFile, "wb+");

    if (fop != NULL) {

        _LOCK(fop);
        fwrite(_VERSIONHEAD, 1, strlen(_VERSIONHEAD), fop);
        _UNLOCK(fop);

        PRINT_DBG_HEAD;
        print_dbg("%s opened", SysVerFile);

        fclose(fop);

    }
}

/*******************************************************************************************
*功能:    注册版本信息
*参数:    modelname                     ---->   模块名
*         version                       ---->   版本
*         date                          ---->   build时间
*         返回值                        ---->   true 成功
*
*注释:
*
*******************************************************************************************/
bool sysver_write(const pchar modelname, const pchar version, const pchar date)
{
    if ((modelname == NULL) || (version == NULL)) return false;
    if ((strlen(modelname) == 0) || (strlen(version) == 0)) return false;

    FILE *fop;
    bool bret = false;

    if ((fop = fopen(SysVerFile, "a+b")) != NULL) {

        _LOCK(fop);
        if (sysver_check(fop)) {
            char line[_LINEMAX] = {0};
            char wt[100] = {0};     //写入时间

            time_t secs;
            struct tm s_tm;

            secs = time(NULL);
            localtime_r(&secs, &s_tm);
            strftime(wt, sizeof(wt), "%F %T", &s_tm);

            //格式化写入
            fseek(fop, 0, SEEK_END);
            if (date == NULL)
                sprintf(line, "[%s%s%s%s%s]\n", modelname, _VERSIONMARK, version,
                        _VERSIONMARK, wt);
            else
                sprintf(line, "[%s%s%s%s%s%s%s]\n", modelname, _VERSIONMARK, version,
                        _VERSIONMARK, date, _VERSIONMARK, wt);

            strupper(line);
            fputs(line, fop);
            bret = true;

            PRINT_DBG_HEAD;
            print_dbg("write one = %s", line);

        }
        _UNLOCK(fop);

        fclose(fop);
    }

    return bret;
}


/*******************************************************************************************
*功能:    读取版本信息
*参数:    modelname                     ---->   模块名
*         version                       ---->   版本
*         date                          ---->   build时间
*         fop                           ---->   文件句柄
*         rewind                        ---->   true 从头开始
*         返回值                        ---->   -1 文件结束  0 失败  1成功
*
*注释:
*
*******************************************************************************************/
int32 sysver_read(pchar modelname, pchar version, pchar date, FILE *fop, bool rewind)
{
    if ((modelname == NULL) || (version == NULL)) return 0;

    int32 ret = 0;
    static FILE *sfop = NULL;      //内部保留，文件结束时关闭

    if (fop == NULL) {
        if (sfop == NULL)
            sfop = fopen(SysVerFile, "rb");
        fop = sfop;
    }

    if (fop != NULL) {

        _LOCK(fop);

        //文件检查
        ret = 1;
        if (rewind)
            ret = sysver_check(fop) ? 1 : 0;

        //读取格式化文件
        if (ret == 1) {
            char line[_LINEMAX] = {0};
            pchar p, p1;
            uint32 len;

            ret = -1;
            while (feof(fop) == 0) {
                fgets(line, sizeof(line), fop);

                //分析版本信息
                strdelspace(line);
                if ((line[0] != '[') || (line[strlen(line) - 1] != ']'))   continue;
                p = strstr(&line[1], _VERSIONMARK);
                if ((p == NULL) || (p == &line[1]))   continue;

                //结束返回
                PRINT_DBG_HEAD;
                print_dbg("read one = %s", line);

                len = ptr_diff(p, (&line[1]));
                strncpy(modelname, &line[1], len);
                modelname[len] = 0;

                if ((p1 = strstr(p + strlen(_VERSIONMARK), _VERSIONMARK)) == NULL) {
                    strcpy(version, p + strlen(_VERSIONMARK));
                    version[strlen(version) - 1] = 0;

                } else {
                    len = ptr_diff(p1, (p + strlen(_VERSIONMARK)));
                    strncpy(version, p + strlen(_VERSIONMARK), len);
                    version[len] = 0;

                    if (date != NULL) {
                        strcpy(date, p1 + strlen(_VERSIONMARK));
                        date[strlen(date) - 1] = 0;
                    }
                }

                ret = 1;
                break;
            }

        }
        _UNLOCK(fop);

        if ((ret != 1) && (sfop != NULL)) {
            fclose(sfop);
            sfop = NULL;
        }
    }

    return ret;
}

/*******************************************************************************************
*功能:    读取版本信息
*参数:    modelname                     ---->   模块名
*         version                       ---->   版本
*         date                          ---->   build时间
*         返回值                        ---->   true 成功
*
*注释:    由调用者指定模块名
*
*******************************************************************************************/
bool sysver_read2(const pchar modelname, pchar version, pchar date)
{
    if ((modelname == NULL) || (version == NULL)) return false;
    if (strlen(modelname) == 0) return false;

    FILE *fop;
    bool bret = false;

    if ((fop = fopen(SysVerFile, "a+b")) != NULL) {
        char line[_LINEMAX] = {0};

        if (sysver_read(line, version, date, fop, true) == 1) {

            do {
                if (strcmp_nocase(modelname, line) == 0) {
                    bret = true;
                    break;
                }
            } while (sysver_read(line, version, date, fop, false) == 1);
        }

        fclose(fop);
    }

    return bret;
}

