/*******************************************************************************************
*文件:    filename.cpp
*描述:    处理文件名相关，包括路径处理，目录与文件判断，目录文件遍历等
*作者:    张冬波
*日期:    2014-11-12
*修改:    创建文件                            ------>     2014-11-12
*         添加判断隐藏文件                    ------>     2014-11-26
*         修改判断系统目录规则                ------>     2014-12-04
*         基本通过PCLINT检查                  ------>     2014-12-09
*         增加文件名为空的判断                ------>     2015-01-14
*         修改make_filepath特殊限制           ------>     2015-03-03
*         添加匹配后缀名接口                  ------>     2016-11-24
*         支持长文件名                        ------>     2017-10-30
*
*******************************************************************************************/


/*
包含头文件
*/

//系统目录
//#include <apue.h>
#include <sys/stat.h>

//工作目录
#include "filename.h"
#include "debugout.h"
#include "stringex.h"

/*
定义文件操作常量
*/
#ifndef __CYGWIN__
const static char _FILESEPRATORCHAR = '/';
const static char _FILESEPRATORSTRING[] = "/";
#else
const static char _FILESEPRATORCHAR = '\\';
const static char _FILESEPRATORSTRING[] = "\\";
#endif

//指针非法or内容空，则返回false
#define GOTO_FALSE(p) {if(((p) == NULL) || (strlen(p) == 0)) return false;}



/*******************************************************************************************
*功能:    根据当前路径获取目录名和文件名
*参数:    filepath            ---->   文件路径
*         filedir             ---->   目录名
*         filename            ---->   文件名
*
*注释:    存贮空间由调用者维护
*
*******************************************************************************************/
bool split_filepath(const pchar filepath, pchar filedir, pchar filename)
{
    pchar cur;

    GOTO_FALSE(filepath);

    //查找尾端分隔符
    cur = strrchr(filepath, _FILESEPRATORCHAR);

    if (filename != NULL) {
        strcpy2(filename, ((cur == NULL) ? filepath : cur + 1));
    }

    if (filedir != NULL) {
        if (cur != NULL) {
            //strncpy(filedir, filepath, ((cur - filepath) + 1)); //结尾带分隔符
            strcpy2(filedir, filepath);
            filedir[(cur - filepath) + 1] = 0;
        } else {
            filedir[0] = '.';
            filedir[1] = _FILESEPRATORCHAR;
            filedir[2] = 0;
        }

    }

    return true;
}


/*******************************************************************************************
*功能:    根据目录名和文件名生成当前路径
*参数:    filepath            ---->   文件路径
*         filedir             ---->   目录名
*         filename            ---->   文件名
*
*注释:    存贮空间由调用者维护
*
*******************************************************************************************/
bool make_filepath(const pchar filedir, const pchar filename, pchar filepath)
{
    GOTO_FALSE(filedir);
    if (filepath == NULL) return false;

    if (filename == filepath) {
        char tmp[_FILEPATHMAX];

        strcat(strcpy(tmp, filedir), (filedir[strlen(filedir) - 1] != _FILESEPRATORCHAR) ?
               _FILESEPRATORSTRING : "");
        strcat(tmp, (filename[0] != _FILESEPRATORCHAR) ? filename : (filename + 1));

        strcpy(filepath, tmp);

    } else {
        //需要注意在目录后增加分隔符
        strcat(strcpy2(filepath, filedir), (filedir[strlen(filedir) - 1] != _FILESEPRATORCHAR) ?
               _FILESEPRATORSTRING : "");

        if (filename != NULL) {
            strcat(filepath, (filename[0] != _FILESEPRATORCHAR) ? filename : (filename + 1));
        }
    }

    return true;

}

/*******************************************************************************************
*功能:    判断文件路径是否为文件
*参数:    filepath            ---->   文件路径
*
*注释:    此函数会尝试获取文件属性以确保文件的真实性
*
*******************************************************************************************/
bool is_file(const pchar filepath)
{
    struct stat filestat;

    GOTO_FALSE(filepath);

    if (stat(filepath, &filestat) == 0) {
        return S_ISREG(filestat.st_mode);   //判断文件类型是否为常规文件
    }


    return false;

}


/*******************************************************************************************
*功能:    判断文件路径是否为目录
*参数:    filepath            ---->   文件路径
*
*注释:    此函数会尝试获取目录属性以确保目录的真实性
*
*******************************************************************************************/
bool is_dir(const pchar filepath)
{
    struct stat filestat;

    GOTO_FALSE(filepath);

    if (stat(filepath, &filestat) == 0) {
        return S_ISDIR(filestat.st_mode);   //S_ISDIR宏，判断文件类型是否为目录
    }


    return false;

}


/*******************************************************************************************
*功能:    判断文件路径是否为系统目录
*参数:    filepath            ---->   文件路径
*
*注释:
*******************************************************************************************/
bool is_sysdir(const pchar filepath)
{
    const char dir[][8] = {
        {'.', 0},
        {'.', _FILESEPRATORCHAR, 0},
        {'.', '.', 0},
        {'.', '.', _FILESEPRATORCHAR, 0},

    };

    GOTO_FALSE(filepath);

    for (uint i = 0; i < sizeof(dir) / 8; i++) {
        if (strcmp(filepath, &dir[i][0]) == 0)   return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    判断文件是否为系统隐藏文件
*参数:    filepath            ---->   文件路径
*
*注释:    仅适用Linux/Unix
*
*******************************************************************************************/
bool is_hidden(const pchar filepath)
{
    GOTO_FALSE(filepath);

    if (is_sysdir(filepath)) return false;

    return (filepath[0] == '.');
}


/*******************************************************************************************
*功能:    判断文件名是否合法
*参数:    filename            ---->   文件名
*         b_overwrite         ---->   true修复当前错误
*         rc                  ---->   替换字符，0：表示删除
*
*注释:    支持删除和替换
*
*******************************************************************************************/
bool is_filenamevalid(pchar filename, bool b_overwrite, char rc)
{
    const char invalidchar[] = "<>/\\|:\"*?";
    pchar cur;
    bool bret;

    GOTO_FALSE(filename);

    cur = strpbrk(filename, invalidchar);
    bret = (cur == NULL);

    //删除无效内容
    if (b_overwrite && !bret) {

        if (rc == 0) {
            do {
                strcpy2(cur, cur + 1);
                cur = strpbrk(cur + 1, invalidchar);

            } while (cur);
        } else {
            do {
                *cur = rc;
                cur = strpbrk(cur + 1, invalidchar);

            } while (cur);
        }


        bret = true;
    }

    if (!bret) {
        PRINT_INFO_HEAD;
        print_info("filename maybe error(%s)!", filename);
    }

    return bret;

}

/*******************************************************************************************
*功能:    判断文件路径是否合法
*参数:    filepath            ---->   文件名
*         b_overwrite         ---->   true修复当前错误
*         rc                  ---->   文件名替换字符，0：表示删除
*
*注释:
*******************************************************************************************/
bool is_filepathvalid(pchar filepath, bool b_overwrite, char rc)
{
    const char invalidchar[] = "<>|\"*?";
    bool bret = true;
    pchar cur;
    char dir[_FILEPATHMAX] = {0};
    char name[_FILEPATHMAX] = {0};

    GOTO_FALSE(filepath);

    split_filepath(filepath, dir, name);

    cur = strpbrk(dir, invalidchar);
    bret = (cur == NULL);

    if (strlen(name) > 0)
        bret = (bret && is_filenamevalid(name, b_overwrite));

    //删除无效内容
    if (b_overwrite && !bret) {
        PRINT_DBG_HEAD;
        print_dbg("src_filepath = %s", filepath);
        do {
            strcpy2(cur, cur + 1);
            cur = strpbrk(cur + 1, invalidchar);

        } while (cur);

        //新的路径
        make_filepath(dir, name, filepath);
        PRINT_DBG_HEAD;
        print_dbg("src_filepath new = %s", filepath);

        bret = true;
    }

    if (!bret) {
        PRINT_INFO_HEAD;
        print_info("filepath maybe error(%s)!", filepath);
    }


    return bret;
}

/*******************************************************************************************
*功能:    获取文件扩展名
*参数:    filename            ---->   文件名
*         suffix              ---->   扩展名,以.开头
*         name                ---->   文件名
*         返回值              ---->   后缀名长度, -1 : 错误返回
*
*注释:    此函数只分析不带路劲的文件名，
*         无扩展名的文件返回值= 0
*
*******************************************************************************************/
int32 get_filesuffix(const pchar filename, pchar suffix, pchar name)
{
    pchar cur;
    int32 len = 0;

    if ((filename == NULL) || (suffix == NULL))  return -1;

    //查找尾端分隔符"."
    cur = strrchr(filename, '.');

    suffix[0] = 0;
    if (cur != 0) {
        strcpy(suffix, cur);
        len = strlen(suffix);
    }

    if (name != NULL) {
        int32 i = strlen(filename) - (len ? len : (len - 1));

        strncpy(name, filename, i);
        name[i] = 0;
    }

    return len;
}

/*******************************************************************************************
*功能:    获取文件路径的目录
*参数:    filepath            ---->   文件路径
*         filedir             ---->   目录名
*         idx                 ---->   目录索引值，0表示根目录
*         nums                ---->   目录总数
*
*注释:    如果是不包含文件的路径，结尾需要"/"
*         如果是开头根目录，忽略根"/"
*
*******************************************************************************************/
bool get_filedir(const pchar filepath, const int32 idx, pchar filedir, pint32 nums)
{
    int32 count = 0;
    char dir[_FILEPATHMAX] = {0};
    pchar cur, tmp;
    bool bret = true;

    GOTO_FALSE(filepath);

    //备份数据
    strcpy(dir, filepath);
    is_filepathvalid(dir, true);
    split_filepath(dir, dir, NULL);

    PRINT_INFO_HEAD;
    print_info("dir info = %s", dir);

    //目录为空
    if (dir[0] == 0)    return false;

    tmp = cur = dir;
    do {
        if (tmp != dir)
            cur = tmp + 1;
        tmp = strchr(cur, _FILESEPRATORCHAR);
        if (tmp == cur) {
            cur++;
            PRINT_INFO_HEAD;
            print_info("dir root skip");
            continue;
        }
        count++;
        if (idx == (count - 1))    break;

    } while (tmp != NULL);

    //拷贝内容
    if (filedir != NULL) {
        filedir[0] = 0;
        if (idx != (count - 1)) {
            PRINT_ERR_HEAD;
            print_err("idx error %d!", idx);
            bret = false;
            goto _next;
        }
        if (tmp == NULL) {
            strcpy(filedir, cur);
        } else {
            strncpy(filedir, cur, tmp - cur);
            filedir[tmp - cur] = 0;
        }

    }

_next:

    //统计总数
    if (nums != NULL) {
        cur = tmp;
        while (cur != NULL) {
            cur += 1;
            cur = strchr(cur, _FILESEPRATORCHAR);

            count++;
        }
        *nums = count;
    }

    PRINT_INFO_HEAD;
    print_info("dir counts = %d, idx = %d, filedir = %s", count, idx, filedir);

    return bret;
}


/*******************************************************************************************
*功能:    获取文件路径的根目录
*参数:    filepath            ---->   文件路径
*         root                ---->   根目录名
*         返回值              ---->   子目录起始地址
*
*注释:    返回NULL ， 表示结束
*
*******************************************************************************************/
pchar split_rootdir(const pchar filepath, pchar root)
{
    if (get_filedir(filepath, 0, root, NULL)) {

        return (filepath + strlen(root) + 1);
    }

    PRINT_INFO_HEAD;
    print_info("dir path end");
    return NULL;
}


/*******************************************************************************************
*功能:    匹配过滤后缀名
*参数:    filter              ---->   过滤表
*         suffix              ---->   后缀名
*         flag                ---->   分隔符
*         返回值              ---->   true匹配
*
*注释:
*
*******************************************************************************************/
bool filter_filesuffix(const pchar filter, const pchar suffix, const pchar flag)
{
    if (is_strempty(filter) || is_strempty(suffix)) return false;

    char tmp[_FILENAMEMAX];
    pchar ptmp;
    sprintf(tmp, "%s%s", suffix, flag);
    ptmp = strstr_nocase(filter, tmp);  //修改bug96
    if (ptmp != NULL) {
        if ((ptmp == filter) || (*(ptmp - 1) == *flag))  return true;
    }

    return false;
}

/*******************************************************************************************
*功能:    获取长文件名的短别名
*参数:    filepath            ---->   文件路径
*         filename            ---->   文件名
*         newname             ---->   后缀名
*         返回值              ---->   别名指针
*
*注释:    如果文件名没有超出范围，则返回值与filename相同
*
*******************************************************************************************/
static int is_utf8(const pchar data);
pchar get_shortname(const pchar filepath, const pchar filename, pchar newname)
{
    if (is_strempty(filename)) return filename;

    PRINT_DBG_HEAD;
    print_dbg("NEW NAME = %s", filename);

    if ((strlen(filename) > 220) && (newname != NULL)) {

        char tmp[_FILENAMEMAX] = {0};
        get_filesuffix(filename, tmp, newname);

        int32 i = 0;
        do {
            int nbyte;
            if (isascii(newname[i])) i++;
            else if (((uint8)(newname[i]) >= 0x81) && ((uint8)(newname[i]) <= 0xFE) &&
                     ((uint8)(newname[i + 1]) >= 0x40) && ((uint8)(newname[i + 1]) <= 0xFE)) i += 2; //GBK
            else if ((nbyte = is_utf8(&newname[i])) > 0) i += nbyte; //UTF8
            else {
                PRINT_DBG_HEAD;
                print_dbg("NEW NAME UNKNOWN %d=%x", i, newname[i]);
                i++;
            }

            if (i > 199) {
                newname[i] = 0;
#if __DEBUG_MORE__
                PRINT_DBG_HEAD;
                print_dbg("NEW NAME %d(%s)", i, printbuf(filename, strlen(filename)));
#endif
                PRINT_DBG_HEAD;
                print_dbg("NEW NAME %d", i);

                break;
            }

        } while (1);

        struct tm s_tm;
        char timetmp[100] = {0};
        time_t times = time(NULL);

        localtime_r(&times, &s_tm);
        strftime(timetmp, sizeof(timetmp), "%Y%m%d_%H%M%S", &s_tm);
        strcat(newname, timetmp);

        int32 j = 0;
        char fullpath[_FILEPATHMAX] = {0};
        char _no[10] = {0};
        make_filepath(filepath, newname, fullpath);
        strcat(fullpath, tmp);
        while (is_file(fullpath)) {
            make_filepath(filepath, newname, fullpath);
            sprintf(_no, "_%03d", ++j);
            strcat(fullpath, _no);
            strcat(fullpath, tmp);
        }

        if (!is_strempty(_no))  strcat(newname, _no);
        strcat(newname, tmp);

        PRINT_DBG_HEAD;
        print_dbg("NEW NAME = %s", newname);

        return newname;
    }

    return filename;
}

int is_utf8(const pchar data)
{
    uint8 c = (uint8)data[0];
    int following = 0;

    if ((c & 0xC0) == 0xC0) {          /* 11xxxxxx begins UTF-8 */
        if ((c & 0x20) == 0) {
            /* 110xxxxx */
            following = 1;
        } else if ((c & 0x10) == 0) {
            /* 1110xxxx */
            following = 2;
        } else if ((c & 0x08) == 0) {
            /* 11110xxx */
            following = 3;
        } else if ((c & 0x04) == 0) {
            /* 111110xx */
            following = 4;
        } else if ((c & 0x02) == 0) {
            /* 1111110x */
            following = 5;
        }

        for (int i = 1, n = 0; n < following; i++, n++) {
            if (!(c = (uint8)data[i])) {following = 0; break;}
            if ((c & 0xC0) != 0x80) {following = 0; break;}
        }
    }

    if (following != 0) following++;
    return following;
}
