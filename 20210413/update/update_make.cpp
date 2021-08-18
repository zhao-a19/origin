/*******************************************************************************************
*文件: update_make.cpp
*描述: 制作升级包
*作者: 王君雷
*日期: 2018-10-10
*修改：
*      添加内核升级功能                                                 ------> 2019-08-30
*      添加both目录，可以同时升级内外网文件；升级包不再强制要求存在sys6 ------> 2020-02-20wjl
*      升级支持ARM平台                                                  ------> 2020-03-28-dzj
*      自动创建目录 inroot/initrd/abin/,outroot/initrd/abin/,解决他们不
*      存在时，in.sh out.sh无法正确拷贝的问题，不严重                   ------> 2020-05-21
*      支持飞腾平台                                                     ------> 2020-07-27
*      支持tar包首部 2KB异或混淆，解包兼容旧版upk包                     --------> 2021-02-19 zza
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <vector>
using namespace std;

#include "update_make.h"
#include "fileoperator.h"
#include "FCMD5.h"
#include "crc.h"

#define DEBUG_MOD
#define UPDATE_CFG       "update.cfg"

extern int IS_XOR;

//文件权限规则
typedef struct _update_rule {
    char path[1024];        //文件或目录路径
    int permission;         //权限
    bool bdir;              //true是针对目录下所有文件的规则  false是针对具体的单一文件的规则
} UPDATE_RULE, *PUPDATE_RULE;

typedef struct _update_mod {
    char path[1024];        //文件或目录路径
    char modname[256];      //升级模块名
} UPDATE_MOD;
//特殊目录规则
UPDATE_RULE g_spec_rule[] = {
    {"/initrd/abin/", PERM_EXEC, true},
    {"/etc/init.d/", PERM_EXEC, true},
};

extern int g_infcnt, g_outfcnt, g_osfcnt, g_bothfcnt;

/**
 * [check_updatepack_suffix 检查升级包的后缀]
 * @param  filename [升级包名称]
 * @return          [合法返回true]
 */
bool check_updatepack_suffix(const char *filename)
{
    int flen = 0, slen = 0;

    if (filename != NULL) {
        flen = strlen(filename);
        slen = strlen(UPPACK_SUFFIX);
        if (flen >= slen) {
            if (memcmp(filename + flen - slen, UPPACK_SUFFIX, slen) == 0) {
                return true;
            } else {
                printf("check suffix fail[%s],suffix should be [%s]\n", filename, UPPACK_SUFFIX);
            }
        } else {
            printf("check suffix filename too short[%s]\n", filename);
        }
    } else {
        printf("check suffix para null\n");
    }
    return false;
}

/**
 * [check_updatepack_sysver 检查sysver是否合法]
 * @param  sysver [待检查的sysver]
 * @return        [合法返回true]
 */
bool check_updatepack_sysver(const char *sysver)
{
    int len = 0;

    if (sysver != NULL) {
        len = strlen(sysver);
        if (len > SYSVER_MAX_LEN) {
            printf("sysver too long[%s], max support is [%d]\n", sysver, SYSVER_MAX_LEN);
        } else {
            return true;
        }
    } else {
        printf("check sysver para null\n");
    }
    return false;
}

/**
 * [check_updatepack_upver 检查upver是否合法]
 * @param  upver [待检查的upver]
 * @return       [合法返回true]
 */
bool check_updatepack_upver(int upver)
{
    if ((upver > MAX_UPVER) || (upver < MIN_UPVER)) {
        printf("upver [%d] error!\n", upver);
        return false;
    }

    return true;
}

/**
 * [check_updatepack_platver 检查platver是否合法]
 * @param  platver [待检查的平台类型]
 * @return         [合法返回true]
 */
bool check_updatepack_platver(int platver)
{
    if ((PLAT_I686 == platver) || (PLAT_SW_64 == platver) || (PLAT_X86_64 == platver)\
        || (PLAT_ARM_64 == platver) || (PLAT_FT == platver)) {
    } else {
        printf("unknown platver[%d]\n", platver);
        return false;
    }
    return true;
}

/**
 * [read_updatepack_spec_rule 读取升级包文件权限规则 --特殊目录规则]
 * @param  inrule  [存放内网文件权限规则的vector]
 * @param  outrule [存放外网文件权限规则的vector]
 */
void read_updatepack_spec_rule(vector<UPDATE_RULE> &inrule, vector<UPDATE_RULE> &outrule)
{
    for (int i = 0; i < (int)ARRAY_SIZE(g_spec_rule); i++) {
        inrule.push_back(g_spec_rule[i]);
        outrule.push_back(g_spec_rule[i]);
    }
}

/**
 * [read_updatepack_rule 读取升级包文件权限规则]
 * @param  inrule  [存放内网文件权限规则的vector]
 * @param  outrule [存放外网文件权限规则的vector]
 * @return         [读取成功返回true]
 */
bool read_updatepack_rule(vector<UPDATE_RULE> &intrule, vector<UPDATE_RULE> &outrule, vector<UPDATE_MOD> &intmod, vector<UPDATE_MOD> &outmod)
{
    CFILEOP fop;
    int intnum = 0;
    int outnum = 0;
    int intmodnum = 0;
    int outmodnum = 0;
    int plen = 0;
    char item[32] = {0};

    intrule.clear();
    outrule.clear();

    //把特殊目录规则读入
    read_updatepack_spec_rule(intrule, outrule);

    //打开配置文件
    int ret = fop.OpenFile(UPDATE_CFG, "rb");
    if (ret == E_FILE_FALSE) {
        //当不存在配置文件时 继续执行
        printf("warn: [%s] not find\n", UPDATE_CFG);
        return true;
    }

    //读取内网规则个数
    ret = fop.ReadCfgFileInt("SYS", "INNUM", &intnum);
    if (ret == E_FILE_FALSE) {
        printf("read rule intnum fail\n");
        goto _err;
    } else {
        printf("read rule intnum = %d \n", intnum);
    }

    //读取内网升级模块个数
    ret = fop.ReadCfgFileInt("SYS", "INTMODNUM", &intmodnum);
    if (ret == E_FILE_FALSE) {
        printf("read rule intmodnum fail\n");
        goto _err;
    } else {
        printf("read rule intmodnum = %d\n", intmodnum);
    }

    //读取外网规则个数
    ret = fop.ReadCfgFileInt("SYS", "OUTNUM", &outnum);
    if (ret == E_FILE_FALSE) {
        printf("read rule outnum fail\n");
        goto _err;
    } else {
        printf("read rule outnum = %d\n", outnum);
    }

    //读取外网升级模块个数
    ret = fop.ReadCfgFileInt("SYS", "OUTMODNUM", &outmodnum);
    if (ret == E_FILE_FALSE) {
        printf("read rule outmodnum fail\n");
        goto _err;
    } else {
        printf("read rule outnum = %d\n", outmodnum);
    }
#ifdef DEBUG_MOD
    printf("inrulenum %d, outrulenum %d, intmodnum %d, outmodnum %d\n",
           intnum, outnum, intmodnum, outmodnum);
#endif
    //读内网规则
    for (int i = 0; i < intnum; ++i) {
        UPDATE_RULE rule;
        memset(&rule, 0, sizeof(rule));

        sprintf(item, "IN%d", i);
        ret = fop.ReadCfgFile(item, "PATH", rule.path, sizeof(rule.path));
        if (ret == E_FILE_FALSE) {
            printf("read %s PATH fail\n", item);
            goto _err;
        } else {
            printf("read %s PATH = %s \n", item, rule.path);
        }

        ret = fop.ReadCfgFileInt(item, "PERM", &rule.permission);
        if (ret == E_FILE_FALSE) {
            printf("read %s PERM fail\n", item);
            goto _err;
        } else {
            printf("read %s PERM = %d\n", item, rule.permission);
        }

        plen = strlen(rule.path);
        rule.bdir = (*(rule.path + plen - 1) == '/');

        intrule.push_back(rule);
    }

    //读外网规则
    for (int i = 0; i < outnum; ++i) {
        UPDATE_RULE rule;
        memset(&rule, 0, sizeof(rule));

        sprintf(item, "OUT%d", i);
        ret = fop.ReadCfgFile(item, "PATH", rule.path, sizeof(rule.path));
        if (ret == E_FILE_FALSE) {
            printf("read %s PATH fail\n", item);
            goto _err;
        } else {
            printf("read %s PATH = %s\n", item, rule.path);
        }

        ret = fop.ReadCfgFileInt(item, "PERM", &rule.permission);
        if (ret == E_FILE_FALSE) {
            printf("read %s PERM fail\n", item);
            goto _err;
        } else {
            printf("read %s PERM = %d\n", item, rule.permission);
        }

        plen = strlen(rule.path);
        rule.bdir = (*(rule.path + plen - 1) == '/');

        outrule.push_back(rule);
    }

    //读取内网升级模块信息
    for (int i = 0; i < intmodnum; ++i) {
        UPDATE_MOD rule;
        memset(&rule, 0, sizeof(rule));

        sprintf(item, "INTMOD%d", i);
        ret = fop.ReadCfgFile(item, "PATH", rule.path, sizeof(rule.path));
        if (ret == E_FILE_FALSE) {
            printf("read %s PATH fail\n", item);
            goto _err;
        } else {
            printf("read %s PATH = %s \n", item, rule.path);
        }

        ret = fop.ReadCfgFile(item, "NAME", rule.modname, sizeof(rule.modname));
        if (ret == E_FILE_FALSE) {
            printf("read %s NAME fail\n", item);
            goto _err;
        } else {
            printf("read %s NAME = %s\n", item, rule.modname);
        }

        intmod.push_back(rule);
    }

    //读外网升级模块信息
    for (int i = 0; i < outmodnum; ++i) {
        UPDATE_MOD rule;
        memset(&rule, 0, sizeof(rule));

        sprintf(item, "OUTMOD%d", i);
        ret = fop.ReadCfgFile(item, "PATH", rule.path, sizeof(rule.path));
        if (ret == E_FILE_FALSE) {
            printf("read %s PATH fail\n", item);
            goto _err;
        } else {
            printf("read %s PATH = %s\n", item, rule.path);
        }

        ret = fop.ReadCfgFile(item, "NAME", rule.modname, sizeof(rule.modname));
        if (ret == E_FILE_FALSE) {
            printf("read %s NAME fail\n", item);
            goto _err;
        } else {
            printf("read %s NAME = %s\n", item, rule.modname);
        }

        outmod.push_back(rule);
    }
    fop.CloseFile();

#ifdef DEBUG_MOD
    printf("in rule size[%d], out rule size[%d]\n", (int)intrule.size(), (int)outrule.size());
#endif
    return true;
_err:
    fop.CloseFile();
    return false;
}

/**
 * [get_permission 获取文件对应的权限]
 * @param  rule [规则]
 * @param  path [网闸上的文件绝对路径]
 * @return      [需要加可执行权限返回PERM_EXEC  否则返回PERM_DEF]
 */
int get_permission(vector<UPDATE_RULE> &rule, const char *path)
{
    int perm = PERM_DEF;
    for (int i = 0; i < (int)rule.size(); ++i) {
        if (rule[i].bdir) {
            //规则是针对整个目录的
            if ((strlen(rule[i].path) < strlen(path))
                && (memcmp(path, rule[i].path, strlen(rule[i].path)) == 0)) {
                perm = rule[i].permission;
                break;
            }
        } else {
            //规则是针对单个文件的
            if (strcmp(path, rule[i].path) == 0) {
                perm = rule[i].permission;
                break;
            }
        }
    }
    return perm;
}
/**
 * [get_permission 解析文件路径，分配模块名]
 * @param  modrule [规则]
 * @param  path    [打包前文件相对路径]
 * @param  modname [返回的模块名]
 * @return         [成功 0]
 */
int parser_modname(vector<UPDATE_MOD> &modrule, const char *path, char *modname)
{
    for (int i = 0; i < (int)modrule.size(); ++i) {
        if (strstr(path, modrule[i].path) != NULL) {
            strcpy(modname, modrule[i].modname);
            break;
        }

    }

    if (0 == strlen(modname)) {
        strcpy(modname, "升级中");
        printf("path[%s]not find in modname\n", path);
    }
    return 0;
}

/**
 * [make_flat_file 制作一个拉平之后的文件]
 * @param  flatpath [拉平之后的文件名称]
 * @param  filepath [源文件]
 * @param  filehead [文件头部]
 * @return          [成功返回true]
 */
bool make_flat_file(const char *flatpath, const char *filepath, FILE_HEAD &filehead)
{
    unsigned int writebyte = 0;
    int wlen = 0, rlen = 0;
    FILE *fp = NULL;
    FILE *fpsrc = NULL;
    char readbuf[ONCE_READ_BLOCK_SIZE] = {0};

    fp = fopen(flatpath, "wb");
    if (fp == NULL) {
        printf("fopen %s fail[%s]\n", flatpath, strerror(errno));
        return false;
    }

    //写入filehead
    wlen = fwrite(&filehead, 1, sizeof(filehead), fp);
    if (wlen != sizeof(filehead)) {
        printf("fwrite (%s:filehead) fail![%d,%s]\n", flatpath, wlen, strerror(errno));
        fclose(fp);
        goto _err;
    }

    //写入整个文件
    {
        fpsrc = fopen(filepath, "rb");
        if (fpsrc == NULL) {
            printf("fopen fail[%s:%s]\n", filepath, strerror(errno));
            fclose(fp);
            goto _err;
        }

        while (1) {
            if ((rlen = fread(readbuf, 1, sizeof(readbuf), fpsrc)) <= 0) {
                if (feof(fpsrc)) {
                    fclose(fp);
                    fclose(fpsrc);
                    break;
                } else {
                    printf("fread (%s) fail![%d,%s]\n", filepath, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fpsrc);
                    goto _err;
                }
            } else {
                wlen = fwrite(readbuf, 1, rlen, fp);
                if (wlen != rlen) {
                    printf("fwrite (%s) fail![%d:%d,%s]\n", flatpath, wlen, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fpsrc);
                    goto _err;
                }
                writebyte += wlen;
            }
        }
    }

    if (writebyte != filehead.len) {
        printf("[filepath:%s][flatpath:%s][writebyte:%u][filelen:%u]something error!\n",
               filepath, flatpath, writebyte, filehead.len);
        goto _err;
    }

    return true;
_err:
    unlink(flatpath);
    return false;
}

/**
 * [flat_store 拉平存放]
 * @param  rule     [权限规则]
 * @param  filepath [扫描到的文件名]
 * @param  filearea [文件区域类型]
 * @param  fsize    [文件字节数]
 * @return          [成功返回true]
 */
bool flat_store(vector<UPDATE_RULE> &rule, vector<UPDATE_MOD> &modrule, const char *filepath, int filearea, unsigned int fsize)
{
    int fcnt = 0;
    char priority = '*';
    char modname[NAME_MAX_LEN] = {0};
    char flatpath[FILE_PATH_MAX_LEN] = {0}; //拉平后的文件名称

    //为文件头赋值
    FILE_HEAD filehead;
    memset(&filehead, 0, sizeof(filehead));
    strcpy(filehead.checkkey, FHEAD_CHECK_KEY);
    filehead.area = filearea;
    filehead.len = fsize;
    switch (filearea) {
    case FILE_AREA_INNET:
        strcpy(filehead.path, filepath + strlen(INROOT_PATH) - 1);
        filehead.permission = get_permission(rule, filehead.path);
        parser_modname(modrule, filehead.path, modname);
        priority = 'b';
        fcnt = g_infcnt++;
        break;
    case FILE_AREA_OUTNET:
        strcpy(filehead.path, filepath + strlen(OUTROOT_PATH) - 1);
        filehead.permission = get_permission(rule, filehead.path);
        priority = 'a';
        parser_modname(modrule, filehead.path, modname);
        fcnt = g_outfcnt++;
        break;
    case FILE_AREA_OS:
        filehead.permission = 1;
        strcpy(filehead.path, filepath);
        strcpy(modname, "OS");
        priority = '5';
        fcnt = g_osfcnt++;
        break;
    case FILE_AREA_BOTH:
        strcpy(filehead.path, filepath + strlen(BOTH_PATH) - 1);
        filehead.permission = PERM_DEF; //内外网都升级的文件 默认不加可执行权限
        priority = '7';
        strcpy(modname, "LIB");
        fcnt = g_bothfcnt++;
        break;
    default:
        printf("file area error[%d] filepath[%s]\n", filearea, filepath);
        return false;
    }
    printf("process file[AREA:%d][PERM:%d][LEN:%d][PATH:%s]\n", filehead.area, filehead.permission,
           filehead.len, filehead.path);

    //使用文件名规则有区别 保证网闸按文件名排序时 能按预定的顺序扫描到文件
    snprintf(flatpath, sizeof(flatpath), "%sfile-%c-%s-%d", FILES_PATH, priority, modname, fcnt);
    return make_flat_file(flatpath, filepath, filehead);
}

/**
 * [process_file 递归处理文件]
 * @param  rule     [权限规则]
 * @param  filepath [扫描的目录]
 * @param  filearea [文件区域类型]
 * @return          [成功返回true]
 */
bool process_file(vector<UPDATE_RULE> &rule, vector<UPDATE_MOD> &modrule , const char *filepath, int filearea)
{
#ifdef DEBUG_MOD
    //printf("process file begin .....[%s]\n", filepath);
#endif
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char srcpath[FILE_PATH_MAX_LEN] = {0}; //扫描到的文件的本地路径

    if ((dirptr = opendir(filepath)) == NULL) {
        printf("opendir[%s] error[%s]\n", filepath, strerror(errno));
        return false;
    }

    while ((entry = readdir(dirptr)) != NULL) {

        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcpath, sizeof(srcpath), "%s%s", filepath, entry->d_name);
        if (lstat(srcpath, &statbuf) < 0) {
            printf("lstat[%s] error[%s]\n", srcpath, strerror(errno));
            goto _err;
        }

        if (S_ISREG(statbuf.st_mode)) {
            //拉平存放
            if (!flat_store(rule, modrule, srcpath, filearea, statbuf.st_size)) {
                goto _err;
            }
        } else if (S_ISDIR(statbuf.st_mode)) {
            //递归
            snprintf(srcpath, sizeof(srcpath), "%s%s/", filepath, entry->d_name);
            if (!process_file(rule, modrule, srcpath, filearea)) {
                goto _err;
            }
        }
    }

    closedir(dirptr);
    return true;
_err:
    closedir(dirptr);
    return false;
}

/**
 * [tar_file 把拉平放好的升级文件打包]
 * @return [成功返回true]
 */
bool tar_file()
{
    char chcmd[1024] = {0};
    unlink(UPDATE_MK_TMPTAR);
    sprintf(chcmd, "tar -czf %s %s", UPDATE_MK_TMPTAR, FILES_PATH);
    system(chcmd);
    return true;
}

/**
 * [read_sys_ver 读取升级包的系统版本信息]
 * @param  sysver [系统版本 出参]
 * @param  len    [出参长度]
 * @return        [成功返回true]
 */
bool read_sys_ver(char *sysver, int len)
{
    FILE *fp = fopen(SYSVER_FILE, "rb");
    if (fp != NULL) {
        fread(sysver, 1, len - 1, fp);
        fclose(fp);
        int rlen = strlen(sysver);
        if ((rlen > 0) && ((sysver[rlen - 1] == '\r') || (sysver[rlen - 1] == '\n'))) {
            sysver[rlen - 1] = 0;
        }
    } else {
        printf("warn: not find file [%s],use default[%s]\n", SYSVER_FILE, DEFAULT_TOTAL_VER);
    }

    if (sysver[0] == 0) {
        strncpy(sysver, DEFAULT_TOTAL_VER, len - 1);
    }
    printf("version[%s]\n", sysver);
    return true;
}

/**
 * [make_upk 制作最终使用的upk升级包文件]
 * @param  filename [升级包名称]
 * @param  sysver   [sysver系统版本]
 * @param  upver    [防降版版本号]
 * @param  platver  [平台类型]
 * @param  checkkey [固定校验字符]
 * @return          [成功返回true]
 */
bool make_upk(const char *filename, const char *sysver, int upver, int platver, const char *checkkey)
{
    char chsysver[SYSVER_MAX_LEN + 1] = {0};
    char readbuf[ONCE_READ_BLOCK_SIZE] = {0};
    int len = strlen(sysver);
    int wlen = 0;
    int rlen = 0;
    FILE *fptar = NULL;
    FILE *fp = NULL;
    TOTAL_HEAD totalhead;
    bool is_xor = false;
    memset(&totalhead, 0, sizeof(totalhead));

    memset(chsysver, '0', SYSVER_MAX_LEN - len);
    memcpy(chsysver + (SYSVER_MAX_LEN - len), sysver, len);
    strcpy(totalhead.checkkey, checkkey);
    totalhead.upver = upver;
    if (IS_XOR == 0) totalhead.toolver = THIS_TOOL_VER;
    else totalhead.toolver = THIS_TOOL_VER_XOR;
    totalhead.platver = platver;
    read_sys_ver((char *)totalhead.reserved, sizeof(totalhead.reserved));
    if (md5sum(UPDATE_MK_TMPTAR, totalhead.md5buff16) < 0) {
        printf("md5sum fail[%s]\n", UPDATE_MK_TMPTAR);
        goto _err;
    }

    //创建或打开
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("fopen (%s) fail![%s]\n", filename, strerror(errno));
        goto _err;
    }

    //写入sysver
    wlen = fwrite(chsysver, 1, SYSVER_MAX_LEN, fp);
    if (wlen != SYSVER_MAX_LEN) {
        printf("fwrite (%s:sysver) fail![%d,%s]\n", filename, wlen, strerror(errno));
        fclose(fp);
        goto _err;
    }

    //写入totalhead
    wlen = fwrite(&totalhead, 1, sizeof(totalhead), fp);
    if (wlen != sizeof(totalhead)) {
        printf("fwrite (%s:totalhead) fail![%d,%s]\n", filename, wlen, strerror(errno));
        fclose(fp);
        goto _err;
    }

    //写入整个tar文件
    {
        fptar = fopen(UPDATE_MK_TMPTAR, "rb");
        if (fptar == NULL) {
            printf("fopen fail[%s:%s]\n", UPDATE_MK_TMPTAR, strerror(errno));
            fclose(fp);
            goto _err;
        }

        while (1) {
            if ((rlen = fread(readbuf, 1, sizeof(readbuf), fptar)) <= 0) {
                if (feof(fptar)) {
                    fclose(fp);
                    fclose(fptar);
                    break;
                } else {
                    printf("fread fail![%s:%d:%s]\n", UPDATE_MK_TMPTAR, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fptar);
                    goto _err;
                }
            } else {
                if ((!is_xor) && (IS_XOR == 1) && (rlen >= 2048)) {
                    puint8 p1 = (puint8)totalhead.md5buff16;
                    puint32 p2 = (puint32)readbuf;
                    uint32 sed = GetCRC32((puint8)p1, 16);
                    for (int32 i = 0; i < 2048; i += sizeof(uint32)) {
                        uint32 tmp = *p2;
                        *p2 = tmp ^ sed;
                        p2++;
                    }
                    is_xor = true;
                }
                wlen = fwrite(readbuf, 1, rlen, fp);
                if (wlen != rlen) {
                    printf("fwrite fail[%s:%d:%d:%s]\n", filename, wlen, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fptar);
                    goto _err;
                }
            }
        }
    }

    unlink(UPDATE_MK_TMPTAR);
    printf("infile %d,outfile %d,osfile %d,bothfile %d\n", g_infcnt, g_outfcnt, g_osfcnt, g_bothfcnt);
    return true;

_err:
    unlink(UPDATE_MK_TMPTAR);
    unlink(filename);
    return false;
}

/**
 * [make_updatepack 制作升级包]
 * @param  filename [升级包名称]
 * @param  sysver   [sysver系统版本]
 * @param  upver    [防降版版本号]
 * @param  platver  [平台类型]
 * @return          [制作成功返回true]
 */
bool make_updatepack(const char *filename, const char *sysver, int upver, int platver)
{
    bool bret = false, bfindos = false;;
    vector<UPDATE_RULE> intrule;
    vector<UPDATE_RULE> outrule;
    vector<UPDATE_RULE> osrule;
    vector<UPDATE_RULE> bothrule;
    vector<UPDATE_MOD> intmod;
    vector<UPDATE_MOD> outmod;
    vector<UPDATE_MOD> osmod;
    vector<UPDATE_MOD> bothmod;
    char chcmd[1024] = {0};

    //把存放拉平文件的目录清空
    sprintf(chcmd, "mkdir -p %s", FILES_PATH);
    system(chcmd);
    sprintf(chcmd, "rm -rf %s*", FILES_PATH);
    system(chcmd);
    sprintf(chcmd, "mkdir -p %sinitrd/abin/", INROOT_PATH);
    system(chcmd);
    sprintf(chcmd, "mkdir -p %sinitrd/abin/", OUTROOT_PATH);
    system(chcmd);
    sprintf(chcmd, "cp -f %s %s%s", IN_SHELL, INROOT_PATH, GAP_IN_SHELL);
    system(chcmd);
    sprintf(chcmd, "cp -f %s %s%s", OUT_SHELL, OUTROOT_PATH, GAP_OUT_SHELL);
    system(chcmd);

#ifdef DEBUG_MOD
    printf("filename[%s] sysver[%s] upver[%d] platver[%d]\n", filename, sysver, upver, platver);
#endif

    //if ((access(INROOT_SYS6, F_OK) != 0) || (access(OUTROOT_SYS6, F_OK) != 0)) {
    //    printf("Warn:file[%s]or[%s] not existed\n", INROOT_SYS6, OUTROOT_SYS6);
    //}

    bret = check_updatepack_suffix(filename)                          //后缀名合法性检查
           && check_updatepack_sysver(sysver)                         //sysver系统版本合法性检查
           && check_updatepack_upver(upver)                           //防降版版本号检查
           && check_updatepack_platver(platver)                       //平台类型检查
           && read_updatepack_rule(intrule, outrule, intmod, outmod); //读取配置规则

    if (bret && (0 == access(OS_UPDATE_SHELL, F_OK)) && (0 == access(OS_UPDATE_PACK, F_OK))) {
        bret = process_file(osrule, osmod, OS_PATH, FILE_AREA_OS);          //扫描内核升级目录 按配置规则 组装好 拉平存放到同一个目录下
        bfindos = true;
        printf("contain os file = %s and file = %s\n", OS_UPDATE_PACK, OS_UPDATE_SHELL);
    }
    if (bret) {
        bret = process_file(intrule, intmod, INROOT_PATH, FILE_AREA_INNET)       //扫描内网升级目录 按配置规则 组装好 拉平存放到同一个目录下
               && process_file(outrule, outmod, OUTROOT_PATH, FILE_AREA_OUTNET); //扫描外网升级目录 按配置规则 组装好 拉平存放到同一个目录下
    }
    if (bret && (access(BOTH_PATH, F_OK) == 0)) {
        bret = process_file(bothrule, bothmod, BOTH_PATH, FILE_AREA_BOTH);
    }
    if (bret) {
        bret = tar_file()                                  //打包文件
               && make_upk(filename, sysver, upver, platver, bfindos ? TOTAL_OS_KEY : TOTAL_CHECK_KEY); //生成upk文件
    }
    return bret;
}
