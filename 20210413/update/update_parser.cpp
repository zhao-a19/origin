/*******************************************************************************************
*文件: update_parser.cpp
*描述: 升级包解析
*作者: 王君雷
*日期: 2018-10-10
*修改：
*      添加内核升级功能                                                 ------> 2019-08-30
*      子进程等待重启（由父进程负责输出success给外部调用）（宋宇）      ------> 2019-09-29
*      添加both目录，可以同时升级内外网文件，去除fork逻辑               ------> 2020-02-20wjl
*      升级完成后，删除掉升级过程中产生的临时tar文件                    ------> 2020-02-25
*      升级支持ARM平台                                                  ------> 2020-03-28-dzj
*      支持飞腾平台                                                     ------> 2020-07-27
*      支持tar包首部 2KB异或混淆，解包兼容旧版upk包                     --------> 2021-02-19 zza
*******************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

//#include "gap_config.h"
#include "debugout.h"
#include "update_parser.h"
#include "FCMD5.h"
#include "crc.h"

extern int IS_XOR;

/**
 * [check_updatepack_size 检查升级包大小是否合法]"
 * @param  filename [升级包名称]
 * @param  hassysver[升级包带sysver字段则为true]
 * @return          [检查通过返回true]
 */
bool check_updatepack_size(const char *filename, bool hassysver)
{
    struct stat statbuf;
    bool bret = false;

    if (lstat(filename, &statbuf) < 0) {
        PRINT_ERR_HEAD
        print_err("lstat[%s] error[%s]", filename, strerror(errno));
        printf("lstat[%s] error %s\n", filename, strerror(errno));
    } else {
        if (S_ISREG(statbuf.st_mode)) {
            if (statbuf.st_size > (int)sizeof(TOTAL_HEAD) + (hassysver ? SYSVER_MAX_LEN : 0)) {
                bret = true;
            } else {
                PRINT_ERR_HEAD
                print_err("the file size is too small.[%s:%d]", filename, (int)statbuf.st_size);
                printf("the file size is too small.[%s:%d]\n", filename, (int)statbuf.st_size);
            }
        } else {
            PRINT_ERR_HEAD
            print_err("not reqular file[%s]", filename);
            printf("not reqular file[%s]\n", filename);
        }
    }

    return bret;
}

/**
 * [uppack_updatepack 拆解升级包]
 * @param  filename  [升级包名称]
 * @param  totalhead [升级包头部]
 * @param  chsysver  [用于存放系统版本号]
 * @return           [成功返回true]
 */
bool uppack_updatepack(const char *filename, TOTAL_HEAD &totalhead, char *chsysver)
{
    int rlen = 0, wlen = 0;
    FILE *fp = NULL;
    FILE *fptar = NULL;
    char chcmd[1024] = {0};
    char readbuf[ONCE_READ_BLOCK_SIZE] = {0};
    bool is_xor = false;

    //删除临时文件  创建临时目录
    unlink(UPDATE_PASR_TMPTAR);
    sprintf(chcmd, "rm -rf %s*", UPDATE_PASR_TMPDIR);
    system(chcmd);
    sprintf(chcmd, "mkdir -p %s", UPDATE_PASR_TMPDIR);
    system(chcmd);

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen %s fail[%s]", filename, strerror(errno));
        printf("fopen %s fail[%s]\n", filename, strerror(errno));
        return false;
    }

    //如果是带sysver的升级包
    if (chsysver != NULL) {
        if ((rlen = fread(chsysver, 1, SYSVER_MAX_LEN, fp)) != SYSVER_MAX_LEN) {
            PRINT_ERR_HEAD
            print_err("fread sysver fail[%s:%d:%s]", filename, rlen, strerror(errno));
            printf("fread sysver fail[%s:%d:%s]\n", filename, rlen, strerror(errno));
            fclose(fp);
            goto _err;
        }
    }

    //读取头部
    if ((rlen = fread(&totalhead, 1, sizeof(totalhead), fp)) != sizeof(totalhead)) {
        PRINT_ERR_HEAD
        print_err("fread totalhead fail[%s:%d:%s]", filename, rlen, strerror(errno));
        printf("fread totalhead fail[%s:%d:%s]\n", filename, rlen, strerror(errno));
        fclose(fp);
        goto _err;
    }

    //读取剩余内容到临时文件
    {
        fptar = fopen(UPDATE_PASR_TMPTAR, "wb");
        if (fptar == NULL) {
            PRINT_ERR_HEAD
            print_err("fopen fail[%s:%s]", UPDATE_PASR_TMPTAR, strerror(errno));
            printf("fopen fail[%s:%s]\n", UPDATE_PASR_TMPTAR, strerror(errno));
            fclose(fp);
            goto _err;
        }

        while (1) {
            if ((rlen = fread(readbuf, 1, sizeof(readbuf), fp)) <= 0) {
                if (feof(fp)) {
                    fclose(fp);
                    fclose(fptar);
                    break;
                } else {
                    PRINT_ERR_HEAD
                    print_err("fread fail[%s:%d:%s]", filename, rlen, strerror(errno));
                    printf("fread fail[%s:%d:%s]\n", filename, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fptar);
                    goto _err;
                }
            } else {
                if ((!is_xor) && (totalhead.toolver > THIS_TOOL_VER_XOR_OFFSET) && (rlen >= 2048)) {
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
                wlen = fwrite(readbuf, 1, rlen, fptar);
                if (wlen != rlen) {
                    PRINT_ERR_HEAD
                    print_err("fwrite fail[%s:%d:%d:%s]", filename, wlen, rlen, strerror(errno));
                    printf("fwrite fail[%s:%d:%d:%s]\n", filename, wlen, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fptar);
                    goto _err;
                }
            }
        }
    }

    return true;
_err:
    return false;
}

/**
 * [check_totalhead 检查升级包头部]
 * @param  totalhead [升级包头部]
 * @return           [检查通过返回true]
 */
bool check_totalhead(TOTAL_HEAD &totalhead)
{
    unsigned char md5buff16[16] = {0};

    if ((strcmp(totalhead.checkkey, TOTAL_CHECK_KEY) != 0) && (strcmp(totalhead.checkkey, TOTAL_OS_KEY) != 0)) {
        PRINT_ERR_HEAD
        print_err("check key fail");
        printf("check key fail\n");                             //外部调用需要获取输出信息
        return false;
    }

    if (!check_updatepack_platver(totalhead.platver)) {
        return false;
    }

    if (md5sum(UPDATE_PASR_TMPTAR, md5buff16) < 0) {
        PRINT_ERR_HEAD
        print_err("md5sum fail[%s]", UPDATE_PASR_TMPTAR);
        printf("md5sum fail[%s]\n", UPDATE_PASR_TMPTAR);        //外部调用需要获取输出信息
        return false;
    }

    if (memcmp(md5buff16, totalhead.md5buff16, 16) != 0) {
        PRINT_ERR_HEAD
        print_err("md5sum check fail.[%s]", UPDATE_PASR_TMPTAR);
        printf("md5sum check fail.[%s]\n", UPDATE_PASR_TMPTAR); //外部调用需要获取输出信息
        return false;
    }
    return true;
}

/**
 * [print_totalhead 打印头部等相关信息]
 * @param  totalhead [升级包头部]
 * @param  chsysver  [网闸系统版本号]
 * @return           [成功返回true]
 */
bool print_totalhead(TOTAL_HEAD &totalhead, const char *chsysver)
{
    printf("******************* PACKET INFO ***********************\n");
    printf("sysver  : %s\n", chsysver);
    printf("checkkey: %s\n", totalhead.checkkey);
    printf("upver   : %u\n", totalhead.upver);
    printf("toolver : %d\n", totalhead.toolver);
    if (totalhead.platver == PLAT_I686) {
        printf("platver : I686\n");
    } else if (totalhead.platver == PLAT_SW_64) {
        printf("platver : SW_64\n");
    } else if (totalhead.platver == PLAT_X86_64) {
        printf("platver : X86_64\n");
    } else if (totalhead.platver == PLAT_ARM_64) {
        printf("platver : ARM_64\n");
    } else if (totalhead.platver == PLAT_FT) {
        printf("platver : FT\n");
    } else {
        printf("platver : unknown %d\n", totalhead.platver);
    }
    printf("md5     : ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", totalhead.md5buff16[i]);
    }
    printf("\n*******************************************************\n");
    return true;
}

/**
 * [unpack_tmptar 解压临时tar文件]
 * @return [成功返回true]
 */
bool unpack_tmptar()
{
    char chcmd[1024] = {0};
    sprintf(chcmd, "tar -xzf %s -C %s", UPDATE_PASR_TMPTAR, UPDATE_PASR_TMPDIR);
    system(chcmd);
    unlink(UPDATE_PASR_TMPTAR);
    return true;
}

/**
 * [filter_fun 过滤函数 供scandir使用]
 * @param  ent [dirent结构指针]
 * @return     [是文件返回1]
 */
int filter_fun(const struct dirent *ent)
{
    return ((ent->d_type == DT_REG) ? 1 : 0);
}

/**
 * [uppack_updatefile 把解压缩之后的目录中的文件，提取头部，并把真正的文件内容还原到另一个文件]
 * @param  filepath [解压缩之后的目录中的文件]
 * @param  orgpath  [还原之后的文件]
 * @param  filehead [文件头部 出参]
 * @return          [成功返回true]
 */
bool uppack_updatefile(const char *filepath, const char *orgpath, FILE_HEAD &filehead)
{
    int rlen = 0;
    int wlen = 0;
    unsigned int writebyte = 0;
    FILE *fp = NULL;
    FILE *fporg = NULL;
    char readbuf[ONCE_READ_BLOCK_SIZE] = {0};

    fp = fopen(filepath, "rb");
    if (fp == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen fail[%s:%s]", filepath, strerror(errno));
        printf("fopen fail[%s:%s]\n", filepath, strerror(errno));
        return false;
    }

    //读取头部
    rlen = fread(&filehead, 1, sizeof(filehead), fp);
    if (rlen != sizeof(filehead)) {
        PRINT_ERR_HEAD
        print_err("fread filehead fail[%s:%s]", filepath, strerror(errno));
        printf("fread filehead fail[%s:%s]\n", filepath, strerror(errno));
        fclose(fp);
        return false;
    }

    //还原文件
    {
        fporg = fopen(orgpath, "wb");
        if (fporg == NULL) {
            PRINT_ERR_HEAD
            print_err("fopen fail[%s:%s]", orgpath, strerror(errno));
            printf("fopen fail[%s:%s]\n", orgpath, strerror(errno));
            fclose(fp);
            goto _err;
        }

        while (1) {
            if ((rlen = fread(readbuf, 1, sizeof(readbuf), fp)) <= 0) {
                if (feof(fp)) {
                    fclose(fp);
                    fclose(fporg);
                    break;
                } else {
                    PRINT_ERR_HEAD
                    print_err("fread fail[%s:%d:%s]", filepath, rlen, strerror(errno));
                    printf("fread fail[%s:%d:%s]\n", filepath, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fporg);
                    goto _err;
                }
            } else {
                wlen = fwrite(readbuf, 1, rlen, fporg);
                if (wlen != rlen) {
                    PRINT_ERR_HEAD
                    print_err("fwrite fail[%s:%d:%d:%s]", orgpath, wlen, rlen, strerror(errno));
                    printf("fwrite fail[%s:%d:%d:%s]\n", orgpath, wlen, rlen, strerror(errno));
                    fclose(fp);
                    fclose(fporg);
                    goto _err;
                }
                writebyte += wlen;
            }
        }
    }

    //校验
    if (writebyte != filehead.len) {
        PRINT_ERR_HEAD
        print_err("[%s]writebyte %u, filehead.len %u, something error!", orgpath, writebyte, filehead.len);
        printf("[%s]writebyte %u, filehead.len %u, something error!\n", orgpath, writebyte, filehead.len);
        goto _err;
    }
    if (strcmp(filehead.checkkey, FHEAD_CHECK_KEY) != 0) {
        PRINT_ERR_HEAD
        print_err("filehead checkkey error![%s]", orgpath);
        printf("filehead checkkey error![%s]\n", orgpath);
        goto _err;
    }

    return true;
_err:
    return false;
}

/**
 * [scandir_file 扫描临时目录处理每个扫描到的文件]
 * @param  fun [处理每个扫描到的文件的函数指针]
 * @return     [成功返回true]
 */
bool scandir_file(FILE_POLICY fun)
{
    int n = 0;
    struct dirent **namelist;
    char tmppasrpath[FILE_PATH_MAX_LEN] = {0};//要扫描这个目录下的文件
    char tmppath1[FILE_PATH_MAX_LEN] = {0};   //临时目录中的临时文件
    char tmppath2[FILE_PATH_MAX_LEN] = {0};   //临时目录中的临时文件
    FILE_HEAD filehead;
    bool bflag = true;

    sprintf(tmppasrpath, "%s%s", UPDATE_PASR_TMPDIR, FILES_PATH);

    n = scandir(tmppasrpath, &namelist, filter_fun, alphasort);
    if (n < 0) {
        printf("scandir fail[%s:%s]\n", tmppasrpath, strerror(errno));
        bflag = false;
    } else {
        printf("file num:%d\n", n);
        for (int i = 0; i < n; ++i) {
            snprintf(tmppath1, sizeof(tmppath1), "%s%s", tmppasrpath, namelist[i]->d_name);
            snprintf(tmppath2, sizeof(tmppath2), "%s.org", tmppath1);
            if (uppack_updatefile(tmppath1, tmppath2, filehead) //拆解校验一个文件
                && fun(tmppath2, filehead)) {                   //处理这个文件
                unlink(tmppath1);
            } else {
                bflag = false;
                break;
            }
        }

        for (int i = 0; i < n; ++i) {
            free(namelist[i]);
        }
        free(namelist);
    }
    return bflag;
}

/**
 * [update_mkdir 创建文件所经过的所有目录]
 * @param  filepath [文件路径]
 * @return          [成功返回true]
 */
bool update_mkdir(const char *filepath)
{
    int len = 0;
    char tmppath[FILE_PATH_MAX_LEN] = {0};

    if (filepath == NULL) {
        PRINT_ERR_HEAD
        print_err("update mkdir para null");
        printf("update mkdir para null\n");
        return false;
    }

    len = strlen(filepath);
    if (len > FILE_PATH_MAX_LEN) {
        PRINT_ERR_HEAD
        print_err("file path too long %d,max support %d", len, FILE_PATH_MAX_LEN);
        printf("file path too long %d,max support %d\n", len, FILE_PATH_MAX_LEN);
        return false;
    }

    //逐级创建目录
    for (int i = 0; i < len; i++) {
        if (filepath[i] != '/') {
            continue;
        }
        strncpy(tmppath, filepath, i + 1);
        if (mkdir(tmppath, S_IRWXO | S_IRWXG | S_IRWXU) != 0) {
            if (errno == EEXIST) {
                continue;
            } else {
                PRINT_ERR_HEAD
                print_err("create dir file[%s:%s]", tmppath, strerror(errno));
                printf("create dir file[%s:%s]\n", tmppath, strerror(errno));
                return  false;
            }
        }
    }
    return true;
}

/**
 * [restore_file 把文件还原到打包之前的多级目录的名称和状态]
 * @param  orgpath  [已经还原为完整升级内容的文件]
 * @param  filehead [文件头]
 * @return          [成功返回true]
 */
bool restore_file(const char *orgpath, FILE_HEAD &filehead)
{
    char rootpath[FILE_PATH_MAX_LEN] = {0};
    char dstpath[FILE_PATH_MAX_LEN] = {0};
    char chcmd[2 * FILE_PATH_MAX_LEN] = {0};

    switch (filehead.area) {
    case FILE_AREA_INNET:
        strcpy(rootpath, INROOT_PATH);
        break;
    case FILE_AREA_OUTNET:
        strcpy(rootpath, OUTROOT_PATH);
        break;
    case FILE_AREA_OS:
        strcpy(rootpath, "");
        break;
    case FILE_AREA_BOTH:
        strcpy(rootpath, BOTH_PATH);
        break;
    default:
        break;
    }

    snprintf(dstpath, sizeof(dstpath), "%s%s", rootpath, filehead.path);

    if (update_mkdir(dstpath)) {
        snprintf(chcmd, sizeof(chcmd), "mv -f '%s' '%s'", orgpath, dstpath);
        system(chcmd);
        PRINT_DBG_HEAD
        print_dbg("[AREA:%d PERM:%d NAME:%s]", filehead.area, filehead.permission, filehead.path);
        printf("[AREA:%d PERM:%d NAME:%s]\n", filehead.area, filehead.permission, filehead.path);
        return true;
    } else {
        return false;
    }
}

/**
 * [print_updatepack 打印升级包]
 * @param  filename [升级包名称]
 * @return          [成功返回true]
 */
bool print_updatepack(const char *filename)
{
    char chsysver[SYSVER_MAX_LEN + 1] = {0};
    TOTAL_HEAD totalhead;
    memset(&totalhead, 0, sizeof(totalhead));

    return (check_updatepack_suffix(filename)                   //扩展名检查
            && check_updatepack_size(filename, true)            //升级包大小检查
            && uppack_updatepack(filename, totalhead, chsysver) //拆解升级包
            && check_totalhead(totalhead)                       //检查升级包头部
            && print_totalhead(totalhead, chsysver)             //打印头部等相关信息
            && unpack_tmptar()                                  //解压临时tar文件到临时目录
            && scandir_file(restore_file));              //扫描临时目录处理每个扫描到的文件
}
