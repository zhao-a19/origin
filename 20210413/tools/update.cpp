/*******************************************************************************************
*文件:    update.cpp
*描述:    升级后台程序工具
*
*作者:    王君雷
*日期:
*修改:    V2 扩展功能可以升级内网的任意文件         ---->     2015-11-13
*         V3 扩展功能可以升级内外网任意文件         ---->     2015-12-15
*         V4 扩展功能可以升级授权证书文件           ---->     2016-04-25
*         V5 传输文件到外网非阻塞                   ---->     2017-08-16
*         V6 支持整体授权和模块授权文件的导入       ---->     2018-01-03
*         V7 使用zlog                               ---->     2018-04-10
*         V8 update添加防降版版本号；废除common,application目录更新
*            支持升级隐藏文件;全文件使用zlog;unix风格,utf8编码
*                                                   ---->     2018-06-14
*         V8.1 修改上个版本update_outnet_dir中引入的错误  ----> 2018-06-21
*         V8.2 不再支持通过该工具导入期限授权文件         ----> 2018-09-21
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "FCSendFileUdp.h"
#include "fileoperator.h"
#include "define.h"
#include "FCPeerExecuteCMD.h"
#include "FCLicenseMod.h"
#include "debugout.h"

#define UPDATE_TMPFILE      "/tmp/update.anmit_tmp"
#define UPDATE_TMPDIR       "/tmp/update.dir/"
#define UPDATE_CHECKMARK    "sugap"
#define CREATETIME          "2018-09-21"
#define UPDATE_VERSION      (0x20) //update自身的版本 只支持大于等于该值的升级包的导入
//#define SUPPORT_COMMONDIR_APPDIR
#define UPDATE_CMD_BUFF_LEN 512

int g_linklanipseg = 0;
int g_linklanport = 0;
loghandle glog_p = NULL;

int DelCheckMark(const char *file1, const char *file2);
int readlinkinfo(int *plinkseg, int *plinkport);
int update_outnet_dir(const char *sdir, const char *ddir);
int update_inroot();
int update_outroot();
int update_outroot2(const char *sdir, const char *ddir);

/**
 * [DelCheckMark 把file1的校验标志和防退版版本号去掉，剩余部分存到file2]
 * @param  file1 [源文件]
 * @param  file2 [待写入的文件]
 * @return       [成功返回0 失败返回负值]
 */
int DelCheckMark(const char *file1, const char *file2)
{
    int marklen = strlen(UPDATE_CHECKMARK);
    char buf[1024] = {0};
    int rlen = 0;
    int wlen = 0;
    FILE *fd1 = NULL;
    FILE *fd2 = NULL;

    fd1 = fopen(file1, "rb");
    if (fd1 == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen [%s] error[%s]", file1, strerror(errno));
        printf("fopen file[%s] error\n", file1);
        goto _out;
    }

    //读取校验标志
    rlen = fread(buf, 1, marklen + 1, fd1);
    if (rlen != marklen + 1) {
        PRINT_ERR_HEAD
        print_err("fread mark error[%s]", strerror(errno));
        printf("fread mark error\n");
        goto _out;
    }

    //检查校验标志
    if (memcmp(buf, UPDATE_CHECKMARK, marklen) != 0) {
        PRINT_ERR_HEAD
        print_err("check mark error");
        printf("check mark error\n");
        goto _out;
    }

    //检查是否退版了
    if (buf[marklen] < UPDATE_VERSION) {
        PRINT_ERR_HEAD
        print_err("version rollback is not allowed,packver[%u] updatever[%u]", buf[marklen], UPDATE_VERSION);
        printf("version rollback is not allowed\n");
        goto _out;
    }

    fd2 = fopen(file2, "wb");
    if (fd2 == NULL) {
        PRINT_ERR_HEAD
        print_err("fopen [%s] error[%s]", file2, strerror(errno));
        printf("fopen [%s] error\n", file2);
        goto _out;
    }

    //剩余内容写入file2
    while (!feof(fd1)) {
        rlen = fread(buf, 1, sizeof(buf), fd1);
        if (rlen <= 0) {
            break;
        }
        wlen = fwrite(buf, 1, rlen, fd2);
        if (wlen != rlen) {
            PRINT_ERR_HEAD
            print_err("fwrite[%s] error[%s],wlen[%d],rlen[%d]", file2, strerror(errno), wlen, rlen);
            printf("fwrite [%s] error\n", file2);
            goto _out;
        }
    }

    fflush(fd2);
    fclose(fd1);
    fclose(fd2);
    return 0;
_out:
    if (fd1 != NULL) {
        fclose(fd1);
        fd1 = NULL;
    }

    if (fd2 != NULL) {
        fclose(fd2);
        fd2 = NULL;
    }
    return -1;
}

/**
 * [readlinkinfo 读取内部连接信息]
 * @param  plinkseg  [内连网段]
 * @param  plinkport [内连端口]
 * @return           [成功返回0 失败返回负值]
 */
int readlinkinfo(int *plinkseg, int *plinkport)
{
    CFILEOP m_fileop;
    if (m_fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        return -1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanIPSeg", plinkseg);
    if (*plinkseg < 1 || *plinkseg > 255) {
        PRINT_ERR_HEAD
        print_err("LinkLanIPSeg[%d] error, use defult 1", *plinkseg);
        *plinkseg = 1;
    }

    m_fileop.ReadCfgFileInt("SYSTEM", "LinkLanPort", plinkport);
    if (*plinkport < 1 || *plinkport > 65535) {
        PRINT_ERR_HEAD
        print_err("LinkLanPort[%d] error, use defult %d", *plinkport, DEFAULT_LINK_PORT);
        *plinkport = DEFAULT_LINK_PORT;
    }

    m_fileop.CloseFile();
    return 0;
}

/**
 * [update_outnet_dir 更新外网指定目录]
 * @param  sdir [更新包中的目录名称]
 * @param  ddir [对应的外网的目录]
 * @return      [成功返回0 失败返回负值]
 */
int update_outnet_dir(const char *sdir, const char *ddir)
{
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char chcmd[UPDATE_CMD_BUFF_LEN] = {0};
    char tmp_path_info[MAX_FILE_PATH_LEN] = {0};
    char srcfile[MAX_FILE_PATH_LEN] = {0};
    char dstfile[MAX_FILE_PATH_LEN] = {0};

    sprintf(tmp_path_info, "%s%s", UPDATE_TMPDIR, sdir);

    if ((dirptr = opendir(tmp_path_info)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", tmp_path_info, strerror(errno));
        printf("opendir[%s] error\n", tmp_path_info);
        return -1;
    }

    //扫描临时目录
    while (entry = readdir(dirptr)) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcfile, sizeof(srcfile), "%s%s", tmp_path_info, entry->d_name);
        snprintf(dstfile, sizeof(dstfile), "%s%s", ddir, entry->d_name);
        if (lstat(srcfile, &statbuf) < 0) {
            PRINT_ERR_HEAD
            print_err("lstat[%s] error[%s]", srcfile, strerror(errno));
            printf("lstat[%s] error\n", srcfile);
            closedir(dirptr);
            return -1;
        }

        if (S_ISREG(statbuf.st_mode)) {
            //发送到外网
            if (send_file_udp(srcfile, dstfile, 10) < 0) {
                closedir(dirptr);
                return -1;
            }
            sprintf(chcmd, "chmod +x %s", dstfile);
            PeerExecuteCMD(chcmd);
        }
    }

    closedir(dirptr);
    return 0;
}

int update_inroot()
{
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char chcmd[UPDATE_CMD_BUFF_LEN] = {0};
    char tmp_path_info[MAX_FILE_PATH_LEN] = {0};
    char srcfile[MAX_FILE_PATH_LEN] = {0};
    char dstfile[MAX_FILE_PATH_LEN] = {0};

    sprintf(tmp_path_info, "%sinroot/", UPDATE_TMPDIR);
    if ((dirptr = opendir(tmp_path_info)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", tmp_path_info, strerror(errno));
        printf("opendir[%s] error\n", tmp_path_info);
        return -1;
    }

    while (entry = readdir(dirptr)) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcfile, sizeof(srcfile), "%s%s", tmp_path_info, entry->d_name);
        snprintf(dstfile, sizeof(dstfile), "/%s", entry->d_name);
        if (lstat(srcfile, &statbuf) < 0) {
            PRINT_ERR_HEAD
            print_err("lstat[%s] error[%s]", srcfile, strerror(errno));
            printf("lstat[%s] error\n", srcfile);
            closedir(dirptr);
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            sprintf(chcmd, "cp -rf %s/* %s", srcfile, dstfile);
            system(chcmd);
        }
    }

    closedir(dirptr);
    return 0;
}

int update_outroot()
{
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char tmp_path_info[MAX_FILE_PATH_LEN] = {0};
    char srcfile[MAX_FILE_PATH_LEN] = {0};
    char dstfile[MAX_FILE_PATH_LEN] = {0};

    sprintf(tmp_path_info, "%soutroot/", UPDATE_TMPDIR);
    if ((dirptr = opendir(tmp_path_info)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", tmp_path_info, strerror(errno));
        printf("opendir[%s] error\n", tmp_path_info);
        return -1;
    }

    while (entry = readdir(dirptr)) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcfile, sizeof(srcfile), "%soutroot/%s", UPDATE_TMPDIR, entry->d_name);
        snprintf(dstfile, sizeof(dstfile), "/%s", entry->d_name);
        if (lstat(srcfile, &statbuf) < 0) {
            PRINT_ERR_HEAD
            print_err("lstat[%s] error[%s]", srcfile, strerror(errno));
            printf("lstat[%s] error\n", srcfile);
            closedir(dirptr);
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (update_outroot2(srcfile, dstfile) < 0) {
                closedir(dirptr);
                return -1;
            }
        }
    }

    closedir(dirptr);
    return 0;
}

/**
 * [update_outroot2 递归升级外网文件]
 * @param  sdir [本地目录]
 * @param  ddir [对端目录]
 * @return      [成功返回0 失败返回负值]
 */
int update_outroot2(const char *sdir, const char *ddir)
{
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char srcfile[MAX_FILE_PATH_LEN] = {0};
    char dstfile[MAX_FILE_PATH_LEN] = {0};

    if ((dirptr = opendir(sdir)) == NULL) {
        PRINT_ERR_HEAD
        print_err("opendir[%s] error[%s]", sdir, strerror(errno));
        printf("opendir[%s] error\n", sdir);
        return -1;
    }

    while (entry = readdir(dirptr)) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(srcfile, sizeof(srcfile), "%s/%s", sdir, entry->d_name);
        snprintf(dstfile, sizeof(dstfile), "%s/%s", ddir, entry->d_name);
        if (lstat(srcfile, &statbuf) < 0) {
            PRINT_ERR_HEAD
            print_err("lstat[%s] error[%s]", srcfile, strerror(errno));
            printf("lstat[%s] error\n", srcfile);
            closedir(dirptr);
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            //递归
            if (update_outroot2(srcfile, dstfile) < 0) {
                closedir(dirptr);
                return -1;
            }
        }

        if (S_ISREG(statbuf.st_mode)) {
            //发送到外网
            if (send_file_udp(srcfile, dstfile, 10) < 0) {
                closedir(dirptr);
                return -1;
            }
            //加可执行权限
            //char chcmd[UPDATE_CMD_BUFF_LEN]={0};
            //sprintf(chcmd,"chmod +x %s",dstfile);
            //PeerExecuteCMD(chcmd);
        }
    }

    closedir(dirptr);
    return 0;
}

/**
 * [read_CSLan 读取管理口]
 * @param  ethno [网卡编号，出参]
 * @return       [成功返回0 失败返回负值]
 */
int read_CSLan(int &ethno)
{
    CFILEOP fileop;
    if (fileop.OpenFile(SYSINFO_CONF, "r") == E_FILE_FALSE) {
        PRINT_ERR_HEAD
        print_err("openfile[%s] error", SYSINFO_CONF);
        printf("openfile[%s] error\n", SYSINFO_CONF);
        return -1;
    }

    if (fileop.ReadCfgFileInt("SYSTEM", "CSLan", &ethno) != E_FILE_OK) {
        PRINT_ERR_HEAD
        print_err("read CSLan error");
        printf("read CSLan error\n");
        fileop.CloseFile();
        return -1;
    }

    fileop.CloseFile();
    return 0;
}

/**
 * [do_modcer 处理模块授权]
 * @param  srcfile [授权文件]
 * @return         [成功返回0 失败返回负值]
 */
int do_modcer(const char *srcfile)
{
    char chcmd[UPDATE_CMD_BUFF_LEN] = {0};

    //读取cslan
    int ethno = 0;
    if (read_CSLan(ethno) < 0) {
        return -1;
    }

    CLicenseMod lmod(ethno);
    if (lmod.readfile(srcfile)) {
        sprintf(chcmd, "cp -f %s %s", srcfile, MOD_LICENSE_FILE);
        system(chcmd);
        system("sync");
    } else {
        //读取失败 则可能是校验失败
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    DIR *dirptr = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    char chcmd[UPDATE_CMD_BUFF_LEN] = {0};
    char full_filename[MAX_FILE_PATH_LEN] = {0};//绝对路径的文件名
    bool indir = false;
    bool inshelldir = false;
    bool outdir = false;
    bool outshelldir = false;
    bool comdir = false;
    bool appdir = false;
    bool inrootdir = false;
    bool outrootdir = false;
    bool b_dirempty = true;//如果升级包解压之后目录为空 则提示出错

    _log_init_(glog_p, update);

    //参数个数检查
    if (argc < 2) {
        printf("Usage(%s):\n\n\t%s filename(绝对路径) [cer]\n\n", CREATETIME, argv[0], argv[0]);
        return -1;
    }

    //检查是不是绝对路径的
    if (argv[1][0] != '/') {
        PRINT_ERR_HEAD
        print_err("updatepkt should be absolute filename[%s]", argv[1]);
        printf("updatepkt should be absolute filename\n");
        return -1;
    }

    //WEB中的授权管理 使用这种调用方法
    if ((argc == 3) && (strcmp(argv[2], "cer") == 0)) {
        if (strstr(argv[1], ".modcer") != NULL) {
            if (do_modcer(argv[1]) < 0) {
                goto _out;
            }
        } else {
            PRINT_ERR_HEAD
            print_err("file name extension should be modcer[%s]", argv[1]);
            printf("file name extension should be modcer\n");
            goto _out;
        }
    } else {
        //读取IP等信息
        if (readlinkinfo(&g_linklanipseg, &g_linklanport) < 0) {
            PRINT_ERR_HEAD
            print_err("readlinkinfo error");
            printf("readlinkinfo error\n");
            goto _out;
        }

        //升级包名称检查
        if (strstr(argv[1], ".upk") == NULL) {
            PRINT_ERR_HEAD
            print_err("file name extension should be upk[%s]", argv[1]);
            printf("file name extension should be upk\n");
            goto _out;
        }

        //删除校验标志 和 防退版版本号
        if (DelCheckMark(argv[1], UPDATE_TMPFILE) < 0) {
            unlink(UPDATE_TMPFILE);
            goto _out;
        }

        //创建临时目录
        sprintf(chcmd, "mkdir -p %s", UPDATE_TMPDIR);
        system(chcmd);

        //清空临时目录
        sprintf(chcmd, "rm -rf %s*", UPDATE_TMPDIR);
        system(chcmd);

        //解压临时文件到临时目录
        sprintf(chcmd, "tar -xzf %s -C %s", UPDATE_TMPFILE, UPDATE_TMPDIR);
        system(chcmd);

        //删除临时文件
        unlink(UPDATE_TMPFILE);

        //打开临时目录
        if ((dirptr = opendir(UPDATE_TMPDIR)) == NULL) {
            PRINT_ERR_HEAD
            print_err("open dir[%s] error,[%s]", UPDATE_TMPDIR, strerror(errno));
            printf("open dir[%s] error\n", UPDATE_TMPDIR);
            goto _out;
        }

        //扫描临时目录 看里面包含哪些文件夹
        while (entry = readdir(dirptr)) {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }

            b_dirempty = false;
            snprintf(full_filename, sizeof(full_filename), "%s%s", UPDATE_TMPDIR, entry->d_name);
            if (lstat(full_filename, &statbuf) < 0) {
                PRINT_ERR_HEAD
                print_err("lstat[%s] error[%s]", full_filename, strerror(errno));
                printf("lstat[%s] error\n", full_filename);
                goto _out;
            }

            if (S_ISDIR(statbuf.st_mode)) {
                if (strcmp(entry->d_name, "in") == 0) {
                    indir = true;
                } else if (strcmp(entry->d_name, "inshell") == 0) {
                    inshelldir = true;
                } else if (strcmp(entry->d_name, "out") == 0) {
                    outdir = true;
                } else if (strcmp(entry->d_name, "outshell") == 0) {
                    outshelldir = true;
                } else if (strcmp(entry->d_name, "common") == 0) {
                    comdir = true;
                } else if (strcmp(entry->d_name, "application") == 0) {
                    appdir = true;
                } else if (strcmp(entry->d_name, "inroot") == 0) {
                    inrootdir = true;
                } else if (strcmp(entry->d_name, "outroot") == 0) {
                    outrootdir = true;
                }
            }
        }

        closedir(dirptr);
        dirptr = NULL;

        if (b_dirempty) {
            printf("packet is empty\n");
            goto _out;
        }

        //升级外网
        if (outrootdir && (update_outroot() < 0)) {
            goto _out;
        }
        if (outdir && (update_outnet_dir("out/", "/initrd/abin/") < 0)) {
            goto _out;
        }
        if (outshelldir && (update_outnet_dir("outshell/", "/etc/init.d/") < 0)) {
            goto _out;
        }

        //升级内网
        if (inrootdir && (update_inroot() < 0)) {
            goto _out;
        }

        if (indir) {
            sprintf(chcmd, "chmod +x %sin/*", UPDATE_TMPDIR);
            system(chcmd);
            sprintf(chcmd, "mv -f %sin/* /initrd/abin/", UPDATE_TMPDIR);
            system(chcmd);
        }

        if (inshelldir) {
            sprintf(chcmd, "chmod +x %sinshell/*", UPDATE_TMPDIR);
            system(chcmd);
            sprintf(chcmd, "mv -f %sinshell/* /etc/init.d/", UPDATE_TMPDIR);
            system(chcmd);
        }

#ifdef SUPPORT_COMMONDIR_APPDIR
        if (comdir) {
            sprintf(chcmd, "cp -rf %scommon/* /var/www/common/", UPDATE_TMPDIR);
            system(chcmd);
        }

        if (appdir) {
            sprintf(chcmd, "cp -rf %sapplication/* /var/www/application/", UPDATE_TMPDIR);
            system(chcmd);
        }
#endif

        //清空临时目录
        sprintf(chcmd, "rm -rf %s*", UPDATE_TMPDIR);
        system(chcmd);
    }

    unlink(argv[1]);
    system("sync");
    system("/etc/init.d/start >/dev/null");
    printf("success\n");
    return 0;

_out:
    unlink(argv[1]);
    if (dirptr != NULL) {
        closedir(dirptr);
        dirptr = NULL;
    }
    return -1;
}
