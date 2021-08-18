/*******************************************************************************************
*文件:  update_marktool.cpp
*描述:  添加更新包校验标志;去除更新包校验标志工具
*作者:  王君雷
*日期:  2015-06-05
*用法：
*             ./update_marktool -add file
*             ./update_marktool -del file
*更新包格式:  sugap(5B) + data
*修改:
*
*      2) 用法修改为：
*             ./update_marktool -add file softver
*             ./update_marktool -del file
*             更新包格式为：
*             0000000001(10B软件版本号) + sugap(5B) + data
*
*       softver 长度1到10个字节，不够10自动前面补0
*       softver 为0时，按原来的协议处理，即sugap(5B) + data           ------> 2016-06-07
*
*      3) 用法修改为：
*             ./update_marktool -add file softver upver
*             ./update_marktool -del file
*             更新包格式为：
*             0000000001(10B软件版本号) + sugap(5B) + upver(1B) + data
*       upver 是1到255范围的整数，当输入0时，忽略该字段，是为了兼容制作符合
*             方法二的升级包
*                                                                     ------> 2018-06-15
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define UPDATE_CHECKMARK    "sugap"
#define UPDATE_TMPFILE      "/tmp/update.marktool_tmp"
#define SOFT_VER_BYTES      10
#define CREATE_TIME         "2018-06-15"
#define TAR_FLAG  0x1F      //tar包第一个字节的值

/**
 * [AddCheckMark 为更新包添加校验标志等信息]
 * @param  file    [文件名称]
 * @param  softver [软件版本号]
 * @param  upver   [update的版本号 用于防退版]
 * @return         [成功返回0 失败返回负值]
 */
int AddCheckMark(const char *file, const char *softver, const char *upver)
{
    int marklen = strlen(UPDATE_CHECKMARK);
    char buf[1024] = {0};
    int rlen = 0;
    int wlen = 0;
    bool use_softver = true;
    unsigned char chupver = 0;
    char ch_softver[SOFT_VER_BYTES] = {0};

    if ((file == NULL) || (softver == NULL) || (strlen(softver) > 10) || (upver == NULL)) {
        printf("AddCheckMark para error!\n");
        return -1;
    }

    //防退版版本号 不允许是0x1F
    chupver = atoi(upver);
    if (chupver == TAR_FLAG) {
        printf("AddCheckMark upver[%d] error!\n", upver);
        return -1;
    }

    //如果已经添加过就不加了
    FILE *fd1 = fopen(file, "rb");
    if (fd1 == NULL) {
        perror("file fopen");
        return -1;
    }

    rlen = fread(buf, 1, marklen + SOFT_VER_BYTES, fd1);
    if (rlen < 0) {
        perror("AddCheckMark fread mark");
        fclose(fd1);
        return -1;
    }

    //检查校验标志
    if ((memcmp(buf, UPDATE_CHECKMARK, marklen) == 0)
        || (memcmp(buf + SOFT_VER_BYTES, UPDATE_CHECKMARK, marklen) == 0)) {
        printf("AddCheckMark repeat!\n");
        fclose(fd1);
        return -1;
    }

    //准备好软件版本字符串
    if (strcmp(softver, "0") == 0) {
        //参数为0的时候 更新包不加软件版本信息
        use_softver = false;
    } else {
        int paralen = strlen(softver);
        int fill = SOFT_VER_BYTES - paralen;//需要程序补充的字节数
        memset(ch_softver, '0', sizeof(ch_softver));
        memcpy(ch_softver + fill, softver, paralen);
    }

    //文件读取指针重置
    fseek(fd1, 0, SEEK_SET);

    //打开文件 UPDATE_TMPFILE
    FILE *fd2 = fopen(UPDATE_TMPFILE, "wb");
    if (fd2 == NULL) {
        perror("filetmp fopen");
        fclose(fd1);
        return -1;
    }

    if (use_softver) {
        //写软件版本字符串
        wlen = fwrite(ch_softver, 1, SOFT_VER_BYTES, fd2);
        if (wlen != SOFT_VER_BYTES) {
            perror("fwrite");
            fclose(fd1);
            fclose(fd2);
            unlink(UPDATE_TMPFILE);
            return -1;
        }
    }

    //写校验标志
    wlen = fwrite(UPDATE_CHECKMARK, 1, marklen, fd2);
    if (wlen != marklen) {
        perror("fwrite");
        fclose(fd1);
        fclose(fd2);
        unlink(UPDATE_TMPFILE);
        return -1;
    }

    //写防降版版本号upver 为0时不加该标志
    if (chupver != 0) {
        fwrite(&chupver, 1, 1, fd2);
    }

    while (!feof(fd1)) {
        memset(buf, 0, sizeof(buf));
        rlen = fread(buf, 1, sizeof(buf), fd1);
        if (rlen <= 0) {
            break;
        }
        wlen = fwrite(buf, 1, rlen, fd2);
        if (wlen != rlen) {
            perror("fwrite");
            fclose(fd1);
            fclose(fd2);
            unlink(UPDATE_TMPFILE);
            return -1;
        }
    }

    //fflush保存
    fflush(fd2);

    //关闭两个文件
    fclose(fd1);
    fclose(fd2);

    //重命名覆盖
    char chcmd[128] = {0};
    sprintf(chcmd, "mv -f %s %s", UPDATE_TMPFILE, file);
    system(chcmd);
    return 0;
}

/**
 * [DelCheckMark 删除校验标志等信息]
 * @param  file [文件名称]
 * @return      [成功返回0 失败返回负值]
 */
int DelCheckMark(const char *file)
{
    int mark_len = strlen(UPDATE_CHECKMARK);
    char buf[1024] = {0};
    int rlen = 0;
    int wlen = 0;

    FILE *fd1 = fopen(file, "rb");
    if (fd1 == NULL) {
        perror("file fopen");
        return -1;
    }

    //读取校验标志
    rlen = fread(buf, 1, mark_len, fd1);
    if (rlen != mark_len) {
        perror("fread mark");
        fclose(fd1);
        return -1;
    }

    //检查校验标志
    if (memcmp(buf, UPDATE_CHECKMARK, mark_len) != 0) {
        //文件读取指针重置
        fseek(fd1, 0, SEEK_SET);
        memset(buf, 0, sizeof(buf));
        rlen = fread(buf, 1, SOFT_VER_BYTES + mark_len + 1, fd1);
        if (rlen != SOFT_VER_BYTES + mark_len + 1) {
            perror("fread mark2");
            fclose(fd1);
            return -1;
        }

        if (memcmp(buf + SOFT_VER_BYTES, UPDATE_CHECKMARK, mark_len) != 0) {
            printf("checkmark error\n");
            fclose(fd1);
            return -1;
        }

        //所操作的文件 是不带upver字段的
        if (buf[SOFT_VER_BYTES + mark_len] == TAR_FLAG) {
            fseek(fd1, -1, SEEK_CUR);
        }
    }

    //打开文件 UPDATE_TMPFILE
    FILE *fd2 = fopen(UPDATE_TMPFILE, "wb");
    if (fd2 == NULL) {
        perror("filetmp fopen");
        fclose(fd1);
        return -1;
    }

    //剩余内容写入file2
    while (!feof(fd1)) {
        memset(buf, 0, sizeof(buf));
        rlen = fread(buf, 1, sizeof(buf), fd1);
        if (rlen <= 0) {
            break;
        }
        wlen = fwrite(buf, 1, rlen, fd2);
        if (wlen != rlen) {
            fclose(fd1);
            fclose(fd2);

            perror("fwrite");
            return -1;
        }
    }

    //fflush保存
    fflush(fd2);

    //关闭两个文件
    fclose(fd1);
    fclose(fd2);

    //重命名覆盖
    char chcmd[128] = "";
    sprintf(chcmd, "mv -f %s %s", UPDATE_TMPFILE, file);
    system(chcmd);
    return 0;
}

void Usage(char *argv[])
{
    printf("\nUsage(%s):\n\t%s -add file softver upver\n\t%s -del file\n\n", CREATE_TIME, argv[0], argv[0]);
    printf("softver: Up to 10 bytes string. This field is ignored in the upgrade package if the input is 0\n");
    printf("upver  : 1 to 255 integer. This field is ignored in the upgrade package if the input is 0\n\n");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        Usage(argv);
        return -1;
    }

    int retcode = 0;

    if ((strcmp(argv[1], "-add") == 0) && (argc == 5)) {
        if (AddCheckMark(argv[2], argv[3], argv[4]) < 0) {
            printf("AddCheckMark fail!\n");
            retcode = -1;
        } else {
            printf("AddCheckMark ok!\n");
        }
    } else if ((strcmp(argv[1], "-del") == 0) && (argc == 3)) {
        if (DelCheckMark(argv[2]) < 0) {
            printf("DelCheckMark fail!\n");
            retcode = -1;
        } else {
            printf("DelCheckMark ok!\n");
        }
    } else {
        Usage(argv);
        retcode = -1;
    }

    return retcode;
}

