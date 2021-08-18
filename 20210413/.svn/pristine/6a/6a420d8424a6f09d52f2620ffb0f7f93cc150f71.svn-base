/*
*logger.sh调用转码程序
* @Author: 赵子昂
* @Date:   2020-11-17 09:47:38
* @Last Modified by:   Lenovo
* @Last Modified time: 2021-04-01 16:42:59
*                      不再依赖文件，直接使用标准输出    ------> 20210628 wjl
*/

#include "debugout.h"
#include "stringex.h"

#define SYSLOG "/tmp/syslog.info"

loghandle glog_p = NULL;

static void print_usage(void)
{
    printf("\n************************* -- SYSLOG_TOOL -- **********************************\n\n");
    printf("build time: %s %s\n", __DATE__, __TIME__);
    printf("usage:\n");
    printf("\t(1)./syslog_tool msg gbk(syslog charset) filepath\n");
    printf("\t(2)./syslog_tool msg utf-8(syslog charset) filepath\n");
    printf("\n******************************************************************************\n\n");
}

int main(int argc, char const *argv[])
{
    _log_init_(glog_p, syslog_tool);
    if (argc != 4) {
        print_usage();
        return -1;
    }

    char msg[2048] = {0};
    char _msg[2048] = {0};
    char filepath[256] = {0};
    strcpy(msg, argv[1]);
    strcpy(filepath, argv[3]);
    if (strcmp(argv[2], "gbk") == 0) {
        PRINT_DBG_HEAD;
        print_dbg("syslog server charset gbk!");
        if ((get_sucharset(msg) == CHARSET_UTF8)) {
            PRINT_DBG_HEAD;
            print_dbg("tool msg charset utf-8 to gbk!");
            strconv("UTF-8", msg, SU_SYSCHARGBK, _msg);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("tool msg charset not utf-8 (may be gbk)");
            strcpy(_msg, msg);
        }
    } else if (strcmp(argv[2], "utf-8") == 0) {
        PRINT_DBG_HEAD;
        print_dbg("syslog server charset utf-8!");
        if ((get_sucharset(msg) == CHARSET_GBK)) {
            PRINT_DBG_HEAD;
            print_dbg("tool msg charset gbk to utf-8!");
            strconv(SU_SYSCHARGBK, msg, "UTF-8", _msg);
        } else {
            PRINT_DBG_HEAD;
            print_dbg("tool msg charset not gbk (may be utf-8)");
            strcpy(_msg, msg);
        }
    } else {
        PRINT_ERR_HEAD;
        print_err("ERROR: not gbk or utf-8; charset %s!", argv[2]);
        strcpy(_msg, msg);
    }

#if 0
    char *p = _msg;     //打印msg的16进制
    char info[2048] = {0};
    char tmp[2048] = {0};
    for (; *p++;) {
        sprintf(tmp, "0x%02x ", *p);
        strcat(info, tmp);
    }
    PRINT_INFO_HEAD;
    print_info("[info] msg 16 [%s]", info);
#endif

#if 0
    FILE *fp = fopen(filepath, "w+");
    fwrite(_msg, strlen(_msg), 1, fp);
    fclose(fp);
    fp = NULL;

    PRINT_DBG_HEAD;
    print_dbg("syslog charset %s exit!  %s  -->  %s", argv[2], msg, _msg);
#else
    printf("%s", _msg);
    fflush(stdout);

    PRINT_DBG_HEAD;
    print_dbg("syslog charset %s exit!  [%s]  -->  [%s]", argv[2], msg, _msg);
#endif
    _log_finish_(glog_p);
    return 0;
}