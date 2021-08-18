/*******************************************************************************************
*文件:    libftp.cpp
*描述:    FTP协议API继承原有接口，但内部实现更新为ftplib4.0
*
*作者:    张冬波
*日期:    2016-07-22
*修改:    修改文件接口实现                            ------>     2016-07-22
*         添加rename接口  //zkp                       ------>     2017-06-16
*
*******************************************************************************************/
#include "libftp.h"
#include "debugout.h"

#define CONNECT_TIMEOUT (5*60*1000)
#define RET_ERROR (-1)
#define RET_OK    (1)
#define _libhandle(f) ((f)->handle)
#define _check_(f) if((f) == NULL) {PRINT_ERR_HEAD; print_err("ftblib handle NULL"); return RET_ERROR;}
#define _return_(r) if(r == 0) r = RET_ERROR; else r = RET_OK; return r;

/**
 * [_libcallback_ 库回调函数，通过FtpSetCallback设置]
 * @param  nControl [description]
 * @param  xfered   [description]
 * @param  arg      [description]
 * @return          [description]
 */
static int _libcallback_(netbuf *nControl, fsz_t xfered, void *arg)
{
    PRINT_DBG_HEAD;
    print_dbg("ftplib xfered or user %lu --- %p", xfered, arg);

    //资源无效
    if (nControl == NULL) return 0;

    //超时退出
    if ((ptr_t)arg == CONNECT_TIMEOUT) {
        return 0;
    }

    //默认
    return 1;
}

int ftp_getfile __P((FTPINFO *ftp_info, __CONST char *rem_path,
                     __CONST char *local_path))
{
    _check_(ftp_info);
    int ret = FtpGet(local_path, rem_path, FTPLIB_BINARY, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s[%s], ret = %d", local_path, rem_path, ret);

    _return_(ret);
}

int ftp_putfile __P((FTPINFO *ftp_info, __CONST char *rem_path,
                     __CONST char *local_path))
{
    _check_(ftp_info);
    int ret = FtpPut(local_path, rem_path, FTPLIB_BINARY, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s[%s], ret = %d", local_path, rem_path, ret);

    _return_(ret);
}

int ftp_dir __P((FTPINFO *ftp_info, __CONST char *rem_path,
                 __CONST char *local_path))
{
    _check_(ftp_info);
    int ret = FtpDir(local_path, rem_path, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s[%s], ret = %d", local_path, rem_path, ret);

    _return_(ret);

}

int ftp_site __P((FTPINFO *ftp_info, __CONST char *cmd))
{
    _check_(ftp_info);
    int ret = FtpSite(cmd, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", cmd, ret);

    _return_(ret);
}

int ftp_mkdir __P((FTPINFO *ftp_info, __CONST char *path))
{
    _check_(ftp_info);
    int ret = FtpMkdir(path, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", path, ret);

    _return_(ret);
}

int ftp_settype __P((FTPINFO *ftp_info, int type))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib = %d NULL", type);

    return RET_OK;
}

int ftp_rmdir __P((FTPINFO *ftp_info, __CONST char *path))
{
    _check_(ftp_info);
    int ret = FtpRmdir(path, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", path, ret);

    _return_(ret);
}

int ftp_pwd __P((FTPINFO *ftp_info))
{
    _check_(ftp_info);
    char tmp[1024];     //与ftplib.c RESPONSE_BUFSIZ同步
    int ret = FtpPwd(tmp, sizeof(tmp) - 1, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", tmp, ret);

    _return_(ret);
}

int ftp_del __P((FTPINFO *ftp_info, __CONST char *file))
{
    _check_(ftp_info);
    int ret = FtpDelete(file, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", file, ret);

    _return_(ret);
}

//添加rename接口
int ftp_rename __P((FTPINFO *ftp_info, __CONST char *srcfile, __CONST char *dstfile))
{
    _check_(ftp_info);
    int ret = FtpRename(srcfile, dstfile, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", srcfile, ret);

    _return_(ret);
}

//添加ftpdate接口
int ftp_moddate __P((FTPINFO *ftp_info, __CONST char *path, char *lasttime))
{
    _check_(ftp_info);
    char timebuf[20] = {0};
    int w, e, r, t, u, q;
    int ret = FtpModDate(path, timebuf, sizeof(timebuf), _libhandle(ftp_info));

    if (sscanf(timebuf, "%4d%2d%2d%2d%2d%2d", &w, &e, &r, &t, &u, &q) <= 0) {
        PRINT_ERR_HEAD;
        print_err("ftplib last time failed time= %s!", timebuf);
    }

    sprintf(lasttime, "%d-%02d-%02d %02d:%02d:%02d", w, e, r, t, u, q);

    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d, lasttime = %s", path, ret, lasttime);

    _return_(ret);
}

int ftp_chdir __P((FTPINFO *ftp_info, __CONST char *rempath))
{
    _check_(ftp_info);
    int ret = FtpChdir(rempath, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", rempath, ret);

    _return_(ret);
}

int ftp_ascii __P((FTPINFO *ftp_info))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_binary __P((FTPINFO *ftp_info))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_bye __P((FTPINFO *ftp_info))
{
    _check_(ftp_info);
    FtpQuit(_libhandle(ftp_info));
    _libhandle(ftp_info) = NULL;
    PRINT_DBG_HEAD;
    print_dbg("ftplib ret = %d", RET_OK);

    return RET_OK;
}

int ftp_accnt __P((FTPINFO *ftp_info, __CONST char *account))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_login __P((FTPINFO *ftp_info, __CONST char *remhost,
                   __CONST char *user, __CONST char *passwd, __CONST char *account))
{
    _check_(ftp_info);
    int ret = ftp_prconnect(ftp_info, remhost);
    if (ret == RET_OK) {

        //必须设置回调处理（超时）
        FtpCallbackOptions callback_init = {_libcallback_, (void *)CONNECT_TIMEOUT, 0, CONNECT_TIMEOUT};
        if (FtpSetCallback(&callback_init, _libhandle(ftp_info)) == 0) {
            PRINT_ERR_HEAD;
            print_err("ftplib FtpSetCallback");
        }

        ret = FtpLogin(user, passwd, _libhandle(ftp_info));
        if (ret == 0) {
            FtpQuit(_libhandle(ftp_info));
            _libhandle(ftp_info) = NULL;
        }
        PRINT_DBG_HEAD;
        print_dbg("ftplib %s[%s], ret = %d", user, passwd, ret);

        _return_(ret);
    }

    return ret;
}

int ftp_passwd __P((FTPINFO *ftp_info, __CONST char *passwd))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_user __P((FTPINFO *ftp_info, __CONST char *user))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_command __P((FTPINFO *ftp_info, __CONST char *opt_info,
                     __CONST char *action))
{
    _check_(ftp_info);
    PRINT_DBG_HEAD;
    print_dbg("ftblib NULL");

    return RET_OK;
}

int ftp_prconnect __P((FTPINFO *ftp_info, __CONST char *host))
{
    _check_(ftp_info);
    char ipport[128];

    int ret;

    //simple test ipv6
    if (strchr(host, ':') != NULL) {
        sprintf(ipport, "[%s]:%u", host, ftp_info->ftp_port);
        ret = FtpConnect6(ipport, &_libhandle(ftp_info));
    } else {
        sprintf(ipport, "%s:%u", host, ftp_info->ftp_port);
        ret = FtpConnect(ipport, &_libhandle(ftp_info));
    }

    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", ipport, ret);

    _return_(ret);
}

int ftp_setport __P((FTPINFO *ftp_info, in_port_t port))
{
    _check_(ftp_info);
    struct servent *se;

    if (port == 0) {
        if ((se = getservbyname("ftp", "tcp")) == NULL) {
            perror("getservbyname");
            return RET_ERROR;
        }

        ftp_info->ftp_port = htons(se->s_port);
    } else
        ftp_info->ftp_port = port;

    return RET_OK;
}

int ftp_init __P((FTPINFO *ftp_info, int onoff))
{
    _check_(ftp_info);
    memset(ftp_info, 0, sizeof(FTPINFO));
    ftplib_debug = onoff;   //库调试信息, 0关闭，1错误，2Response，3Sendcmd

    return RET_OK;
}

char *ftp_getmsg __P((FTPINFO *ftp_info))
{
    if (ftp_info == NULL)    return NULL;

    return FtpLastResponse(_libhandle(ftp_info));
}

int ftp_opts __P((FTPINFO *ftp_info, __CONST char *opts))
{
    _check_(ftp_info);
    int ret = FtpOpts(opts, _libhandle(ftp_info));
    PRINT_DBG_HEAD;
    print_dbg("ftplib %s, ret = %d", opts, ret);

    _return_(ret);
}
