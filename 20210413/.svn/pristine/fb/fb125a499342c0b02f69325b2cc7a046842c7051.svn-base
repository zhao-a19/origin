/*******************************************************************************************
*文件: readcfg.h
*描述: 读配置文件使用的宏
*
*作者: 王君雷
*日期: 2018-04-12
*修改:
*******************************************************************************************/
#ifndef __READ_CFG_H__
#define __READ_CFG_H__

//flag为true表示 读取失败是严重错误 ，需要goto跳出
#define READ_STRING(fop, name1, name2, outval, flag, o) \
if (fop.ReadCfgFile((name1), (name2), (outval), sizeof(outval)) != E_FILE_OK) { \
PRINT_ERR_HEAD \
print_err("read [%s][%s] error", name1, name2); \
if (flag){goto o;}\
}

#define READ_INT(fop, name1, name2, outval, flag, o) \
if (fop.ReadCfgFileInt((name1), (name2), &(outval)) != E_FILE_OK) { \
PRINT_ERR_HEAD \
print_err("read [%s][%s] error", name1, name2); \
if (flag){goto o;}\
}

#endif
