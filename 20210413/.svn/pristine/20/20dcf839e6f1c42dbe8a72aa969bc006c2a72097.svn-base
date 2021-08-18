/*******************************************************************************************
*文件:    callclitool.cpp
*描述:    用来调用clitool测试  不是正式程序 不放在网闸上
*作者:    王君雷
*日期:    2016-04-19
*修改:
*******************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "FCKey.h"
#include "fileoperator.h"
#include "define.h"
#include "debugout.h"

loghandle glog_p = NULL;

int readlinklan(int* plinklan)
{
	CFILEOP  m_fileop;
	if (m_fileop.OpenFile(SYSINFO_CONF,"r") == E_FILE_FALSE)
	{
		return -1;
	}

	char tmp[100]={0};
	if (m_fileop.ReadCfgFile("SYSTEM","LinkLan",tmp,100) == E_FILE_FALSE)
	{
		strcpy(tmp,"");
		m_fileop.CloseFile();
		return -1;
	}
	*plinklan=atoi(tmp);
	m_fileop.CloseFile();
	return 0;
}

int main(int argc, char* argv[])
{
    _log_init_(glog_p, callclitool);
    char chout[33] = {0};
    char str[1024] = {0};

    int linklan = 0;
    if (readlinklan(&linklan) == 0)
    {
        //生成KEY对象
        KEY mykey(KEY_FILE, linklan);
        if (mykey.md5(time(NULL),chout))
        {
            sprintf(str,"/initrd/abin/clitool %s", chout);
            system(str);
            printf("调用clitool完成!\n");
            if (mykey.file_exist(KEY_FILE))
            {
                printf("创建key文件成功!\n");
            }
            else
            {
                printf("但创建key文件失败!\n");
            }
        }
        else
        {
            printf("调用clitool失败!\n");
        }
    }

    return 0;
}
