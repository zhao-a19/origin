/*******************************************************************************************  
*文件:    lib_memory_one_time.c                                                                            
*描述:    一次性内存管理函数                                                                         
*         此模块重复使用一个大的内存空间供模块解析报文使用，每次申请时都是递增使用内存，无需释放内存.
*         但需要在解析报文前进行初始化，以便恢复指针，另外不支持多线程使用
*作者:    于明明                                                                              
*日期:    2017-01-05                                                                          
*修改:      创建文件                            ------>     2017-01-05
*                                                                                             
*******************************************************************************************/  

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lib_memory.h"

static int memory_used = 0;
static uint32_t _M[LIB_MEMORY_ONE_TIME_SIZE/sizeof(uint32_t)]; //保证地址对齐
static uint8_t *m = (uint8_t *)_M;

void Memory_reset(void)
{
	memory_used = 0;
	//memset(m, 0, LIB_MEMORY_ONE_TIME_SIZE);
}

void *Memory_malloc(size_t size)
{
	size = 4 + (size +3)/4*4;
	if (memory_used + size > LIB_MEMORY_ONE_TIME_SIZE) {
		return NULL;
	}
	uint32_t *p = (uint32_t *)(m + memory_used);
	*p = size;
	memory_used += size;
    return (void *)(p+1);
}

void *Memory_calloc(size_t nmemb, size_t size)
{
    uint8_t *p = Memory_malloc(nmemb * size);
	memset(p, 0, nmemb * size);
	return p;
}

void *Memory_realloc(void *ptr, size_t size)
{
	uint8_t *p = Memory_malloc(size);
	if (p == NULL)
    	return NULL;
	if (ptr == NULL)
		return p;
	memcpy(p, ptr, size);
	return p;
}

void Memory_free(void* memb)
{
    ;
}

