
/*******************************************************************************************
*文件:    zdb_porting.c
*描述:    suricata.c的裁剪
*
*作者:    张冬波
*日期:    2016-05-05
*修改:    创建文件                            ------>     2016-05-05
*
*******************************************************************************************/

#include "suricata-common.h"
#include "zdb_porting.h"


#ifdef DBG_MEM_ALLOC
#ifndef _GLOBAL_MEM_
#define _GLOBAL_MEM_
/* This counter doesn't complain realloc's(), it's gives
 * an aproximation for the startup */
size_t global_mem = 0;
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
uint8_t print_mem_flag = 0;
#else
uint8_t print_mem_flag = 1;
#endif
#endif
#endif

#if CPPCHECK != 1
SC_ATOMIC_DECLARE(unsigned int, engine_stage);
void __main_test(void)
{
    SC_ATOMIC_INIT(engine_stage);

    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_INIT, SURICATA_RUNTIME);

    while (1) {
        sleep(1);
    }


    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_RUNTIME, SURICATA_DEINIT);

    SC_ATOMIC_DESTROY(engine_stage);

}
#endif

