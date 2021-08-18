/*
 * Linux 下兼容Windows Typedef 等定义
*/

#pragma once

/**
* 基本宏定义：
* 平台宏，用于区分当前编译的目标平台，定义下列宏表明编译的目标操作系统为对应的操作系统
*    PLT_WIN32 32位 Windows 平台
*   PLT_WIN64 64位 Windows 平台
*   PLT_LINUX32 32 位 Linux 平台
*   PLT_LINUX64 64 位 Linux 平台
* 传参方式:
*   AV_CALLTYPE
*/

#include <stdint.h>
#include <stddef.h>

#ifndef PURE
#define PURE = 0
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define _Inout_
#define _In_opt_z_
#define _In_

#ifdef _MSC_VER
#ifdef _WIN64
#define PLT_WIN64
#define PLT_WIN
#else
#define PLT_WIN32
#define PLT_WIN
#endif
#endif // _MSC_VER

typedef long LONG;
typedef long *LPLONG;

#ifdef __GNUC__
#ifdef _X86_
#define PLT_LINUX32
#define PLT_LINUX
#else
#define PLT_LINUX64
#define PLT_LINUX
#endif // _X86_
#endif // GCC

// #ifdef __cplusplus
/*
__if_not_exists(DWORD) {
typedef unsigned long DWORD;
}
__if_not_exists(QWORD) {
typedef uint64_t QWORD;
}
__if_not_exists(WORD) {
typedef uint16_t WORD;
}
__if_not_exists( BYTE ) {
typedef uint8_t BYTE;
}
*/

#ifdef __GNUC__
#include <stdbool.h>
typedef void VOID;
typedef int  BOOL;
typedef int  BOOLEAN;
typedef char CHAR;

#ifndef LPCSTR_DEF
#define LPCSTR_DEF
typedef const char *LPCSTR, *LPCCH;
typedef char *LPSTR;
typedef wchar_t WCHAR;
typedef const wchar_t *LPCWSTR;
#endif // LPCSTR_DEF

typedef int INT;
typedef unsigned int UINT;
typedef uint32_t DWORD32;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef short SHORT;
typedef unsigned short USHORT, *USHORT_PTR;
// typedef long LONG;
typedef unsigned long ULONG, *ULONG_PTR;
typedef unsigned long long ULONG64, ULONG64_PTR;
typedef size_t SIZE_T;
typedef void *LPVOID;
typedef void *PVOID;
typedef void *SC_HANDLE;
typedef void *HANDLE;
#define CONST const
#endif // __GNUC__

#ifndef DWORD_DEF
#define DWORD_DEF
typedef unsigned long long QWORD;
typedef uint32_t DWORD, *LPDWORD;
typedef uint16_t WORD, UINT16;
typedef uint8_t BYTE, UINT8;
#endif // DWORD_DEF

// #endif //__cplusplus

#ifdef PLT_WIN
#include <Window.h>
#define CRUN_CALLTYPE __cdecl // C运行库的传参方式
#define AV_CALLTYPE __stdcall
#define PATH_SPLIT_CHAR '\\'
#define PATH_SPLIT_STRING L"\\"

#ifdef AVUTIL_EXPORTS
#define AVUTIL_API __declspec(dllexport)
#else
#define AVUTIL_API __declspec(dllimport)
#endif

#endif // PLT_WIN

#ifdef PLT_LINUX

#define PATH_SPLIT_CHAR '/'
#define PATH_SPLIT_STRING "/"

#define AVUTIL_API __attribute__((visibility("default")))

#ifdef __x86_64__

#define _cdecl
#define _stdcall
#define __cdecl
#define __stdcall
#define CRUN_CALLTYPE
#define AV_CALLTYPE

#else

#define _cdecl __attribute__((__cdecl__))
#define _stdcall __attribute__((__stdcall__))
#define __cdecl __attribute__((__cdecl__))
#define __stdcall __attribute__((__stdcall__))
#define CRUN_CALLTYPE __attribute__((__cdecl__)) // C运行库的传参方式
#define AV_CALLTYPE __attribute__((__stdcall__))

#endif // __x86_64__

#include <stdio.h>
#include <stdlib.h>

#define far

#define APIENTRY _stdcall

#ifndef _Null_terminated_
#define _Null_terminated_
#endif // _Null_terminated_

#endif // PLT_LINUX

#ifdef __cplusplus
#define EXTERN_C_BEGIN \
	extern "C"         \
	{
#define EXTERN_C_END }
#define EXTERN_C extern "C"
#endif //__cplusplus

#ifdef PLT_WIN

#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif // WIN64

#endif // WIN32

#ifdef PLT_LINUX

/*
#ifdef PLT_LINUX64
typedef unsigned long long  size_t;
#else
typedef unsigned int     size_t;
#endif // PLT_LINUX64
*/
typedef int ACCESS_MASK;
typedef long long __int64;
typedef uint64_t __time64_t;

//#define __int64 long long

#define _IN_
#define _OUT_
#define IN
#define OUT

#define _In_
#define _Out_

#define _In_z_
#define _Inout_z_
#define _Out_z_

#define _In_opt_
#define _Out_opt_

#define _Ret_maybenull_
#define _Post_writable_byte_size_(n)
#define _Inout_updates_(n)
#define _Inout_updates_to_(n, n2)
#define _Out_writes_all_(n)
#define _In_reads_(n)
#define _Out_writes_all_(n)
#define _Null_terminated_

// #define nullptr  ((void*)0)

#define FALSE 0

#define _ATL_PACKING 8
#ifndef AtlThrow
#define AtlThrow(x)
#endif // AtlThrow

#ifndef FILENAME_MAX
#define FILENAME_MAX 260
#endif // FILENAME_MAX

#ifndef MAX_PATH
#define MAX_PATH 4096
#define _MAX_PATH MAX_PATH
#endif // MAX_PATH

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif // PLT_LINUX

#ifndef UINT_PTR_DEF
#define UINT_PTR_DEF

#ifdef _MSC_VER
#ifdef _WIN64
typedef unsigned __int64 UINT_PTR;
#define _64BIT_ 1
#else
typedef unsigned int UINT_PTR;
#define _32BIT_ 1
#endif
#endif // VC

#ifdef __GNUC__
#ifdef _X86_
typedef char __int8;
typedef short __int16;
typedef unsigned int UINT_PTR;
typedef int		INT_PTR;
#define _64BIT_ 1
#else
typedef unsigned long long UINT_PTR;
typedef long long			INT_PTR;
#define _32BIT_ 1
#endif // _X86_

#endif // GCC

#endif // UINT_PTR_DEF

#ifdef __GNUC__
#include <pthread.h>
#ifndef HLOCK_DEFINED
#define HLOCK_DEFINED
typedef pthread_mutex_t *HLOCK;
#endif // HLOCK_DEFINED
typedef pthread_mutex_t CRITICAL_SECTION;
typedef pthread_mutex_t *LPCRITICAL_SECTION;
#endif

#ifndef _FILETIME_
#define _FILETIME_

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

//__if_not_exists(SYSTEMTIME) {
typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME;
//}
#endif // _FILETIME_

typedef unsigned long long ULONGLONG;
typedef BOOL *PBOOL;

typedef void *LPSECURITY_ATTRIBUTES;

#define UNREFERENCED_PARAMETER(P) (P)
#define DBG_UNREFERENCED_PARAMETER(P) (P)
#define DBG_UNREFERENCED_LOCAL_VARIABLE(V) (V)

//typedef bool boolean_t;
// #define NO 0
