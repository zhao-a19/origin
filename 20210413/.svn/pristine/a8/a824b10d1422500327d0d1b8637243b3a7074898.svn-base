/*
Linux 下兼容Windows API定义
*/

#ifndef _WINAPI_DEF
#define _WINAPI_DEF

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "tchar.h"

#define ERROR_INVALID_NAME		-1


#define DRIVE_UNKNOWN     0
#define DRIVE_NO_ROOT_DIR 1
#define DRIVE_REMOVABLE   2
#define DRIVE_FIXED       3
#define DRIVE_REMOTE      4
#define DRIVE_CDROM       5
#define DRIVE_RAMDISK     6

#define INFINITE				0xFFFFFFFF  // Infinite timeout
#define INVALID_HANDLE_VALUE	 ((HANDLE)(-1))

long InterlockedIncrement(long volatile *Addend);
long InterlockedDecrement(long volatile *Addend);

typedef unsigned int* PUINT32;
// typedef uint64_t ULONG64;
// typedef unsigned int UINT;

typedef void* HMODULE;

typedef void* LPARAM;

#define _T( x )	 x
#define TEXT(x)	 x

#define LoadLibraryEx(dll,rev,flag)		LoadLibraryA(dll)

void* LoadLibraryA(const char * lpLibFileName);
void* GetProcAddress(void * hModule, const char * lpProcName);
bool  FreeLibrary(void* hLibModule);
int   GetLastError();
void  SetLastError(int err);
int   GetModuleFileName(HMODULE hModule,char* lpFilename,DWORD nSize );

void  AV_CALLTYPE Sleep(unsigned int t);

int   GetFullPathNameA(const char* path, int bufSize, char* buf, char**ppName);

//
#define _export_	__attribute__((visibility("default")))

#define _Inout_
#define __in
#define __out
#define __inout
#define _Inout_
#define __in_opt
#define __out_opt

#define VOID		void
#define WINAPI

// typedef unsigned int	DWORD;
typedef void*			HWND;

void CloseHandle(HANDLE handle);

BOOL WINAPI InitializeCriticalSectionEx(  __out LPCRITICAL_SECTION lpCriticalSection, __in  DWORD dwSpinCount, __in  DWORD Flags );
BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
VOID WINAPI DeleteCriticalSection( 	__inout LPCRITICAL_SECTION lpCriticalSection );
VOID WINAPI EnterCriticalSection(	_Inout_ LPCRITICAL_SECTION lpCriticalSection );
VOID WINAPI LeaveCriticalSection( 	_Inout_ LPCRITICAL_SECTION lpCriticalSection );
BOOL WINAPI TryEnterCriticalSection(__inout LPCRITICAL_SECTION lpCriticalSection);

HANDLE WINAPI	CreateSemaphore(	__in_opt LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, __in     LONG lInitialCount, __in     LONG lMaximumCount, __in_opt LPCSTR lpName );
HANDLE WINAPI	OpenSemaphore(		__in DWORD dwDesiredAccess,	__in BOOL bInheritHandle,	__in LPCSTR lpName);
BOOL   WINAPI	ReleaseSemaphore(	__in  HANDLE hSemaphore, __in LONG lReleaseCount, __out_opt LPLONG lpPreviousCount );

HANDLE WINAPI	CreateMutexEx(	__in_opt LPSECURITY_ATTRIBUTES lpMutexAttributes, __in_opt LPCSTR lpName, __in     DWORD dwFlags, __in     DWORD dwDesiredAccess );
BOOL   WINAPI	ReleaseMutex(	__in HANDLE hMutex );

HANDLE WINAPI	CreateEvent(	__in_opt LPSECURITY_ATTRIBUTES lpEventAttributes, __in BOOL bManualReset, __in BOOL bInitialState, __in_opt LPCSTR lpName );
HANDLE WINAPI	OpenEvent(		__in DWORD dwDesiredAccess,	__in BOOL bInheritHandle,	__in LPCSTR lpName );

BOOL   WINAPI	SetEvent(		__in HANDLE hEvent );
BOOL   WINAPI	ResetEvent(		__in HANDLE hEvent );


#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_DEVICE               0x00000040
#define FILE_ATTRIBUTE_NORMAL               0x00000080
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800
#define FILE_ATTRIBUTE_OFFLINE              0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000

DWORD WINAPI GetFileAttributes( 	__in LPCSTR lpFileName );
int   WINAPI SHCreateDirectoryEx(	__in_opt HWND hwnd, __in LPCSTR pszPath,__in_opt const LPSECURITY_ATTRIBUTES *psa);

int	  GetLocalTime(SYSTEMTIME* time);
DWORD WINAPI GetTickCount( 	VOID );

#define STATUS_WAIT_0        ((DWORD   )0x00000000L)
#define WAIT_OBJECT_0       ((STATUS_WAIT_0 ) + 0 )
#define WAIT_TIMEOUT		0x00000102L

#include <sys/syscall.h>
#include <unistd.h>

inline DWORD GetCurrentThreadId(VOID)
{
	// return pthread_self();
	return syscall(__NR_gettid);
}

typedef void(__cdecl*   _beginthread_proc_type)(void*);
typedef unsigned(__stdcall* _beginthreadex_proc_type)(void*);

HANDLE __cdecl _beginthreadex(
	_In_opt_  void*                    _Security,
	_In_      unsigned                 _StackSize,
	_In_      _beginthreadex_proc_type _StartAddress,
	_In_opt_  void*                    _ArgList,
	_In_      unsigned                 _InitFlag,
	_Out_opt_ unsigned*                _ThrdAddr
);

void __cdecl _endthreadex(
	_In_ unsigned _ReturnCode
);

typedef DWORD(WINAPI *PTHREAD_START_ROUTINE)(
	LPVOID lpThreadParameter
	);
typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

HANDLE WINAPI CreateThread(
	__in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in      SIZE_T dwStackSize,
	__in      LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	__in      DWORD dwCreationFlags,
	__out_opt LPDWORD lpThreadId
);

DWORD WINAPI ResumeThread(__in HANDLE hThread);

BOOL WINAPI TerminateThread(__in HANDLE hThread, __in DWORD dwExitCode);


////////////////////////////////////////////////////////////////////////
//

#define ERROR_SUCCESS                    0L
typedef LONG HRESULT;

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)

typedef enum tagCOINIT
{
	COINIT_APARTMENTTHREADED = 0x2,      // Apartment model

	// These constants are only valid on Windows NT 4.0
	COINIT_MULTITHREADED = 0x0,      // OLE calls objects on any thread.
	COINIT_DISABLE_OLE1DDE = 0x4,      // Don't use DDE for Ole1 support.
	COINIT_SPEED_OVER_MEMORY = 0x8,      // Trade memory for speed.
} COINIT;

inline HRESULT CoInitializeEx(__in_opt LPVOID pvReserved, __in DWORD dwCoInit)
{
	return ERROR_SUCCESS;
}
inline void CoUninitialize(void)
{
}


#define SEM_FAILCRITICALERRORS      0x0001
#define SEM_NOGPFAULTERRORBOX       0x0002
#define SEM_NOALIGNMENTFAULTEXCEPT  0x0004
#define SEM_NOOPENFILEERRORBOX      0x8000

inline UINT WINAPI GetErrorMode(VOID)
{
	return 0;
}

inline UINT WINAPI SetErrorMode(__in UINT uMode)
{
	return 0;
}


#undef __in			// 某些头文件有用到，为避免冲突，取消定义
#undef __out

#endif // _WINAPI_DEF