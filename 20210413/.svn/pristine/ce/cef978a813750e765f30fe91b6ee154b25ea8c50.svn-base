#ifndef TCHAR_DEF
#define TCHAR_DEF

#ifndef _TCHAR_DEFINED
#ifdef _UNICODE
typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
typedef WCHAR TCHAR, *PTCHAR;
typedef WCHAR TBYTE, *PTBYTE;
#define _T( x ) L##x
#else
typedef char TCHAR, *PTCHAR;
typedef unsigned char TBYTE, *PTBYTE;
#define _T( x ) x
#endif
#define _TCHAR_DEFINED
// #pragma message( "TCHAR defined in " __FILE__)
#endif /* !_TCHAR_DEFINED */


#define _mktime64	mktime

#ifdef _UNICODE

#define _tcscat		wcscat
#define _tcscpy		wcscpy
#define _tcsncpy	wcsncpy


#else

#define _tcsicmp	strcasecmp
#define _tcsnicmp	strncasecmp
#define _tcsncmp	strncmp
#define _tcscmp		strcmp
#define _stricmp	strcasecmp
#define _strnicmp	strncasecmp


#define _tcscat		strcat
#define _tcscpy		strcpy
#define _tcsncpy	strncpy
#define _tcsncpy_s(d,dlen,s,len) strncpy(d,s,len)
#define _tcsrchr	strrchr
#define _tcstok_s(s,delim,pp)	strtok(s,delim)

#define _tstat		stat
#define _stat64i32	stat
#define _stat64		stat
#define _tstat64	stat

#define _tcsrchr	strrchr
#define _tcschr		strchr
#define _tcsstr		strstr

#define _tfopen		fopen
#define _ftprintf	fprintf
#define _tprintf	printf
#define _stprintf	sprintf


#define lstrlen		strlen
#define _tcslen		strlen

#define _tcscpy_s(d,n,s) strncpy(d,s,n)
#define _tcscat_s(d,n,s) strcat(d,s)
#define strncpy_s	 strncpy

#define _countof(s)	strlen(s)


#define _ttoi		atoi
#define _tcstoul	strtoul


typedef  char*	LPTSTR;
typedef const char * LPCTSTR;

#endif // _UNICODE

#endif // TCHAR_DEF
