#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

//É¾³ý×ó±ßµÄ¿Õ¸ñ
char *l_trim(char *szOutput, const char *szInput)
{
    if (szInput == NULL || szOutput == NULL || szOutput == szInput) return NULL;
    for ( ; *szInput != '\0' && isspace(*szInput); ++szInput)
    {
        ;
    }
    return strcpy(szOutput, szInput);
}

//É¾³ýÓÒ±ßµÄ¿Õ¸ñ
char *r_trim(char *szOutput, const char *szInput)
{
    char *p = NULL;
    if (szInput == NULL || szOutput == NULL || szOutput == szInput) return NULL;
    memcpy(szOutput, szInput, strlen(szInput));
    for (p = szOutput + strlen(szOutput) - 1; p >= szOutput && isspace(*p);	--p)
    {
        ;
    }
    *(++p) = '\0';
    return szOutput;
}

//É¾³ýÁ½±ßµÄ¿Õ¸ñ
char *a_trim(char *szOutput, const char *szInput)
{
    char *p = NULL;
    if (szInput == NULL || szOutput == NULL) return NULL;
    l_trim(szOutput, szInput);
    for (p = szOutput + strlen(szOutput) - 1; p >= szOutput && isspace(*p);	--p)
    {
        ;
    }
    *(++p) = '\0';
    return szOutput;
}
