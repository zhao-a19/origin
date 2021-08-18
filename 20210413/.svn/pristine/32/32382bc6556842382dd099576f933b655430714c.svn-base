#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <fcntl.h>


#define MSPEED_SEM "/mspeed_sem"

int main(int argc,char* argv[])
{

    struct timeval t1, t2;
    char  buf[1024];
    memset(buf, '1', sizeof(buf));
    buf[1023] = 0;
    char* ptr[100];

    sem_unlink(MSPEED_SEM);
    sem_t *semmspeed = sem_open(MSPEED_SEM, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IRGRP | S_IWUSR | S_IROTH, 1);
    if(semmspeed == SEM_FAILED)
    {
        printf("sem_open failed!\n");
        return -1;
    }

    while (1)
    {
        gettimeofday(&t1, NULL);
        for (int i = 0; i < 100; i++)
        {
            ptr[i] = (char*)malloc(sizeof(buf));
            if (ptr[i] == NULL)
            {
                perror("malloc");
                break;
            }
            memcpy(ptr[i], buf, sizeof(buf));
            sem_wait(semmspeed);
            sem_post(semmspeed);
        }
        gettimeofday(&t2, NULL);

        unsigned  long diff;

        diff = 1000000 * (t2.tv_sec - t1.tv_sec) + t2.tv_usec - t1.tv_usec;

        printf("malloc speed: %ld us, 100 ITEM:%ld\n", diff/100, diff);

        sleep(1);
        for (int i = 0; i < 100; i++)
        {
            //printf("%s\n", ptr[i]);
            free(ptr[i]);
            ptr[i] = NULL;
        }
    }

	return 0;
}

