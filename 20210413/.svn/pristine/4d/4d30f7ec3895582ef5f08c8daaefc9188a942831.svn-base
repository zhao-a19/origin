
#set build 
CC = g++
C = gcc
flag=-Wall -Wno-write-strings -Wno-unused -O2 ${FLAG}

#file size larger 2GB
include ../suos_vermake

#project public files
COM = ../public/
COMINC = $(COM)inc/
CURLINC = /usr/local/curl/include/

CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

VPATH += $(COMINC): $(CURLINC)
ifdef suosv8
        LIBS=-lmysqlclient_r -L/usr/local/mysql/lib
        VPATH += ..:../include:/usr/local/mysql/include
        LIBZLOG=-lzlog
        SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
        LIBS=-lmysqlclient
        VPATH += ..:../include:/usr/local/mysql/include
        LIBZLOG=-lzlog 
        SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
        LIBS=-lmysqlclient_r -L/usr/local/mysql/lib 
        VPATH += ..:../include:/usr/local/mysql/include
        LIBZLOG=-lzlog
        SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
        LIBS=-lmysqlclient_r 
        VPATH += ..:../include:/usr/include/mysql/
        LIBZLOG=-lzlog
        SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
        LIBS=../lib/libmysqlclient_r.a ../lib/libmyisammrg.a
        VPATH += ..:../include:../mysql
        LIBZLOG=../lib/libzlog.a
        SUOSVERSION=-DSUOS_V=6
endif

#set env variable
VPATH += $(COMINC): $(CURLINC)

#get all files
SOURCE = $(wildcard *.cpp)  $(wildcard $(COM)*.cpp)
OBJS = $(patsubst %.cpp,%.o,$(SOURCE))

all : check_log	
check_log : $(OBJS)
	$(CC) $(SUOSVERSION)  $(CPPFLAGS) -g -rdynamic -o $@ $^ $(LIBS) $(LIBZLOG) -lpthread

.PHONY : clean
clean :
	-rm -f check_log $(OBJS) 

include $(SOURCE:.cpp=.d)	
	
%.o:%.cpp
	$(CC) $(SUOSVERSION) $(flag) $(CPPFLAGS) -c $< -o $@

#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

