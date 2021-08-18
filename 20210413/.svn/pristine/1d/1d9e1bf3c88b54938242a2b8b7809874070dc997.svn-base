
#set build
CC = g++
C = gcc
AR = ar
CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))

#file size larger 2GB
include ../../osmake

#project public files
COM = ../
COMINC = $(COM)inc/
COMLIB = $(COM)lib/

ZLOG = ../../3rd-party/zlog/
ZLOGINC = $(ZLOG)inc/
ZLOGLIB = $(ZLOG)lib/
QCOM = ../../3rd-party/glib/

LIBS = -lpthread -lcurses  -lz

#set env variable
VPATH = $(COMINC): $(COMLIB): $(ZLOGINC): $(ZLOGLIB)

ifeq ($(osv), x86)
QINC = $(QCOM)inc_v6/glib-2.0/
VPATH += $(QINC)
else ifeq ($(osv), aarch64)
QINC = /usr/include/glib-2.0/
VPATH += $(QINC)
else
QINC = $(QCOM)inc_v8/glib-2.0/
VPATH += $(QINC)
endif

#get all files
#SOURCE = $(wildcard *.cpp)  $(COM)stringex.cpp $(COM)filename.cpp $(COM)md5.cpp
SOURCE = $(wildcard *.cpp)
OBJS = $(patsubst %.cpp,%.o,$(SOURCE))

#user model name, pls replace by yourself
all : syssocket
syssocket : $(OBJS)
	$(AR) -rcs libsyssocket.a $(OBJS)

.PHONY : clean
clean :
	-rm -f libsyssocket.a *.o *.d $(COM)*.o $(COM)*.d

include $(SOURCE:.cpp=.d)

%.o:%.cpp
	$(CC) -Wall -O2 $(CPPFLAGS) -c $< -o $@
#get all dependencies
%.d:%.cpp
	@set -e; rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

