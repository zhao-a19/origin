
#set build, supported by cross compile 
CC = $(SUCROSS_C)g++
C = $(SUCROSS_C)gcc
AR = $(SUCROSS_C)ar
CFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CPPFLAGS +=  $(patsubst %,-I%,$(subst :, ,$(VPATH)))
CFLAGS += -std=c99

#file size larger 2GB
CFLAGS += -D_FILE_OFFSET_BITS=64
CPPFLAGS += -D_FILE_OFFSET_BITS=64

#project public files
COM = ../../../public/
COMINC = $(COM)inc/
COMLIB = $(COM)lib/
PCAP = ../../../3rd-party/pcap/
PCAPINC = $(PCAP)inc/
PCAPLIB = $(PCAP)lib/
PCRE = ../../../3rd-party/pcre/
PCRELIB = $(PCRE)lib/
PCREINC = $(PCRE)inc/
ZLOG = ../../../3rd-party/zlog/
ZLOGINC = $(ZLOG)inc/
ZLOGLIB = $(ZLOG)lib/

SELFINC = ./
SELFLIB = ../lib/

LIBS = -lpthread -lcurses  -lz

#set env variable
VPATH = $(COMINC): $(COMLIB): $(PCAPINC): $(PCAPLIB): $(PCREINC): $(PCRELIB): $(SELFINC): $(SELFLIB)
VPATH += /user/include/: $(ZLOGINC): $(ZLOGLIB)

#get all files
SOURCE = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCE))

#user model name, pls replace by yourself
all : suricata	
suricata : $(OBJS)
	$(AR) -rcs libsuricata.a $(OBJS)

.PHONY : clean
clean :
	-rm -f libsuricata.a $(patsubst %.o,%.d,$(OBJS)) $(OBJS)

include $(SOURCE:.c=.d)	
	
%.o:%.c
	$(C) -Wall -O2 $(CFLAGS) -c $< -o $@

#get all dependencies
%.d:%.c
	@set -e; rm -f $@; \
	$(C) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

