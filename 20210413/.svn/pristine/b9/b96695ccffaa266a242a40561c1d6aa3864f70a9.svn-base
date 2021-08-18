cc=g++
FLAG=-O2

include ../suos_vermake

THLIB=-lpthread
OBJS=crt.o FCThread.o common.o

COM=../
INCLUDE=-I. -I$(COM) -I$(COM)include/

ifdef suosv8
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=8
else ifdef suosv8.1
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=81
else ifdef suos_arm64_1043
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=1000
else ifdef suos_ft
	LIBZLOG=-lzlog
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBZLOG=../lib/libzlog.a
	SUOSVERSION=-DSUOS_V=6
endif

all:crt
crt:$(OBJS)
	$(cc) $(FLAG) -o crt $(OBJS) $(LIBZLOG) $(THLIB)
crt.o:crt.cpp  crt.h
	$(cc) $(FLAG) -c crt.cpp $(INCLUDE) $(LIBZLOG)
FCThread.o:$(COM)FCThread.cpp $(COM)FCThread.h
	$(cc) $(FLAG) -c $(COM)FCThread.cpp $(INCLUDE) $(LIBZLOG)
common.o:$(COM)common.cpp $(COM)common.h
	$(cc) $(FLAG) -c $(COM)common.cpp $(INCLUDE) $(LIBZLOG)
clean:
	rm -f *.o crt

#End makefile
