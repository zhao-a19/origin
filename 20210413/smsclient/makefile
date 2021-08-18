
include ../suos_vermake

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
	LIBZLOG=-lzlog -lpthread
	SUOSVERSION=-DSUOS_V=2000
else ifdef suosv6
	LIBZLOG=../lib/libzlog.a -lpthread
	SUOSVERSION=-DSUOS_V=6
endif

C++ = g++
C   = cc
flag=-O2
RUN=${C++} ${flag}
RUNLINK=${C++} ${flag}
INCLUDE=-I../ -I../include/ -I../public/inc
OBJECTS= smsmain.o FCBSTX.o

smsmain:$(OBJECTS)
	$(RUNLINK)  -o smsc $(OBJECTS) $(LIBZLOG) $(INCLUDE)

smsmain.o:smsmain.cpp
	$(RUN) -c $(INCLUDE) smsmain.cpp
FCBSTX.o:../FCBSTX.cpp ../FCBSTX.h
	$(RUN) -c $(INCLUDE) ../FCBSTX.cpp

clean:
	rm -r --force *.o smsc
