
include ../suos_vermake

CC=gcc

CFLAGS_WARN = -Wall

DEFINE =

ifdef suos_arm64_1043
INCLUDE = -I/usr/local/wireshark/
INCLUDE += -I/usr/include/glib-2.0/
INCLUDE += -I/usr/include/glib-2.0/glib/
INCLUDE += -I/usr/lib64/glib-2.0/include/
else ifdef suos_ft
INCLUDE = -I../3rd-party/opensource/wireshark-2.0.2/
INCLUDE += -I/usr/include/glib-2.0/
INCLUDE += -I/usr/lib/aarch64-linux-gnu/glib-2.0/include/
else
INCLUDE = -I../3rd-party/opensource/wireshark-2.0.2/
INCLUDE += -I../3rd-party/glib/inc_v8/glib-2.0/
INCLUDE += -I../3rd-party/glib/inc_v8/glib-2.0/glib/
endif

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TARGET  = libwireshark_epan_print.a

All:$(OBJS)
	ar -r $(TARGET) *.o

%.o:%.c
	$(CC) -c $(CFLAGS_WARN) $(DEFINE) $(INCLUDE) $< -o $@
clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
