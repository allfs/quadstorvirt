
include ../../build/rules.mk

CFLAGS += -Wall -pthread -I$(QUADSTOR_ROOT)/includes -I$(QUADSTOR_ROOT)/common -fpic

#CFLAGS += -DENABLE_DEBUG

ifeq ($(UNAME), Linux)
LDFLAGS += -lpthread
else
LDFLAGS += -pthread
endif


ifeq ($(UNAME), FreeBSD)
LDFLAGS += -lcam
endif

OBJS = messages.o commonapis.o physdisk.o tdisk.o

all: libtlmsg.so

libtlmsg.so: $(OBJS)
	@set -e; \
	$(CC) $(CFLAGS) -shared -o libtlmsg.so $(OBJS) $(LDFLAGS); \
	if [ "$(RELEASE_BUILD)" -eq "1" ]; then \
		strip --strip-unneeded *.so; \
	fi

clean:
	rm -f *.o *.so
