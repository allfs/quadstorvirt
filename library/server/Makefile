
include ../../build/rules.mk

CFLAGS += -Wall -pthread -I. -I../../includes -I../common/ -I$(QUADSTOR_ROOT)/pgsql/include/ -I$(QUADSTOR_ROOT)/common -I$(QUADSTOR_ROOT)/core -I../../io -fpic -Winit-self

#CFLAGS += -DENABLE_DEBUG

CFLAGS += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

LDFLAGS += -Wl,-rpath=/quadstor/lib:$(QUADSTOR_ROOT)/library/common -L../common -L/quadstor/lib -ltlmsg

ifeq ($(UNAME), Linux)
LDFLAGS += -lpthread
else
LDFLAGS += -pthread
endif

ifeq ($(UNAME), FreeBSD)
LDFLAGS += -lcam -lgeom
endif

SRCS = serverapis.c

OBJS = serverapis.o ietadm.o physlib.o sqlint.o diskinfo.o node_client.o node_controller.o node_recv.o node_send.o node_usr.o fcconfig.o log.o pgsql.o md5c.o

all: libtlsrv.so

libtlsrv.so: $(OBJS)
	@set -e; \
	$(CC) -Wall $(CFLAGS) -shared -o libtlsrv.so $(OBJS) $(QUADSTOR_ROOT)/pgsql/lib/libpq.a  $(LDFLAGS); \
	if [ "$(RELEASE_BUILD)" -eq "1" ]; then \
		strip --strip-unneeded *.so; \
	fi

clean:
	rm -f *.o *.so

