include ../build/rules.mk

CFLAGS += -Wall -I$(QUADSTOR_ROOT)/includes -I$(QUADSTOR_ROOT)/common -I$(QUADSTOR_ROOT)/core -Wl,-rpath=$(QUADSTOR_ROOT)/library/common -Wl,-rpath=$(QUADSTOR_ROOT)/library/client -Wl,-rpath=/quadstor/lib -Wl,-rpath=$(QUADSTOR_ROOT)/library/server

LDFLAGS += -L../library/common/ -L../library/client -L../library/server -ltlclnt -ltlmsg

ifeq ($(UNAME), FreeBSD)
LIBCAM = -lcam
CAM = cam
endif

all: scctl $(CAM) dbrecover vdconfig spconfig bdconfig ndconfig qclone qmirror qmirrorcheck fcconfig qmapping rundiag qsync 

dbrecover: dbrecover.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -I../io/ -I../pgsql/include -I../library/server -o dbrecover dbrecover.c $(LDFLAGS) $(LIBGEOM) -ltlmsg -ltlsrv

cam: cam.c
	$(CC) $(CFLAGS) -o cam cam.c $(LDFLAGS) -lcam

install:
	@set -e; \
	mkdir -p $(QUADSTOR_ROOT)/bin; \
	echo "cp -f scctl $(QUADSTOR_ROOT)/bin"; \
	cp -f scctl $(QUADSTOR_ROOT)/bin; \
	cp -f dbrecover $(QUADSTOR_ROOT)/bin; \
	cp -f vdconfig $(QUADSTOR_ROOT)/bin; \
	cp -f spconfig $(QUADSTOR_ROOT)/bin; \
	cp -f bdconfig $(QUADSTOR_ROOT)/bin; \
	cp -f ndconfig $(QUADSTOR_ROOT)/bin; \
	cp -f qclone $(QUADSTOR_ROOT)/bin; \
	cp -f qmirror $(QUADSTOR_ROOT)/bin; \
	cp -f qsync $(QUADSTOR_ROOT)/bin; \
	cp -f qmirrorcheck $(QUADSTOR_ROOT)/bin; \
	cp -f fcconfig $(QUADSTOR_ROOT)/bin; \
	cp -f qmapping $(QUADSTOR_ROOT)/bin; \
	cp -f rundiag $(QUADSTOR_ROOT)/bin; \
	if [ -f cam ]; then \
		cp -f cam $(QUADSTOR_ROOT)/bin; \
	fi

clean:
	rm -f *.o scctl cam dbrecover vdconfig spconfig bdconfig ndconfig qclone qmirror qmirrorcheck fcconfig qmapping qsync rundiag

clobber: clean
