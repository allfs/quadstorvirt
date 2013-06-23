include ../build/rules.mk

CFLAGS += -Wall -I$(QUADSTOR_ROOT)/includes -I$(QUADSTOR_ROOT)/common -I$(QUADSTOR_ROOT)/core -Wl,-rpath=$(QUADSTOR_ROOT)/library/common -Wl,-rpath=$(QUADSTOR_ROOT)/library/client -Wl,-rpath=/quadstor/lib -Wl,-rpath=$(QUADSTOR_ROOT)/library/server

LDFLAGS += -L../library/common/ -L../library/client -L../library/server -ltlclnt -ltlmsg

ifeq ($(UNAME), FreeBSD)
LIBCAM = -lcam
CAM = cam
endif

all: scctl $(CAM) dbrecover vdconfig ndconfig qclone qmirror qmirrorcheck fcconfig qmapping rundiag qsync 

dbrecover: dbrecover.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -I../io/ -I../pgsql/include -I../library/server -o dbrecover dbrecover.c $(LDFLAGS) $(LIBGEOM) -ltlmsg -ltlsrv

cam: cam.c
	$(CC) $(CFLAGS) -o cam cam.c $(LDFLAGS) -lcam

install:
	@set -e; \
	mkdir -p /quadstor/bin; \
	echo "cp -f scctl /quadstor/bin"; \
	cp -f scctl /quadstor/bin;
	cp -f dbrecover /quadstor/bin;
	cp -f vdconfig /quadstor/bin;
	cp -f ndconfig /quadstor/bin;
	cp -f qclone /quadstor/bin;
	cp -f qmirror /quadstor/bin;
	cp -f qsync /quadstor/bin;
	cp -f qmirrorcheck /quadstor/bin;
	cp -f fcconfig /quadstor/bin;
	cp -f qmapping /quadstor/bin;
	cp -f rundiag /quadstor/bin;
	cp -f cam /quadstor/bin;

clean:
	rm -f *.o scctl cam dbrecover vdconfig ndconfig qclone qmirror qmirrorcheck fcconfig qmapping qsync rundiag

clobber: clean
