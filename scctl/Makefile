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
	mkdir -p $(QUADSTOR_INSTALL_ROOT)/bin; \
	echo "cp -f scctl $(QUADSTOR_INSTALL_ROOT)/bin"; \
	cp -f scctl $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f dbrecover $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f vdconfig $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f spconfig $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f bdconfig $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f ndconfig $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f qclone $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f qmirror $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f qsync $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f qmirrorcheck $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f fcconfig $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f qmapping $(QUADSTOR_INSTALL_ROOT)/bin; \
	cp -f rundiag $(QUADSTOR_INSTALL_ROOT)/bin; \
	if [ -f cam ]; then \
		cp -f cam $(QUADSTOR_INSTALL_ROOT)/bin; \
	fi

clean:
	rm -f *.o scctl cam dbrecover vdconfig spconfig bdconfig ndconfig qclone qmirror qmirrorcheck fcconfig qmapping qsync rundiag

clobber: clean
