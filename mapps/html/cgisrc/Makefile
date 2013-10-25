include ../../../build/rules.mk

CGILIST = system.cgi restart.cgi adddisk.cgi rescandisk.cgi liststoragepool.cgi modifystoragepool.cgi listtdisk.cgi addtdisk.cgi modifytdisk.cgi redirect.cgi modifytdiskpost.cgi adddiskpost.cgi modifydisk.cgi modifydiskpost.cgi adddiskcomp.cgi addstoragepool.cgi addstoragepoolpost.cgi deletestoragepool.cgi rundiag.cgi viewtdisk.cgi iscsiconfpost.cgi addtdiskpost.cgi deletetdisk.cgi viewstoragepool.cgi mirrorconf.cgi

all: $(CGILIST) strip install


HTDOCS = /var/www/html/
CGIBIN = /var/www/cgi-bin/

CFLAGS += -Wall -O2 -I../cgihtml/ -I$(QUADSTOR_ROOT)/includes -DCGIBIN=\"$(CGIBIN)\" -I $(QUADSTOR_ROOT)/common

LDFLAGS += -Wl,-rpath=$(QUADSTOR_ROOT)/library/common -Wl,-rpath=/quadstor/lib:$(QUADSTOR_ROOT)/library/client -L../../../library/common/ -L../../../library/client  -I$(QUADSTOR_ROOT)/common -ltlclnt -ltlmsg


CGIHTML = ../cgihtml/cgihtml.a 


addtdisk.cgi: addtdisk.o cgimain.o
	$(CC) $(CFLAGS) -o addtdisk.cgi addtdisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

addstoragepool.cgi: addstoragepool.o cgimain.o
	$(CC) $(CFLAGS) -o addstoragepool.cgi addstoragepool.o cgimain.o $(CGIHTML) $(LDFLAGS)

addstoragepoolpost.cgi: addstoragepoolpost.o cgimain.o
	$(CC) $(CFLAGS) -o addstoragepoolpost.cgi addstoragepoolpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

liststoragepool.cgi: liststoragepool.o cgimain.o
	$(CC) $(CFLAGS) -o liststoragepool.cgi liststoragepool.o cgimain.o $(CGIHTML) $(LDFLAGS)

modifystoragepool.cgi: modifystoragepool.o cgimain.o
	$(CC) $(CFLAGS) -o modifystoragepool.cgi modifystoragepool.o cgimain.o $(CGIHTML) $(LDFLAGS)

viewstoragepool.cgi: viewstoragepool.o cgimain.o
	$(CC) $(CFLAGS) -o viewstoragepool.cgi viewstoragepool.o cgimain.o $(CGIHTML) $(LDFLAGS)

deletestoragepool.cgi: deletestoragepool.o cgimain.o
	$(CC) $(CFLAGS) -o deletestoragepool.cgi deletestoragepool.o cgimain.o $(CGIHTML) $(LDFLAGS)

listtdisk.cgi: listtdisk.o cgimain.o
	$(CC) $(CFLAGS) -o listtdisk.cgi listtdisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

deletetdisk.cgi: deletetdisk.o cgimain.o
	$(CC) $(CFLAGS) -o deletetdisk.cgi deletetdisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

modifytdisk.cgi: modifytdisk.o cgimain.o
	$(CC) $(CFLAGS) -o modifytdisk.cgi modifytdisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

modifytdiskpost.cgi: modifytdiskpost.o cgimain.o
	$(CC) $(CFLAGS) -o modifytdiskpost.cgi modifytdiskpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

viewtdisk.cgi: viewtdisk.o cgimain.o
	$(CC) $(CFLAGS) -o viewtdisk.cgi viewtdisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

addtdiskpost.cgi: addtdiskpost.o cgimain.o
	$(CC) $(CFLAGS) -o addtdiskpost.cgi addtdiskpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

adddisk.cgi: adddisk.o cgimain.o
	$(CC) $(CFLAGS) -o adddisk.cgi adddisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

adddiskcomp.cgi: adddiskcomp.o cgimain.o
	$(CC) $(CFLAGS) -o adddiskcomp.cgi adddiskcomp.o cgimain.o $(CGIHTML) $(LDFLAGS)

adddiskpost.cgi: adddiskpost.o cgimain.o
	$(CC) $(CFLAGS) -o adddiskpost.cgi adddiskpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

modifydisk.cgi: modifydisk.o cgimain.o
	$(CC) $(CFLAGS) -o modifydisk.cgi modifydisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

modifydiskpost.cgi: modifydiskpost.o cgimain.o
	$(CC) $(CFLAGS) -o modifydiskpost.cgi modifydiskpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

rescandisk.cgi: rescandisk.o cgimain.o
	$(CC) $(CFLAGS) -o rescandisk.cgi rescandisk.o cgimain.o $(CGIHTML) $(LDFLAGS)

redirect.cgi: redirect.o cgimain.o
	$(CC) $(CFLAGS) -o redirect.cgi redirect.o cgimain.o $(CGIHTML) $(LDFLAGS)

system.cgi: system.o cgimain.o
	$(CC) $(CFLAGS) -o system.cgi system.o cgimain.o $(CGIHTML) $(LDFLAGS)

restart.cgi: restart.o cgimain.o
	$(CC) $(CFLAGS) -o restart.cgi restart.o cgimain.o $(CGIHTML) $(LDFLAGS)

iscsiconfpost.cgi: iscsiconfpost.o cgimain.o
	$(CC) $(CFLAGS) -o iscsiconfpost.cgi iscsiconfpost.o cgimain.o $(CGIHTML) $(LDFLAGS)

rundiag.cgi: rundiag.o cgimain.o
	$(CC) $(CFLAGS) -o rundiag.cgi rundiag.o cgimain.o $(CGIHTML) $(LDFLAGS)

mirrorconf.cgi: mirrorconf.o cgimain.o
	$(CC) $(CFLAGS) -o mirrorconf.cgi mirrorconf.o cgimain.o $(CGIHTML) $(LDFLAGS)

clean:
	rm -f *.o *.cgi


install: $(CGILIST)
	@set -x; \
	export LD_LIBRARY_PATH=.; \
	sh ./install.sh

localinstall: $(CGILIST)
	@set -x; \
	export LD_LIBRARY_PATH=.; \
	sh ./install.sh localinstall

strip:
	@set -x; \
	if [ "$(RELEASE_BUILD)" -eq "1" ]; then \
		strip --strip-unneeded *.cgi; \
	fi
