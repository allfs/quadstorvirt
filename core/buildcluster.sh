#/bin/sh

set -x
os=`uname`

if [ "$QUADSTOR_ROOT" = "" ]; then
	QUADSTOR_ROOT=`cd .. && pwd`
fi

if [ "$1" = "install" ]; then
	exit 0
fi

rm -f corelib.o
if [ "$os" = "FreeBSD" ]; then
	make -f Makefile.bsd.cluster $1 QUADSTOR_ROOT=$QUADSTOR_ROOT
else
	make -f Makefile.ext.cluster $1 QUADSTOR_ROOT=$QUADSTOR_ROOT
fi

if [ "$?" != "0" ]; then
  	exit 1
fi

if [ "$1" = "clean" ]; then
	exit 0
fi

rm -f core.ko corelib.o
if [ "$os" = "FreeBSD" ]; then
	ld  -d -warn-common -r -d -o corelib.o `ls *.o`
else
	ld -m elf_x86_64 -r -o corelib.o `ls *.o` `ls util/*.o`
fi

#objcopy --strip-debug corelib.o
#objcopy --strip-unneeded corelib.o
mkdir -p $QUADSTOR_ROOT/lib/modules/
cp -f corelib.o $QUADSTOR_ROOT/lib/modules/
