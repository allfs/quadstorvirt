#!/bin/sh

checkerror() {
	if [ "$?" != "0" ]; then
		echo "ERROR: Building kernel modules failed!"
		exit 1
	fi
}

if [ ! -f /quadstor/lib/modules/corelib.o ]; then
	echo "Cannot find core library. Check if quadstor-core package is installed"
	exit 1
fi

os=`uname`
cd /quadstor/src/export
make clean && make 
checkerror

kvers=`uname -r`
mkdir /quadstor/lib/modules/$kvers

cp -f coredev.ko /quadstor/lib/modules/$kvers/
cp -f ldev.ko /quadstor/lib/modules/$kvers/
