#!/bin/sh
set -x
curdir=`pwd`

cd /quadstor/quadstor/ && sh buildcluster.sh clean
cd $curdir
DEBIAN_ROOT=$curdir/debian
rm -rf $DEBIAN_ROOT
mkdir $DEBIAN_ROOT
mkdir $DEBIAN_ROOT/DEBIAN
cp debian-itf-min-control $DEBIAN_ROOT/DEBIAN/control
install -m 755 debian-itf-min-prerm $DEBIAN_ROOT/DEBIAN/prerm
install -m 755 debian-itf-min-postrm $DEBIAN_ROOT/DEBIAN/postrm
install -m 755 debian-itf-min-preinst $DEBIAN_ROOT/DEBIAN/preinst
install -m 755 debian-itf-min-postinst $DEBIAN_ROOT/DEBIAN/postinst

install -m 755 -d $DEBIAN_ROOT/etc/udev/rules.d
install -m 755 -d $DEBIAN_ROOT/quadstor/src
install -m 755 -d $DEBIAN_ROOT/quadstor/src/export
install -m 644 /quadstor/quadstor/export/devq.[ch] $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/ldev_linux.[ch] $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/linuxdefs.h $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/exportdefs.h $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/missingdefs.h $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/qsio_ccb.h $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/core_linux.c $DEBIAN_ROOT/quadstor/src/export/
install -m 644 /quadstor/quadstor/export/Makefile.dist $DEBIAN_ROOT/quadstor/src/export/Makefile
install -m 644 /quadstor/quadstor/export/queue.h $DEBIAN_ROOT/quadstor/src/export/

install -m 755 -d $DEBIAN_ROOT/quadstor/src/common
install -m 644 /quadstor/quadstor/common/ioctldefs.h $DEBIAN_ROOT/quadstor/src/common/
install -m 644 /quadstor/quadstor/common/commondefs.h $DEBIAN_ROOT/quadstor/src/common/

install -m 755 /quadstor/quadstor/scripts/builditf.min.linux.sh $DEBIAN_ROOT/quadstor/bin/builditf.min
install -m 644 /quadstor/quadstor/scripts/quadstor-udev.rules $DEBIAN_ROOT/etc/udev/rules.d/65-quadstor.rules

rm -f debian.deb
fakeroot dpkg-deb --build $DEBIAN_ROOT 
