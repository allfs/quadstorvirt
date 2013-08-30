#/bin/sh
set -x
curdir=`pwd`
libvers="3.0.46"

cd /quadstor/quadstor/ && sh buildcluster.sh clean
cd /quadstor/quadstor/ && sh buildcluster.sh
cd $curdir

DEBIAN_ROOT=$curdir/debian
rm -rf $DEBIAN_ROOT
mkdir $DEBIAN_ROOT
mkdir $DEBIAN_ROOT/DEBIAN
cp debian-client-control $DEBIAN_ROOT/DEBIAN/control
install -m 755 debian-client-postrm $DEBIAN_ROOT/DEBIAN/postrm
install -m 755 debian-client-postinst $DEBIAN_ROOT/DEBIAN/postinst

install -m 755 -d $DEBIAN_ROOT/quadstor/lib/modules
install -m 755 -d $DEBIAN_ROOT/quadstor/bin
install -m 755 -d $DEBIAN_ROOT/quadstor/sbin
install -m 755 -d $DEBIAN_ROOT/quadstor/etc
install -m 755 -d $DEBIAN_ROOT/quadstor/etc/iet
install -m 755 -d $DEBIAN_ROOT/etc/init.d

install -m 755 /quadstor/quadstor/masterd/mdaemon $DEBIAN_ROOT/quadstor/sbin/ncdaemon
install -m 744 /quadstor/quadstor/scctl/ndconfig $DEBIAN_ROOT/quadstor/bin/ndconfig
install -m 744 /quadstor/quadstor/scctl/rundiag $DEBIAN_ROOT/quadstor/bin/rundiag
install -m 744 /quadstor/quadstor/scctl/qmapping $DEBIAN_ROOT/quadstor/bin/qmapping
install -m 644  /quadstor/quadstor/library/client/libtlclnt.so $DEBIAN_ROOT/quadstor/lib/libtlclnt.so.$libvers
install -m 644 /quadstor/quadstor/library/server/libtlsrv.so $DEBIAN_ROOT/quadstor/lib/libtlsrv.so.$libvers
install -m 644 /quadstor/quadstor/library/common/libtlmsg.so $DEBIAN_ROOT/quadstor/lib/libtlmsg.so.$libvers
install -m 644 /quadstor/lib/modules/corelib.o $DEBIAN_ROOT/quadstor/lib/modules/
install -m 744 /quadstor/quadstor/etc/quadstor.linux.client $DEBIAN_ROOT/etc/init.d/quadstor
sed -i -e "s/Default-Start.*/Default-Start:\t\t2 3 4 5/g" $DEBIAN_ROOT/etc/init.d/quadstor
sed -i -e "s/Default-Stop.*/Default-Stop:\t\t\t0 1 6/g" $DEBIAN_ROOT/etc/init.d/quadstor
install -m 744 /quadstor/quadstor/scripts/diaghelper.linux $DEBIAN_ROOT/quadstor/bin/diaghelper
install -m 444 /quadstor/quadstor/LICENSE $DEBIAN_ROOT/quadstor/
install -m 444 /quadstor/quadstor/GPLv2 $DEBIAN_ROOT/quadstor/

#Install src
install -m 755 -d $DEBIAN_ROOT/quadstor/src/others
install -m 644 /quadstor/quadstor/core/sha*.[ch] $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/core/sha*.s $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/core/md32_common.h $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/library/server/md5*.[ch] $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/core/lzf*.[ch] $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/core/lz4*.[ch] $DEBIAN_ROOT/quadstor/src/others/
install -m 644 /quadstor/quadstor/core/sysdefs/*.h $DEBIAN_ROOT/quadstor/src/others/


cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlclnt.so.$libvers libtlclnt.so.1
cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlclnt.so.$libvers libtlclnt.so
cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlsrv.so.$libvers libtlsrv.so.1
cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlsrv.so.$libvers libtlsrv.so
cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlmsg.so.$libvers libtlmsg.so.1
cd $DEBIAN_ROOT/quadstor/lib && ln -fs libtlmsg.so.$libvers libtlmsg.so
rm -f debian.deb
fakeroot dpkg-deb --build $DEBIAN_ROOT 

