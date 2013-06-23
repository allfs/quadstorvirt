#!/bin/sh
set -x
curdir=`pwd`
sh buildinit.sh bsd9
cd /quadstor/quadstor/pgsql && gmake install
cd $curdir
rm -f createpkg9.sh createclient9.sh createitf9.sh
cp createpkg.sh createpkg9.sh
cp createclient.sh createclient9.sh
cp createitf.sh createitf9.sh

sed -i -e "s/FreeBSD8.2/FreeBSD9.1/" createpkg9.sh
sed -i -e "s/FreeBSD8.2/FreeBSD9.1/" createclient9.sh
sed -i -e "s/FreeBSD8.2/FreeBSD9.1/" createitf9.sh
sed -i -e "s/FreeBSD 8.2/FreeBSD 9.1/" pkg-post-itf.sh
sed -i -e "s/FreeBSD 8.2/FreeBSD 9.1/" pkg-post.sh

sh createpkg9.sh && sh createclient9.sh && sh createitf9.sh
