#!/bin/sh
set -x
curdir=`pwd`
sh buildinit.sh bsd
cd /quadstor/quadstor/pgsql && gmake install
cd $curdir
sh createpkg.sh && sh createclient.sh && sh createitf.sh
