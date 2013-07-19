#!/bin/sh
set -x

cd /quadstor/quadstor/scctl/
./scctl -u
sleep 4

cd /quadstor/quadstor/masterd
sh unload.sh
sleep 4

/sbin/kldunload ldev 
/sbin/kldunload coredev 

/quadstor/pgsql/etc/pgsql stop
cd /quadstor/quadstor
