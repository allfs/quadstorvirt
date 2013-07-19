#!/bin/bash
set -x 

root=`pwd`

cd $root/scctl
./scctl -u
sleep 4

cd $root/masterd
sh unload.sh

sleep 2

cd $root
/sbin/rmmod ldev 
/sbin/rmmod coredev 

sudo /quadstor/pgsql/etc/pgsql stop

sudo /sbin/rmmod netconsole
