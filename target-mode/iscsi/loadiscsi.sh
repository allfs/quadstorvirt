#!/bin/bash
set -x

#sudo /sbin/insmod crypto/crypto.o
sudo /sbin/modprobe crypto
#sudo /sbin/insmod kernel/iscsi_trgt.ko debug_enable_flags=1
sudo /sbin/insmod kernel/iscsit.ko

cd ./usr 
#sudo ./ietd  -d 3 -c /quadstor/conf/iscsi.conf
ulimit -c unlimited
sudo ./ietd  -d 3 -c /quadstor/conf/iscsi.conf
#sudo ./ietd  -c /quadstor/conf/iscsi.conf
