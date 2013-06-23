#!/bin/bash
set -x

cd ./usr 
#sudo ./ietadm --op delete >/dev/null 2>/dev/null
sudo killall ietd 2> /dev/null

#sudo pkill ietd
sudo /sbin/rmmod iscsit.ko
sudo /sbin/rmmod crypto
