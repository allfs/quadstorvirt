#!/bin/sh
cp -f /quadstor/etc/quadstor /etc/rc.d/
chmod +x /quadstor/etc/quadstor
chmod +x /quadstor/lib/modules/*

cp -f /quadstor/lib/modules/ispmod.ko /boot/kernel/
chmod +x /quadstor/lib/modules/ispmod.ko

exit 0
