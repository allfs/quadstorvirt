#!/bin/sh
set -x
version="3.0.51"
sh buildinit.sh debian6
sh debiancore.sh
mv debian.deb quadstor-core-$version-debian6-x86_64.deb
sh debianclient.sh
mv debian.deb quadstor-client-$version-debian6-x86_64.deb
sh debianitf.sh
mv debian.deb quadstor-itf-$version-debian6-x86_64.deb
sh debianitfmin.sh
mv debian.deb quadstor-itf-minimal-$version-debian6-x86_64.deb
