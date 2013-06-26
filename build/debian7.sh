#!/bin/sh
set -x
version="3.0.39"
sh buildinit.sh debian7
sh debiancore.sh
mv debian.deb quadstor-core-$version-debian7-x86_64.deb
sh debianclient.sh
mv debian.deb quadstor-client-$version-debian7-x86_64.deb
sh debianitf.sh
mv debian.deb quadstor-itf-$version-debian7-x86_64.deb
