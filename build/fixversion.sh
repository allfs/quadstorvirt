#!/bin/sh
set -x 
for i in `ls -1`; do
	sed -i -e "s/3.0.58/3.0.58/g" $i
	sed -i -e "s/3.0.58-x86_64/3.0.58-x86_64/g" $i
done
