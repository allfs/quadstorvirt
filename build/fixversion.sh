#!/bin/sh
set -x 
for i in `ls -1`; do
	sed -i -e "s/3.0.59/3.0.59/g" $i
	sed -i -e "s/3.0.59-x86_64/3.0.59-x86_64/g" $i
done
