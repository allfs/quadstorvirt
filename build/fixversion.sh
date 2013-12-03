#!/bin/sh
set -x 
for i in `ls -1`; do
	sed -i -e "s/3.0.54/3.0.54/g" $i
	sed -i -e "s/3.0.54-x86_64/3.0.54-x86_64/g" $i
done
