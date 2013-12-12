#!/bin/sh
set -x 
for i in `ls -1`; do
	sed -i -e "s/3.0.56/3.0.56/g" $i
	sed -i -e "s/3.0.56-x86_64/3.0.56-x86_64/g" $i
done
