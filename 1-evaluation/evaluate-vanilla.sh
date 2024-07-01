#!/bin/bash

# create image
#./create-image.sh
chmod +x *.sh
if [ -d "kernels" ]; then
	rm -r kernels
else
	:
fi
tar -xvf kernels.tar.xz
screen -d -m -S virtual-machine ./run-vanilla.sh
sleep 20
./copy2vm.sh ../2-source-code/POCs
./copy2vm.sh ./scripts

screen -r virtual-machine
