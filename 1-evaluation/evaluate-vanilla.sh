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
gnome-terminal --title="terminal1: RUN VM & POC here"  -- ./run-vanilla.sh 
sleep 20
./copy2vm.sh ../2-source-code/POCs
./copy2vm.sh ./scripts
gnome-terminal --title="terminal2: RUN BPF & MONITOR OUTPUT here" -- ./connect2vm.sh

