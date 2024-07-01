#!/bin/bash

# create image
#./create-image.sh

screen -d -m -S virtual-machine ./run-C2.sh
sleep 20
./copy2vm.sh ../2-source-code/POCs
./copy2vm.sh ./scripts

screen -r virtual-machine
