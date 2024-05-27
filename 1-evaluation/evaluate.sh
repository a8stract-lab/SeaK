#!/bin/bash

# create image
#./create-image.sh
sudo rm -r lmbench

unzip lmbench.zip

gnome-terminal --title="terminal1: RUN VM & POC here"  -- ./run.sh 
sleep 20

## copy necessary files
./copy2vm ../2-source-code/POCs
./copy2vm ./scripts

gnome-terminal --title="terminal2: RUN BPF & MONITOR OUTPUT here" -- ./connect2vm.sh

