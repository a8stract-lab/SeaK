#!/bin/bash
cd ..
./bpf/hotbpf_38_tests &
BPF_38_tests=$!
cd lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/64AAs.txt 1001
echo finished
cd ..
kill SIGINT $BPF_38_tests
