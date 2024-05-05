#!/bin/bash
python3 Seak_lmbench.py
python3 Seak_phoronix.py

mkdir ../Seak_memory_overhead/durable
mv ../Seak_memory_overhead/cred.txt ../Seak_memory_overhead/durable
mv ../Seak_memory_overhead/fdtable.txt ../Seak_memory_overhead/durable
mv ../Seak_memory_overhead/sk_filter.txt ../Seak_memory_overhead/durable

python3 merge.py
rm ../Seak_memory_overhead/durable
python3 Seak_memory_overhead.py
