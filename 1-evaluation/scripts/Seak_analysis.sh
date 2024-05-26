#!/bin/bash
python3 SeaK_lmbench.py
python3 SeaK_phoronix.py

mkdir ../SeaK_memory_overhead/durable
mv ../SeaK_memory_overhead/cred.txt ../SeaK_memory_overhead/durable
mv ../SeaK_memory_overhead/fdtable.txt ../SeaK_memory_overhead/durable
mv ../SeaK_memory_overhead/sk_filter.txt ../SeaK_memory_overhead/durable

python3 merge.py
mv ../SeaK_memory_overhead/durable ../
rm -r ../SeaK_memory_overhead/durable
python3 SeaK_memory_overhead.py
