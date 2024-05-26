#!/bin/bash
cd ..
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* EF_lmbench/C2/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../EF_memory_overhead/C2.txt 1001
echo finished
cd ..

python3 scripts/phoronix_test.py efc2
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/efc2/composite.xml EF_phoronix/C2/result.txt

