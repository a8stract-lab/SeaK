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

python3 ../scripts/memory_overhead.py ../EF_memory_overhead/C2.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..

python3 scripts/phoronix_test.py EF_C2
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/EF_C2/composite.xml EF_phoronix/C2/result.txt

