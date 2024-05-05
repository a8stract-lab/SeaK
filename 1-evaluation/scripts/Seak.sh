#!/bin/bash
cd ..
echo start_vanilla
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
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/vanilla/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/vanilla.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..

python3 scripts/phoronix_test.py Seak_vanilla
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_vanilla/composite.xml Seak_phoronix/vanilla/result.txt


echo start_l2cap
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf/hotbpf_uaf_l2cap_chan_close &
BPF_l2cap=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/l2cap/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/l2cap.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_l2cap

./bpf/hotbpf_uaf_l2cap_chan_close &
BPF_l2cap=$!
python3 scripts/phoronix_test.py Seak_l2cap
kill $BPF_l2cap
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_l2cap/composite.xml Seak_phoronix/l2cap/result.txt


echo start_seq
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf/hotbpf_seq &
BPF_seq=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/seq/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/seq.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_seq

./bpf/hotbpf_seq &
BPF_seq=$!
python3 scripts/phoronix_test.py Seak_seq
kill $BPF_seq
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_seq/composite.xml Seak_phoronix/seq/result.txt


echo start_cred
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi

tar -xvf lmbench.tar.gz
./bpf/hotbpf_cred &
BPF_cred=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/cred/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/cred.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_cred

./bpf/hotbpf_cred &
BPF_cred=$!
python3 scripts/phoronix_test.py Seak_cred
kill $BPF_cred
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_cred/composite.xml Seak_phoronix/cred/result.txt


echo start_sk_filter
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf/hotbpf_sk_filter &
BPF_sk_filter=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/sk_filter/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/sk_filter.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_sk_filter

./bpf/hotbpf_sk_filter &
BPF_sk_filter=$!
python3 scripts/phoronix_test.py Seak_sk_filter
kill $BPF_sk_filter
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_sk_filter/composite.xml Seak_phoronix/sk_filter/result.txt


echo start_fdtable
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf/hotbpf_fdtable &
BPF_fdtable=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/fdtable/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/fdtable.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_fdtable

./bpf/hotbpf_fdtable &
BPF_fdtable=$!
python3 scripts/phoronix_test.py Seak_fdtable
kill $BPF_fdtable
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_fdtable/composite.xml Seak_phoronix/fdtable/result.txt


echo start_file
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf/hotbpf_file &
BPF_file=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* Seak_lmbench/file/

cd lmbench

python3 ../scripts/memory_overhead.py ../Seak_memory_overhead/file.txt &
MEMORY_PID=$!
make rerun
sleep 1200
kill $MEMORY_PID
cd ..
kill $BPF_file

./bpf/hotbpf_file &
BPF_file=$!
python3 scripts/phoronix_test.py Seak_file
kill $BPF_file
python3 scripts/phronix_parse.py /var/lib/phoronix-test-suite/test-results/Seak_file/composite.xml Seak_phoronix/file/result.txt

