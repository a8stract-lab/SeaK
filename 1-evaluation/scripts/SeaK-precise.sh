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
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/vanilla/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/vanilla.txt 1001
echo finished
cd ..

python3 scripts/phoronix_test.py seakvanilla
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakvanilla/composite.xml SeaK_phoronix/vanilla/result.txt


echo start_l2cap
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_uaf-l2cap_chan_close &
BPF_l2cap=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/l2cap/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/l2cap.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_l2cap

./bpf-evaluation/hotbpf_uaf-l2cap_chan_close &
BPF_l2cap=$!
python3 scripts/phoronix_test.py seakl2cap
kill -SIGINT $BPF_l2cap
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakl2cap/composite.xml SeaK_phoronix/l2cap/result.txt


echo start_seq
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_seq &
BPF_seq=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/seq/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/seq.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_seq

./bpf-evaluation/hotbpf_seq &
BPF_seq=$!
python3 scripts/phoronix_test.py seakseq
kill -SIGINT $BPF_seq
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakseq/composite.xml SeaK_phoronix/seq/result.txt


echo start_cred
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi

tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_cred &
BPF_cred=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/cred/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/cred.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_cred

./bpf-evaluation/hotbpf_cred &
BPF_cred=$!
python3 scripts/phoronix_test.py seakcred
kill -SIGINT $BPF_cred
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakcred/composite.xml SeaK_phoronix/cred/result.txt


echo start_sk_filter
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_sk_filter &
BPF_sk_filter=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/sk_filter/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/sk_filter.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_sk_filter

./bpf-evaluation/hotbpf_sk_filter &
BPF_sk_filter=$!
python3 scripts/phoronix_test.py seakskfilter
kill -SIGINT $BPF_sk_filter
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakskfilter/composite.xml SeaK_phoronix/sk_filter/result.txt


echo start_fdtable
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_fdtable &
BPF_fdtable=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/fdtable/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/fdtable.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_fdtable

./bpf-evaluation/hotbpf_fdtable &
BPF_fdtable=$!
python3 scripts/phoronix_test.py seakfdtable
kill -SIGINT $BPF_fdtable
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakfdtable/composite.xml SeaK_phoronix/fdtable/result.txt


echo start_file
if [ -d "lmbench" ]; then
	rm -r lmbench
else
	:
fi
tar -xvf lmbench.tar.gz
./bpf-evaluation/hotbpf_file &
BPF_file=$!
cd lmbench
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
make rerun
cd ..
mv lmbench/results/x86_64-linux-gnu/* SeaK_lmbench/file/

cd lmbench

cd ../lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/file.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_file

./bpf-evaluation/hotbpf_file &
BPF_file=$!
python3 scripts/phoronix_test.py seakfile
kill -SIGINT $BPF_file
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakfile/composite.xml SeaK_phoronix/file/result.txt


./bpf-evaluation/hotbpf_38_tests &
BPF_38_tests=$!
cd lmbench
make rerun &
python3 ../scripts/memory_overhead.py ../SeaK_memory_overhead/64AAs.txt 1001
echo finished
cd ..
kill -SIGINT $BPF_38_tests
