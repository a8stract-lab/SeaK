cmd_/usr/src/linux-5.15.106/samples/bpf/hotbpf_gpf-vb2_mmap := gcc -Wp,-MD,/usr/src/linux-5.15.106/samples/bpf/.hotbpf_gpf-vb2_mmap.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I./tools/testing/selftests/bpf/ -I/usr/src/linux-5.15.106/samples/bpf/libbpf/include -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0   -o /usr/src/linux-5.15.106/samples/bpf/hotbpf_gpf-vb2_mmap /usr/src/linux-5.15.106/samples/bpf/hotbpf_gpf-vb2_mmap_user.o /usr/src/linux-5.15.106/samples/bpf/libbpf/libbpf.a -lelf -lz 