# Crash report analyzer for HotBPF

## Build
There is a docker machine with automated setup scripts, this repo directory is mapped to `/home/hotbpf/hot_bpf_analyzer/` in the docker container.
```
host$ docker compose up -d dev
host$ docker exec -it hot_bpf_analyzer-dev-1 /bin/bash

root@docker$ $BUILD_LLVM
root@docker$ $BUILD_ANALYZER
root@docker$ cd /home/hot_bpf_analyzer/sample/<SAMPLE_NAME>
root@docker$ ./build-kernel.sh
```

The following components will be built:
- LLVM 12.0.1 with a patched `clang` for generating bitcode
- Linux kernel built with customized `clang`
- Crash report analyzer for HotBPF built with the same `clang` as above

## Automated run
- Step 1: Find the addresses of all allocation sites and save to a file, can be done manually through cross-referencing in a disassembler or using `binja_get_allocs.py` script with a Binary Ninja personal license.
- Step 2: Put `linux/, linux-bitcode/, vmlinux_addrs.txt, report` in the same directory.
- Step 3: Run `python3 run_all.py <work_dir> <hotbpf_dir>`

## Step-by-step usage guide

### Analyzing the kernel
- Step 1: Get call graph of crash report: `python3 get_cg.py $SAMPLE_DIR/report`. This will result in a file called `report_cg.txt`
- Step 2: Put `linux-bitcode` directory in the same directory as `report_cg.txt`
- Step 3: Get analysis report: `python3 run_analyze.py $REPORT_CG_DIR`. This will result in a file called `sts.txt`

### Find allocation sites of objects
General command:
```
./analyzer -struct <struct_name> `find <bitcode_path>`
```

Example for `bug-kobject_add_internal` sample, the vulnearable object is `hci_conn`, we run:
```
/home/hotbpf/hot_bpf_analyzer/build/lib/analyzer -struct hci_conn  `find /home/hotbpf/linux-bitcode/net/bluetooth -name "*.bc"`
```

Output will be:
```
Total 38 file(s)
dumping location of allocating hci_conn
hci_conn_add net/bluetooth/hci_conn.c:525
Possible Caller for hci_conn_add
hci_connect_le_scan
hci_connect_sco
hci_conn_request_evt
hci_connect_acl
hci_cs_create_conn
le_conn_complete_evt
hci_conn_complete_evt
phylink_add
hci_connect_le
```

### Find kernel address from source lines
There are 2 files that needed to be run: `srcanalysis.py` will generate `line2bin.pickle`, a mapping between all allocation addresses and their corresponding lines in source; `src2addr.py` will lookup the mapping for the desired lines:
- Step 1: Find the addresses of all allocation sites and save to a file, can be done manually through cross-referencing in a disassembler or using `binja_get_allocs.py` script with a Binary Ninja personal license. Example for such file can be found in `bug-kobject_add_internal/vmlinux_addrs.txt`.
- Step 2: Run `srcanalysis.py`: `python3 ./hot_bpf_analyzer/srcanalysis.py <action> -a <path_to_alloc_addr_file> -k <path_to_vmlinux> -n <num_thread> [-d]`. This will result in a file called `line2bin.pickle`
- Step 3: Run `src2addr.py`: `python3 ./hot_bpf_analyzer/src2addr.py <action> -s <path_to_src_lines_file> -k <path_to_vmlinux> -m <path_to_line2bin_mapping>`

Example for `bug-kobject_add_internal` sample, we run:
- `python3 ./hot_bpf_analyzer/srcanalysis.py gen -a ./hot_bpf_analyzer/sample/bug-kobject_add_internal/vmlinux_addrs.txt -k ./linux/vmlinux`
- `python3 ./hot_bpf_analyzer/src2addr.py new -s ./hot_bpf_analyzer/sample/bug-kobject_add_internal/srclines.txt -k ./linux/vmlinux -m ./line2bin.pickle`

Output will be:
```
hci_conn_add+0x33
```
