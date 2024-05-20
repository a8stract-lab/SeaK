from utility import runCommand
import sys

if len(sys.argv) != 3:
    print("sys.argv[1] = location of the directory containing linux/, linux-bitcode/, vmlinux_addrs.txt, report")
    print("sys.argv[2] = location of hot_bpf_analyzer")
    sys.exit()

rootdir = sys.argv[1]
hotbpf = sys.argv[2]
report = rootdir + "/report"
vmlinux = rootdir + "/linux/vmlinux"
bitcode = rootdir + "/linux-bitcode"
vmlinux_addrs = rootdir + "/vmlinux_addrs.txt"
structs = rootdir + "/sts.txt"
srclines = rootdir + "/srclines.txt"
srcmapping = rootdir + "/line2bin.pickle"

# Run get_cg.py
print("[*] Getting call graph from crash report")
runCommand("python3 {}/get_cg.py {}".format(hotbpf, report))

# Run struct finder
print("[*] Finding vulnerable objects")
runCommand("python3 {}/run_analyze.py {}".format(hotbpf, rootdir))

# Run allocation finder
print("[*] Finding vulnerable allocation sites")
sts = open(structs, "r")
alloc_sites = []
for line in sts:
    line = line.strip()
    ret, out, err = runCommand("{}/build/lib/analyzer -struct {}  `find {} -name \"*.bc\"`".format(hotbpf, line, bitcode))
    lines = err.split('\n')
    for i in range(len(lines)):
        if "Possible Caller" in lines[i]:
            alloc_sites += [lines[i-1]]

with open(srclines, "w") as f:
    for s in alloc_sites:
        f.write(s + "\n")

# Run srcanalysis
print("[*] Mapping all allocation sites to source (might take a while)")
runCommand("python3 {}/srcanalysis.py gen -a {} -k {} -n `nproc`".format(hotbpf, vmlinux_addrs, vmlinux), "stdout")

# Run src2binaddr
print("[*] Looking up vulnerable allocation sites in binary")
ret, out, err = runCommand("python3 {}/src2addr.py new -s {} -k {} -m {}".format(hotbpf, srclines, vmlinux, srcmapping))

print("[*] Result:")
print(out)
