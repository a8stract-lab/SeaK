KERNEL=./kernels/bzImage-SeaK
IMAGE=./bullseye.img
qemu-system-x86_64 \
    -m 2G \
    -smp 2 \
    -kernel $KERNEL \
    -append "nokaslr console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=$IMAGE,format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
    -net nic,model=e1000 \
    -nographic \
    -pidfile vm.pid \
    -enable-kvm \
    # -s -S \
#	2>&1 | tee vm.log
