#!/bin/bash

BUILD_DIR=/home/hotbpf
KERNEL_GIT_URL=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
KERNEL_COMMIT=d6efb3ac3e6c19ab722b28bdb9252bae0b9676b6

LLVM_BUILD=/home/hotbpf/llvm-project/build

if [ ! -d $BUILD_DIR/linux ]; then
    mkdir -p ${BUILD_DIR}/linux
    git clone ${KERNEL_GIT_URL} ${BUILD_DIR}/linux
    pushd $BUILD_DIR/linux
    git checkout ${KERNEL_COMMIT}
    patch -p1 < /home/hotbpf/hot_bpf_analyzer/patch/kernel_stpcpy_error.patch
    popd
else
    pushd $BUILD_DIR/linux
    make clean
    git checkout ${KERNEL_COMMIT}
    patch -p1 < /home/hotbpf/hot_bpf_analyzer/patch/kernel_stpcpy_error.patch
    popd
fi

if [ ! -d $BUILD_DIR/linux-bitcode ]; then
    mkdir -p ${BUILD_DIR}/linux-bitcode
fi

cp $BUILD_DIR/hot_bpf_analyzer/sample/bug-kobject_add_internal/config $BUILD_DIR/linux/.config

pushd $BUILD_DIR/linux
yes "" | make CC="/home/hotbpf/llvm-project/build/bin/clang" olddefconfig
make CC="/home/hotbpf/llvm-project/build/bin/clang" -j`nproc`

# Copy all bitcode files out while keeping directory structure
find . -name '*.bc' -exec cp --parents \{\} ..//linux-bitcode \;
popd
