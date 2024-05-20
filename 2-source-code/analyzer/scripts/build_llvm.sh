#!/bin/bash

BUILD_DIR=/home/hotbpf

pushd /home/hotbpf
if [ ! -d $BUILD_DIR/llvm-project ]; then
    wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-12.0.1.zip
    unzip -q llvmorg-12.0.1.zip
    mv llvm-project-* llvm-project
    rm llvmorg-12.0.1.zip
    # git clone https://github.com/llvm/llvm-project
    # pushd llvm-project
    # git checkout 5521236a18074584542b81fd680158d89a845fca
    # patch -p1 < /home/hotbpf/hot_bpf_analyzer/patch/WriteBitcode.patch
    # popd
fi

pushd llvm-project
cp -r /home/hotbpf/analyzer/patch/llvm .

mkdir build && cd build
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DLLVM_ENABLE_PROJECTS=clang \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -Wno-dev \
    ../llvm

ninja
popd
popd