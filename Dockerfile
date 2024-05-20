FROM debian:bullseye-slim

SHELL ["/bin/bash", "-c"]
ENTRYPOINT ["/bin/bash"]
WORKDIR /home/hotbpf/

ENV BUILD_ANALYZER=/home/hotbpf/hot_bpf_analyzer/scripts/build_analyzer.sh \
    BUILD_LLVM=/home/hotbpf/hot_bpf_analyzer/scripts/build_llvm.sh

RUN apt-get update; \
  apt-get install -y --no-install-recommends \
    cmake ninja-build python3 python3-pip wget unzip\
    build-essential ca-certificates\
    make m4 curl \
    flex bison fakeroot bc kmod cpio libssl-dev libelf-dev \
    git pkg-config libssl-dev; \
    
RUN pip3 install tqdm scikit-learn celery
