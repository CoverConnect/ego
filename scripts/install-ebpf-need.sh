#!/bin/bash

sudo apt-get update

# install llvm
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 all


# build for libbpf
sudo apt-get install -y bpfcc-tools "linux-headers-$(uname -r)"
sudo apt-get install -y zsh
sudo apt-get install -y libbpf-dev
sudo apt install -y  pkg-config
sudo apt-get install -y zlib1g-dev
sudo apt install -y zip bison build-essential cmake flex git libedit-dev  zlib1g-dev libelf-dev libfl-dev python3-setuptools liblzma-dev arping netperf iperf python3 

git clone https://github.com/libbpf/libbpf.git
sudo cd libbpf/src && sudo make install


# build bpftool
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd ./bpftool/src && sudo make install

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
sudo ln -s /usr/bin/clang-17 /usr/bin/clang
sudo ln -s /usr/bin/llvm-strip-17 /usr/bin/llvm-strip