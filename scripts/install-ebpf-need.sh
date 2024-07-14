#!/bin/bash

set -eux

#mkdir /etc/gcrypt
#echo all >> /etc/gcrypt/hwf.deny
#apt-get update


sudo apt-get update

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 all


sudo apt-get install -y bpfcc-tools "linux-headers-$(uname -r)"
sudo apt-get install -y zsh
sudo apt-get install -y libbpf-dev

sudo apt install -y  pkg-config
sudo apt-get install -y zlib1g-dev


sudo apt install -y zip bison build-essential cmake flex git libedit-dev  zlib1g-dev libelf-dev libfl-dev python3-setuptools liblzma-dev arping netperf iperf python3 

sudo git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
sudo git submodule update --init --recursive 


git clone --recurse-submodules https://github.com/libbpf/bpftool.git
sudo ln -s /usr/bin/clang-17 /usr/bin/clang
sudo ln -s /usr/bin/llvm-strip-17 /usr/bin/llvm-strip

cd ./bpftool/src && sudo make install

