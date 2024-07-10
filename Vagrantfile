# -*- mode: ruby -*-
# vi: set ft=ruby :

host_os = case
when Vagrant::Util::Platform.linux?
  "Linux"
when Vagrant::Util::Platform.darwin?
  "Darwin"
else
  puts "ERROR: Host OS is not supported."
  abort
end

arch = case `uname -m`.strip
when "x86_64", "amd64"
  "amd64"
when "aarch64", "arm64"
  "arm64"
else
  puts "ERROR: Architecture is not supported."
  abort
end

vm_name = "ego-#{arch}-vm"

Vagrant.configure("2") do |config|
  case arch
  when "amd64"
     config.vm.box = "bento/ubuntu-24.04"
     config.vm.box_version = "202404.26.0"
  when "arm64"
    config.vm.box = "bento/ubuntu-22.04-arm64"
  end

  
  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:

  end


  config.vm.provision :shell, :privileged => false, :path => "scripts/install-ebpf-need.sh"
end
