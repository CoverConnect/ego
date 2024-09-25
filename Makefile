
all: 
	cd ./tracee && /home/momo/go/bin/go1.22.6 build . -buildvcs=false
	cd ./pkg/instrument && /home/momo/go/bin/go1.22.6 generate
	/home/momo/go/bin/go1.22.6 build

dump-map:
	sudo bpftool map dump name context_map
log:
	sudo bpftool prog tracelog

run-env:
	qemu-system-x86_64 \
	-display none                                          \
	-m 16G                                                          \
	-smp 6                                                         \
	-hda vmdisk.qcow2                                            \
	-netdev user,id=net0,net=192.168.0.0/24,dhcpstart=192.168.0.9  \
	-device virtio-net-pci,netdev=net0                             \
	-device e1000,netdev=net1           \
	-virtfs local,path=/Users/c-yeh/workspace/ego,mount_tag=host_folder,security_model=mapped,id=hostfolder \
	-netdev user,id=net1,hostfwd=tcp::5555-:22

build-env:
	qemu-system-x86_64 \
	-accel hvf                                                    \
	-m 16G                                                          \
	-smp 6                                                         \
	-hda vmdisk.qcow2                                            \
	-cdrom ubuntu22_24.iso                  \
	-netdev user,id=net0,net=192.168.0.0/24,dhcpstart=192.168.0.9  \
	-device virtio-net-pci,netdev=net0                             \
	                                                      \
	-device e1000,netdev=net1           \
	-netdev user,id=net1,hostfwd=tcp::5555-:22



create_disk:
	rm vmdisk.qcow2
	qemu-img create -f qcow2 vmdisk.qcow2 16G

ssh:
	ssh backman@localhost -p 5555
