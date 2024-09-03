
all: 
	cd ./tracee && go build .
	cd ./pkg/instrument && go generate
	go build

dump-map:
	sudo bpftool map dump name context_map
log:
	sudo bpftool prog tracelog

run-env:
	qemu-system-x86_64 \
	-accel hvf           \
	-display none                                          \
	-m 16G                                                          \
	-smp 6                                                         \
	-hda vmdisk.qcow2                                            \
	-netdev user,id=net0,net=192.168.0.0/24,dhcpstart=192.168.0.9  \
	-device virtio-net-pci,netdev=net0                             \
	-device e1000,netdev=net1           \
	-netdev user,id=net1,hostfwd=tcp::5555-:22\

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
