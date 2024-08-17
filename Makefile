
all: 
	make tracee
	go generate && go build

dump-map:
	sudo bpftool map dump name context_map
log:
	sudo bpftool prog tracelog

tracee:
	cd ./tracee && go build .


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
	curl https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso?_ga=2.142890165.1432353644.1720835055-855202174.1719714410&_gl=1*1w1zd4n*_gcl_au*MTMxNzc0NzY3NS4xNzIwODM1MDgx -o ubuntu22_24.iso \
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
