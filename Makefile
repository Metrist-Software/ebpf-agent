
BPF_BLOB := target/bpf/programs/tls_mon/tls_mon.elf
EXE := target/debug/metrist-ebpf-agent

# Note: most of these targets should run inside the Vagrant VM,
# unless you have everything setup on the host level.

all: build

build: probes prog

run: build
	sudo $(EXE)

release: build
	cargo build --release

trace_run: build
	sudo strace $(EXE)

probes: $(BPF_BLOB)

prog: $(EXE)

$(EXE): ${BPF_BLOB} Cargo.* src/*.rs
	cargo build

H2_DEPS != find h2 | grep -v target
$(BPF_BLOB): probes/Cargo.* probes/src/*.rs probes/src/*/*.rs $(H2_DEPS)
	cd probes; cargo bpf build --target-dir ../target

# Setup stuff follows.

.ONESHELL:
dev:
	# Even though we build in a VM, you want Rust and the Rust Language Server on the host.
	which cargo || (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)
	. ~/.cargo/env
	rustup component add rls
	# This is where the real work happens, the rest is in the Vagrantfile.
	which vagrant || make install_vagrant
	# We want libvirt (Qemu/kvm) because virtualbox in a commercial setting is problematic with Oracle around.
	vagrant up --provider=libvirt --provision

install_libvirt:
	sudo apt install qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils virtinst libvirt-daemon
	sudo systemctl enable --now libvirtd

install_vagrant: install_libvirt
	sudo apt update && sudo apt install vagrant vagrant-libvirt

# Utility targets.

watch_build:
	find Makefile Cargo* src probes h2 | entr vagrant ssh -- ". .profile; make -C /vagrant"

tail_log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

shell:
	-vagrant ssh

.PHONY: dist
dist:
	./make-dist.sh

# These are just quick and simple test commans, mostly here as executable documentation
# We use ipinfo.io because it supports both protocols and returns small answers which
# is nicer for debugging

# Test one request on HTTP/1.1
test_one_one:
	curl -v --http1.1 'https://ipinfo.io/1.2.3.4/geo' >/dev/null

# Test one request on HTTP/2
test_one_two:
	curl -v 'https://ipinfo.io/1.2.3.4/geo' >/dev/null

# Test multiple requests on HTTP/1.1
test_multi_one:
	curl -vs --http1.1 'https://ipinfo.io/{1.2.3.4,5.6.7.8,9.10.11.12}/geo' >/dev/null

# Test multiple requests on HTTP/2
test_multi_two:
	curl -vs 'https://ipinfo.io/{1.2.3.4,5.6.7.8,9.10.11.12}/geo' >/dev/null
