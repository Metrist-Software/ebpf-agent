# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2004"
  # Libvirt is preferred given issues around VirtualBox, Oracle licensing, and
  # commercial use we need to sort out first.
  config.vm.provider "libvirt" do |vm|
    vm.memory = "8192"
    vm.cpus = 8
    vm.memorybacking :access, :mode => "shared"
  end
  config.vm.synced_folder "./", "/vagrant", type: "virtiofs"

  config.vm.provision "shell", inline: <<-SHELL
    set -vx
    DEBIAN_FRONTEND=noninteractive
    export CMAKE_BUILD_PARALLEL_LEVEL=8

    # Basic stuff
    apt-get update
    apt-get install -y build-essential curl sudo zstd git curl unzip wget pkg-config ripgrep entr cmake ruby
    gem install fpm

    # LLVM.
    sudo apt-get -y install zlib1g-dev linux-headers-$(uname -r) libelf-dev gcc-multilib
    # For BPF, we need clang-13 which is not on Apt so we go from source.
    [ -f /opt/llvm-13/bin/llvm-config ] || {
      cd /tmp
      git clone -b release/13.x --single-branch --depth 1 https://github.com/llvm/llvm-project
      cd llvm-project
      mkdir build
      cd build
      cmake ../llvm -DCMAKE_INSTALL_PREFIX=/opt/llvm-13 -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang
      cmake --build . --target install
      cp bin/FileCheck /opt/llvm-13/bin

      # Cargo-bpf wants to link against libLLVM-13 which does not exist. It gets created if we generate a dynamic
      # library, but then both static and dynamic libraries end up in cargo-bpf and that gives run-time errors around
      # duplicate symbols. This hack creates the library that works.
      cd /opt/llvm-13/lib
      echo 'create libLLVM-13.a' >/tmp/makelib.m
      ls libLLVM*.a | awk '{print "addlib "  $1}' >>/tmp/makelib.m
      echo 'save' >>/tmp/makelib.m
      echo 'end' >>/tmp/makelib.m
      ar -M </tmp/makelib.m
      cat >>/home/vagrant/.profile <<EOF
export LLVM_SYS_130_PREFIX=/opt/llvm-13
PATH=/opt/llvm-13/bin:\$PATH
ulimit -n 1048576
cd /vagrant
EOF
    }

    export LLVM_SYS_130_PREFIX=/opt/llvm-13
    PATH=/opt/llvm-13/bin:$PATH

    cat <<EOF >/tmp/install.sh
    set -vx
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >/tmp/install-rust.sh
    chmod +x /tmp/install-rust.sh
    /tmp/install-rust.sh -y
    . ~/.profile # to pick up the changes that cargo makes
    rustup default 1.56
    cargo install cargo-bpf --git https://github.com/redsift/redbpf
EOF
    chmod +x /tmp/install.sh
    sudo -iu vagrant /tmp/install.sh
  SHELL
end
