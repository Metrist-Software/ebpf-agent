#!/usr/bin/env sh
#
# Run a build through Vagrant. The actual build steps are on do-build.sh
#

set -e
set -vx

dist=$1
ver=$2
base=$(cd $(dirname $0); /bin/pwd)

case $dist:$ver in
    ubuntu:20.04)
        # We can use the main vagrant file
        vagrantfile=$base/../Vagrantfile
        ;;
    *)
        echo "Unknown distribution/version"
        exit 1
        ;;
esac

vagrant ssh -- "/vagrant/dist/do-build.sh $1 $2"

pkg=$(cat pkg/$dist-$ver)
arch=$(uname -m) # Really should come from the machine once we target ARM etc

gpg --sign --armor --detach-sign pkg/$pkg

aws s3 cp pkg/$pkg s3://dist.metrist.io/orchestrator-plugins/ebpf/$dist/
aws s3 cp pkg/$pkg.asc s3://dist.metrist.io/orchestrator-plugins/ebpf/$dist/
aws s3 rm s3://dist.metrist.io/orchestrator-plugins/ebpf/$dist/$dist-$ver.latest.txt
echo $pkg | aws s3 cp - s3://dist.metrist.io/orchestrator-plugins/ebpf/$dist/$ver.$arch.latest.txt
