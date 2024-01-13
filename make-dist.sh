#!/usr/bin/env bash

set -eo pipefail
set -vx

arch=$(uname -m)
version=$(grep ^version Cargo.toml | sed 's/[^0-9.]//g')
tag=$(git rev-parse --short HEAD)
name=metrist-ebpf-agent
bucket=s3://dist.metrist.io/orchestrator-plugins/ebpf/

fullname=$name-$arch-$version-$tag

rm -rf target
vagrant ssh -c "make release"
cd target/release
strip metrist-ebpf-agent
tar cvfz $fullname.tar.gz $name
gpg --sign --armor --detach-sign $fullname.tar.gz
echo $fullname >latest-$arch.txt

aws s3 cp $fullname.tar.gz $bucket
aws s3 cp $fullname.tar.gz.asc $bucket
aws s3 cp latest-$arch.txt $bucket
