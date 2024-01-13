#!/usr/bin/env sh
#
#  This script runs inside a Vagrant VM to build a package.
#
#
#  Build the code and tag it with distribution $2 and version $3
#
set -e
set -vx

. ~/.profile

base=/vagrant
dist=$1
ver=$2
rel=$base/dist/$dist/$ver

cd $base
tag=$(git rev-parse --short HEAD)

[ -d target ] && rm -rf target
make release

plugin_ver=$(grep version Cargo.toml | head -1 | awk '{print $3}' | sed 's/"//g')

dest=/tmp/pkgbuild
[ -e $dest ] && rm -rf $dest
mkdir -p $dest

pkg_dest=/tmp/pkgout
[ -e $pkg_dest ] && rm -rf $pkg_dest
mkdir -p $pkg_dest


# Copy the binary over
mkdir -p $dest/usr/bin
cp target/release/metrist-ebpf-agent $dest/usr/bin/


# Copy anything else we want to include over. We remove `.gitkeep` files
# because that is cleaner
(cd $rel/inc; cp -rv . $dest/)

# Build the package. Distribution-method specific arguments MUST
# be in the `fpm.cmd` file in the rel directory. At a minimum, this
# should contain something like "-t deb"
cd $dest
fpm --verbose -s dir \
    $(cat $rel/fpm.cmd) \
    --license "APSLv2" \
    --vendor "Metrist Software, Inc." \
    --provides metrist-ebpf-agent \
    -m "Metrist Software, Inc. <support@metrist.io>" \
    -n metrist-ebpf-agent \
    -v $plugin_ver-$dist-$ver-$tag \
    -a native \
    -p $pkg_dest \
    .

pkg=$(cd $pkg_dest; ls)

mkdir -p $base/pkg
cp $pkg_dest/$pkg $base/pkg
echo $pkg >$base/pkg/$dist-$ver
