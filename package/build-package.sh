#!/bin/bash
# Builds the smbfs package on Haiku. Run from anywhere; requires haiku_devel.
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=$(grep '^version' package/PackageInfo | awk '{print $2}')
ARCH=$(getarch)

echo "Building the kernel add-on..."
make -C src/kernel
echo "Building mount_smbfs..."
make -C src/mount_smbfs
echo "Building SMBMounter..."
make -C src/SMBMounter

PKG=$ROOT/package/pkg
rm -rf "$PKG"
mkdir -p "$PKG/add-ons/kernel/file_systems" "$PKG/bin" "$PKG/apps" \
	"$PKG/add-ons/Tracker" "$PKG/data/deskbar/menu/Applications" \
	"$PKG/documentation/packages/smbfs"

cp src/kernel/objects/smbfs "$PKG/add-ons/kernel/file_systems/smbfs"
cp src/mount_smbfs/objects.*/mount_smbfs "$PKG/bin/mount_smbfs"
cp src/SMBMounter/objects.*/SMBMounter "$PKG/apps/SMBMounter"
ln -s ../../apps/SMBMounter "$PKG/add-ons/Tracker/SMBMounter"
ln -s ../../../../apps/SMBMounter "$PKG/data/deskbar/menu/Applications/SMBMounter"
cp README.md "$PKG/documentation/packages/smbfs/README.md"
cp LICENSE "$PKG/documentation/packages/smbfs/LICENSE"
sed "s/^architecture.*/architecture\t$ARCH/" package/PackageInfo > "$PKG/.PackageInfo"

OUT=$ROOT/package/smbfs-$VERSION-$ARCH.hpkg
rm -f "$OUT"
(cd "$PKG" && package create -q "$OUT")
echo "Created $OUT"
echo "Install with: pkgman install $OUT"
