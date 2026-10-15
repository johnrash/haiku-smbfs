#!/bin/bash
# End-to-end test of the smbfs kernel add-on on Haiku, using ordinary
# commands on a mounted share.
#
# usage: vm-test.sh //server/share user password [extra mount options]
set -u
UNC=$1; USER_=$2; PASS=$3; EXTRA=${4:-}
MP=/boot/home/smbfs-test-mnt
FAIL=0
check() { if [ "$1" -ne 0 ]; then echo "FAIL: $2"; FAIL=$((FAIL+1)); else echo "ok: $2"; fi; }

# Build the Tracker-style copy helper before mounting, so that its own disk
# writes do not keep the page writer busy during the copy checks below.
C=/tmp/smbfs-copy-$$
mkdir -p "$C"
COPYORDER=""
g++ -o "$C/copyorder" "$(dirname "$0")/copyorder.cpp" -lbe 2>/dev/null \
	&& COPYORDER="$C/copyorder"

mkdir -p "$MP"
mount -t smbfs -p "$UNC user=$USER_ password=$PASS $EXTRA" "$MP"
check $? "mount"
[ $FAIL -ne 0 ] && exit 1

D="$MP/vmtest-$$"
mkdir "$D"; check $? "mkdir"
# Copies that keep permissions and times (Tracker, cp -p) set them while the
# file is still open and its data is still in Haiku's cache. The data must
# reach the server even for read-only files, and the times must survive.
# Checked after remounting, so everything is read back from the server.
# Runs first, on an idle mount: while the page writer is busy with earlier
# writes it may write the data early and hide data loss.
printf 'read-only source file\n' > "$C/ro.txt"
printf 'writable source file\n' > "$C/rw.txt"
touch -d "2024-03-16 13:13:28" "$C/ro.txt" "$C/rw.txt"
chmod 444 "$C/ro.txt"
mkdir "$D/copies"
cp -p "$C/ro.txt" "$C/rw.txt" "$D/copies/"; check $? "cp -p of read-only and writable files"
COPIES="ro rw"
if [ -n "$COPYORDER" ]; then
	"$COPYORDER" "$C/ro.txt" "$D/copies/tracker-ro.txt"; check $? "Tracker-style copy of a read-only file"
	"$COPYORDER" "$C/rw.txt" "$D/copies/tracker-rw.txt"; check $? "Tracker-style copy of a writable file"
	COPIES="ro rw tracker-ro tracker-rw"
else
	echo "note: g++ not available, Tracker-style copies skipped"
fi
unmount "$MP"; check $? "unmount to drop cached data"
mount -t smbfs -p "$UNC user=$USER_ password=$PASS $EXTRA" "$MP"; check $? "mount again"
for f in $COPIES; do
	src="$C/${f#tracker-}.txt"
	cmp "$src" "$D/copies/$f.txt"; check $? "$f: content on the server"
	[ "$(stat -c %Y "$D/copies/$f.txt")" = "$(stat -c %Y "$src")" ]; check $? "$f: modification time kept"
done
[ ! -w "$D/copies/ro.txt" ] && [ -w "$D/copies/rw.txt" ]; check $? "read-only flag copied"
chmod u+w "$D"/copies/*.txt && rm -r "$D/copies"; check $? "remove copies"
rm -rf "$C"
echo "hello from haiku" > "$D/a.txt"; check $? "create file"
[ "$(cat "$D/a.txt")" = "hello from haiku" ]; check $? "read back"
echo "more" >> "$D/a.txt"; [ "$(wc -l < "$D/a.txt")" -eq 2 ]; check $? "append"
head -c 8388608 /dev/urandom > /tmp/smbfs-big.bin
cp /tmp/smbfs-big.bin "$D/big.bin"; check $? "copy 8 MiB file"
cmp /tmp/smbfs-big.bin "$D/big.bin"; check $? "compare 8 MiB file"
[ "$(stat -c %s "$D/big.bin")" -eq 8388608 ]; check $? "stat size"
cp "$D/big.bin" /tmp/smbfs-big2.bin && cmp /tmp/smbfs-big.bin /tmp/smbfs-big2.bin; check $? "copy back and compare"
mv "$D/a.txt" "$D/b.txt"; check $? "rename"
[ ! -e "$D/a.txt" ] && [ -e "$D/b.txt" ]; check $? "rename result"
mkdir "$D/sub"; mv "$D/b.txt" "$D/sub/"; [ -e "$D/sub/b.txt" ]; check $? "move into subdirectory"
mv "$D/sub" "$D/sub2"; [ -e "$D/sub2/b.txt" ]; check $? "rename directory"
touch -d "2001-09-09 01:46:40" "$D/sub2/b.txt" && [ "$(stat -c %Y "$D/sub2/b.txt")" = "1000000000" ]; check $? "set mtime"
chmod 444 "$D/sub2/b.txt" && [ ! -w "$D/sub2/b.txt" ]; check $? "set read-only"
chmod 644 "$D/sub2/b.txt" && [ -w "$D/sub2/b.txt" ]; check $? "clear read-only"
cp -r /boot/system/develop/headers/os/support "$D/tree"; check $? "copy directory tree"
diff -r /boot/system/develop/headers/os/support "$D/tree" > /dev/null; check $? "compare directory tree"
N=$(ls "$D/tree" | wc -l); M=$(ls /boot/system/develop/headers/os/support | wc -l); [ "$N" -eq "$M" ]; check $? "directory listing count ($N)"
rmdir "$D/sub2" 2>/dev/null; [ $? -ne 0 ]; check $? "rmdir non-empty fails"
rm "$D/sub2/b.txt" && rmdir "$D/sub2"; check $? "remove file and directory"
rm -r "$D/tree"; check $? "remove tree"
rm "$D/big.bin"; check $? "remove big file"
ls "$D/big.bin" 2>/dev/null; [ $? -ne 0 ]; check $? "removed file is gone"
df "$MP" | grep -q smbfs; check $? "df shows smbfs"
# parallel writers and readers (Tracker is multi-threaded)
head -c 4194304 /dev/urandom > /tmp/smbfs-par.bin
for i in 1 2 3 4; do cp /tmp/smbfs-par.bin "$D/par$i.bin" & done; wait
PFAIL=0; for i in 1 2 3 4; do cmp /tmp/smbfs-par.bin "$D/par$i.bin" || PFAIL=1; done; [ $PFAIL -eq 0 ]; check $? "parallel copies"
for i in 1 2 3 4; do (cmp /tmp/smbfs-par.bin "$D/par$i.bin" || echo "reader $i mismatch") & done; wait
for i in 1 2 3 4; do (cat "$D/par$i.bin" > /dev/null; ls -l "$D" > /dev/null; stat "$D/par$i.bin" > /dev/null) & done; wait; check $? "parallel readers and listings"
for i in 1 2 3 4; do rm "$D/par$i.bin" & done; wait; [ -z "$(ls "$D" | grep par)" ]; check $? "parallel removes"
rm -f /tmp/smbfs-par.bin
# cache coherency: change a file on the server side through another path
echo "first" > "$D/coh.txt"; cat "$D/coh.txt" > /dev/null
echo "second version" > "$D/coh-src.txt"; mv "$D/coh-src.txt" "$D/coh.txt"
[ "$(cat "$D/coh.txt")" = "second version" ]; check $? "replaced file content visible"
rm "$D/coh.txt"
rmdir "$D"; check $? "rmdir test directory"
# mmap/read_pages path: run a program copied to the share
cp /bin/true "$D-true" 2>/dev/null && "$D-true"; check $? "execute binary from share"
rm -f "$D-true"
unmount "$MP"; check $? "unmount"
rmdir "$MP"
rm -f /tmp/smbfs-big.bin /tmp/smbfs-big2.bin
echo "== $FAIL failure(s) =="
tail -5 /var/log/syslog | grep -i smbfs
exit $FAIL
