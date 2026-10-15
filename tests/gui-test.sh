#!/bin/bash
# Scripted GUI test for SMBMounter's favorites panel. Run on a Haiku machine:
#   tests/gui-test.sh [SMBMounter binary] [//server/share] [user] [password]
# It drives the window with "hey" and waits for windows with "waitfor", so it
# needs a running desktop. The settings file is backed up and restored.
# Set SCREENSHOT=/path/file.png to capture the screen while a favorite is
# mounted.
set -u

APP=${1:-/boot/system/apps/SMBMounter}
UNC=${2:-//192.168.1.234/HaikuSMB}
USER_NAME=${3:-test}
PASSWORD=${4:-test}
SIG=application/x-vnd.HaikuSMB-SMBMounter
SETTINGS="$(finddir B_USER_SETTINGS_DIRECTORY)/SMBMounter settings"
SERVER=${UNC#//}; SERVER=${SERVER%%/*}
SHARE=${UNC##*/}
FAILED=0

check() {	# check <description> <expected> <actual>
	if [ "$2" == "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: expected '$2', got '$3'"
		FAILED=$((FAILED + 1))
	fi
}

# Extracts the "result" value from hey's reply: strings lose their quotes,
# int32 values their hex suffix, booleans become 1/0.
result() {
	sed -n 's/.*"result" ([A-Z_0-9]*) : //p' | head -1 \
		| sed 's/^"\(.*\)"$/\1/; s/ (0x[0-9a-fA-F]*)$//; s/^TRUE$/1/; s/^FALSE$/0/'
}

get() {		# get <view> [window]  -> Value property (text or int)
	hey $SIG get Value of View "$1" of Window "${2:-0}" | result
}

set_value() {	# set_value <view> <value> [window]; strings must reach hey quoted
	local value="$2"
	case "$value" in
		''|*[!0-9]*) value="\"$value\"" ;;
	esac
	hey $SIG set Value of View "$1" of Window "${3:-0}" to "$value" >/dev/null
}

count_favorites() {
	hey $SIG count Item of View favorites of Window 0 | result
}

select_favorite() {	# like a click on the item
	hey $SIG set Selection "$1" of View favorites of Window 0 to "bool(true)" >/dev/null
}

mounted_count() {	# number of mounted smbfs volumes (df lists the fs type)
	df 2>/dev/null | grep -c " smbfs "
}

wait_mounted() {	# wait_mounted <expected count>
	for i in 1 2 3 4 5 6 7 8 9 10; do
		[ "$(mounted_count)" == "$1" ] && break
		sleep 1
	done
	mounted_count
}

restore() {
	hey $SIG quit >/dev/null 2>&1
	waitfor -e SMBMounter
	if [ -f "$SETTINGS.gui-test-backup" ]; then
		mv "$SETTINGS.gui-test-backup" "$SETTINGS"
	else
		rm -f "$SETTINGS"
	fi
}
trap restore EXIT

# Start from a clean settings file, keeping the user's one.
hey $SIG quit >/dev/null 2>&1
waitfor -e SMBMounter
[ -f "$SETTINGS" ] && mv "$SETTINGS" "$SETTINGS.gui-test-backup"

"$APP" "$UNC" "user=$USER_NAME" "password=$PASSWORD" &
waitfor "w>SMBMounter"
check "starts with no favorites" 0 "$(count_favorites)"
check "remove button disabled" 0 \
	"$(hey $SIG get Enabled of View removeFavorite of Window 0 | result)"

# Add: the prompt proposes "<share> on <server>".
hey $SIG addf of Window 0 >/dev/null
waitfor "w>Add favorite"
check "default name" "$SHARE on $SERVER" "$(get name "Add favorite")"
set_value name "Lab share" "Add favorite"
hey $SIG nmok of Window "Add favorite" >/dev/null
waitfor -e "w>Add favorite"
check "one favorite after add" 1 "$(count_favorites)"
check "new favorite selected, remove enabled" 1 \
	"$(hey $SIG get Enabled of View removeFavorite of Window 0 | result)"
check "password kept for the same account" "$PASSWORD" "$(get password)"

# A second favorite with different values.
set_value server "fileserver.example.org"
set_value share "media"
set_value user "guest"
set_value readonly 1
hey $SIG addf of Window 0 >/dev/null
waitfor "w>Add favorite"
check "default name follows the form" "media on fileserver.example.org" \
	"$(get name "Add favorite")"
set_value name "Media (read-only)" "Add favorite"
hey $SIG nmok of Window "Add favorite" >/dev/null
waitfor -e "w>Add favorite"
check "two favorites" 2 "$(count_favorites)"

# Clicking the first favorite fills the form again.
select_favorite 0
check "server restored" "$SERVER" "$(get server)"
check "share restored" "$SHARE" "$(get share)"
check "user restored" "$USER_NAME" "$(get user)"
check "read-only restored" 0 "$(get readonly)"
check "mount point follows share" "/$SHARE" "$(get mountpoint)"
check "password not carried over from another account" "" "$(get password)"

select_favorite 1
check "second favorite: server" "fileserver.example.org" "$(get server)"
check "second favorite: share" "media" "$(get share)"
check "second favorite: read-only" 1 "$(get readonly)"
check "second favorite: mount point" "/media" "$(get mountpoint)"
check "password cleared for another account" "" "$(get password)"

# Rename, then check the new name through the rename prompt.
hey $SIG renf of Window 0 >/dev/null
waitfor "w>Rename favorite"
check "rename prompt shows the name" "Media (read-only)" \
	"$(get name "Rename favorite")"
set_value name "Media" "Rename favorite"
hey $SIG nmok of Window "Rename favorite" >/dev/null
waitfor -e "w>Rename favorite"
hey $SIG renf of Window 0 >/dev/null
waitfor "w>Rename favorite"
check "renamed" "Media" "$(get name "Rename favorite")"
hey $SIG nmok of Window "Rename favorite" >/dev/null
waitfor -e "w>Rename favorite"
check "renaming to the same name keeps two favorites" 2 "$(count_favorites)"

# Adding under an existing name updates that favorite instead of adding one.
set_value user "other"
hey $SIG addf of Window 0 >/dev/null
waitfor "w>Add favorite"
set_value name "Media" "Add favorite"
hey $SIG nmok of Window "Add favorite" >/dev/null
waitfor -e "w>Add favorite"
check "still two favorites" 2 "$(count_favorites)"
select_favorite 0
select_favorite 1
check "favorite updated in place" "other" "$(get user)"

# Persistence: quit and start again.
hey $SIG quit >/dev/null
waitfor -e SMBMounter
"$APP" &
waitfor "w>SMBMounter"
check "favorites survive a restart" 2 "$(count_favorites)"
select_favorite 1
check "restored favorite: server" "fileserver.example.org" "$(get server)"
check "restored favorite: read-only" 1 "$(get readonly)"

# Double-click (select + invoke) mounts the favorite; the password is not
# stored, so type it first as a user would.
select_favorite 0
set_value password "$PASSWORD"
hey $SIG do Item 0 of View favorites of Window 0 >/dev/null
check "double-click mounted the share" 1 "$(wait_mounted 1)"
check "mount point field unchanged after mounting" "/$SHARE" "$(get mountpoint)"
if [ -n "${SCREENSHOT:-}" ]; then
	screenshot -s -f png "$SCREENSHOT" && echo "screenshot: $SCREENSHOT"
fi
hey $SIG umnt of Window 0 >/dev/null
check "unmounted again" 0 "$(wait_mounted 0)"

# Remove (the confirmation is answered directly).
select_favorite 1
hey $SIG remc of Window 0 with which=int32\(1\) and index=int32\(1\) and name=\"Media\" >/dev/null
check "favorite removed" 1 "$(count_favorites)"

echo
if [ $FAILED -eq 0 ]; then
	echo "All GUI checks passed."
else
	echo "$FAILED GUI check(s) failed."
	exit 1
fi
