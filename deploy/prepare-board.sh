#!/bin/bash
# prepare-board.sh - make a SightPAS SP4 board an Indagate controller and nothing else.
#
# A board arrives from its maker running the maker's application, with the maker's update
# services, an FTP server and two accounts with published passwords. This script switches
# all of that off and removes it, and puts the Indagate services in place. It is safe to
# run more than once: on a board already prepared it finds nothing to do.
#
#   bash prepare-board.sh                    show what would be done; change nothing
#   bash prepare-board.sh --apply            do it
#
# Options:
#   --apply              make the changes (without it, nothing is changed)
#   --remove-pre-rename  also remove what Indagate itself left behind under its old names
#                        (hlaxs-access, highline-nexus). Only for a board that ran those
#                        builds, and only once it runs from /var/lib/indagate.
#   --no-display         also switch off the display service (weston), for a board with no
#                        screen
#
# Nothing is deleted before it has been copied into one archive, /root/indagate-removed-<date>.tar.gz
# (readable by root only: it can hold the maker's update token and old controller secrets).
# Delete the archive once the board has passed its checks.
#
# What it never touches: the operating system, the boot loader, the board support services
# (variscite-*, NetworkManager, the modem, Bluetooth and Wi-Fi), SSH, and anything under
# /opt/indagate, /etc/indagate and /var/lib/indagate.
#
# Afterwards: reboot, then remove the power and restore it, and check each time that the
# controller is running and a card releases its door (see README.md beside this file).

set -u

APPLY=0
PRE_RENAME=0
NO_DISPLAY=0
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        --remove-pre-rename) PRE_RENAME=1 ;;
        --no-display) NO_DISPLAY=1 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

# For testing the file handling against a copy of a board's folders: with this set, paths
# are taken under it and nothing is asked of systemd, the package manager or the accounts.
ROOT="${INDAGATE_PREPARE_ROOT:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$APPLY" = 1 ] && [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
    echo "run as root to apply" >&2
    exit 1
fi

CHANGES=0
PROBLEMS=0
say()  { echo "$*"; }
plan() { CHANGES=$((CHANGES + 1)); if [ "$APPLY" = 1 ]; then echo "  doing: $*"; else echo "  would: $*"; fi; }
fail() { PROBLEMS=$((PROBLEMS + 1)); echo "  PROBLEM: $*" >&2; }
system() { [ -z "$ROOT" ]; }   # true when working on the real board

# ---------- what is to go ----------

# The maker's application and update services, and the FTP server.
VENDOR_UNITS="monitor.service mender-connect.service mender-authd.service mender-updated.service mender-client.service swupdate.service swupdate.socket vsftpd.service"
VENDOR_PACKAGES="mender-connect mender-configure mender-update mender-flash mender-snapshot mender-setup mender-auth mender-client4 mender-client-version-inventory-script vsftpd"
VENDOR_PATHS="/home/user/Board_Source /etc/mender /var/lib/mender"
DEFAULT_ACCOUNTS="user weston"

# Indagate's own leftovers from before it was renamed.
PRE_RENAME_UNITS="highline-nexus-controller.service hlaxs-access.service hlaxs-access-bench.service hlaxs-access-cloud-bench.service hlaxs-access-integration-bench.service"
PRE_RENAME_PATHS="/opt/hlaxs /opt/hlaxs-access /var/lib/highline-nexus /var/lib/hlaxs /var/lib/hlaxs-access /var/lib/hlaxs-access-bench /var/lib/hlaxs-access-cloud-bench /var/lib/hlaxs-access-integration /etc/hlaxs-access /etc/hlaxs-access-auto-shadow-035 /etc/hlaxs-access-bench /etc/hlaxs-access-capture-bridge /etc/hlaxs-access-cloud-bench /etc/hlaxs-access-integration /usr/local/bin/highline-nexus-controller /usr/local/bin/highline-nexus-controller.pre-hlaxs-telemetry /usr/local/bin/highline-nexus-controller.pre-network-manager /etc/systemd/system/highline-nexus-controller.service /etc/systemd/system/highline-nexus-controller.service.d /etc/systemd/system/hlaxs-access.service /etc/systemd/system/hlaxs-access.service.d /etc/systemd/system/hlaxs-access-bench.service /etc/systemd/system/hlaxs-access-cloud-bench.service /etc/systemd/system/hlaxs-access-integration-bench.service"

DISPLAY_UNITS="weston.service weston.socket"

say "Indagate board preparation: $([ "$APPLY" = 1 ] && echo "APPLYING CHANGES" || echo "showing only, nothing will be changed")"
[ -n "$ROOT" ] && say "(test mode: files under $ROOT; services, packages and accounts are not touched)"

# ---------- services ----------

unit_known() { systemctl cat "$1" >/dev/null 2>&1; }

switch_off() {   # $1 = unit
    local unit="$1" active enabled
    unit_known "$unit" || return 0
    active="$(systemctl is-active "$unit" 2>/dev/null)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null)"
    if [ "$active" = active ] || [ "$enabled" = enabled ]; then
        plan "stop and disable $unit (now: $active, $enabled)"
        [ "$APPLY" = 1 ] && { systemctl disable --now "$unit" >/dev/null 2>&1 || fail "could not disable $unit"; }
    fi
    # A unit that ships with the system image is masked, so nothing can start it by accident.
    # One that only exists in /etc is removed with its file instead (see the file lists).
    if [ "$enabled" != masked ] && [ ! -e "/etc/systemd/system/$unit" ]; then
        plan "mask $unit so it cannot be started"
        [ "$APPLY" = 1 ] && { systemctl mask "$unit" >/dev/null 2>&1 || fail "could not mask $unit"; }
    fi
}

if system; then
    say ""
    say "Services:"
    before=$CHANGES
    for unit in $VENDOR_UNITS; do switch_off "$unit"; done
    [ "$PRE_RENAME" = 1 ] && for unit in $PRE_RENAME_UNITS; do switch_off "$unit"; done
    [ "$NO_DISPLAY" = 1 ] && for unit in $DISPLAY_UNITS; do switch_off "$unit"; done
    [ "$CHANGES" = "$before" ] && say "  nothing to do"
fi

# ---------- accounts ----------

if system; then
    say ""
    say "Accounts with published passwords:"
    before=$CHANGES
    for account in $DEFAULT_ACCOUNTS; do
        id "$account" >/dev/null 2>&1 || continue
        state="$(passwd -S "$account" 2>/dev/null | awk '{print $2}')"
        if [ "$state" != L ]; then
            plan "lock the password of '$account' (the account and anything running as it are kept)"
            [ "$APPLY" = 1 ] && { passwd -l "$account" >/dev/null 2>&1 || fail "could not lock $account"; }
        fi
    done
    [ "$CHANGES" = "$before" ] && say "  nothing to do"
    say "  note: the root password is yours to change, with 'passwd'; this script does not touch it"
fi

# ---------- files: archive, then remove ----------

# A board must be running from the new data folder before the old one may go.
pre_rename_allowed() {
    [ -f "$ROOT/var/lib/indagate/device.json" ] || { fail "not removing the pre-rename files: /var/lib/indagate/device.json is missing, so this board may still be running from the old folder"; return 1; }
    if system && [ "$(systemctl is-active indagate-controller.service 2>/dev/null)" != active ]; then
        fail "not removing the pre-rename files: indagate-controller.service is not running"
        return 1
    fi
    return 0
}

PATHS="$VENDOR_PATHS"
if [ "$PRE_RENAME" = 1 ] && pre_rename_allowed; then
    PATHS="$PATHS $PRE_RENAME_PATHS"
fi

say ""
say "Files:"
PRESENT=""
for path in $PATHS; do
    case "$path" in /*) ;; *) continue ;; esac            # absolute paths only
    [ "$path" = / ] && continue
    if [ -e "$ROOT$path" ] || [ -L "$ROOT$path" ]; then
        size="$(du -sh "$ROOT$path" 2>/dev/null | awk '{print $1}')"
        plan "archive, then remove $path ($size)"
        PRESENT="$PRESENT $path"
    fi
done
[ -z "$PRESENT" ] && say "  nothing to do"

if [ "$APPLY" = 1 ] && [ -n "$PRESENT" ]; then
    stamp="$(date +%Y%m%d-%H%M%S)"
    archive="$ROOT/root/indagate-removed-$stamp.tar.gz"
    mkdir -p "$ROOT/root"
    umask 077
    relative=""
    for path in $PRESENT; do relative="$relative ${path#/}"; done
    # shellcheck disable=SC2086
    if tar -C "${ROOT:-/}" -czf "$archive" $relative 2>/dev/null && [ -s "$archive" ]; then
        chmod 600 "$archive"
        say "  archived to ${archive#"$ROOT"} ($(du -sh "$archive" | awk '{print $1}'))"
        for path in $PRESENT; do
            rm -rf -- "${ROOT:?}$path" 2>/dev/null || rm -rf -- "$ROOT$path" || fail "could not remove $path"
        done
    else
        rm -f "$archive"
        fail "the archive could not be written; nothing was removed"
    fi
fi

# ---------- packages ----------

if system; then
    say ""
    say "Packages:"
    before=$CHANGES
    installed=""
    for package in $VENDOR_PACKAGES; do
        dpkg -s "$package" >/dev/null 2>&1 && installed="$installed $package"
    done
    if [ -n "$installed" ]; then
        plan "remove packages:$installed"
        if [ "$APPLY" = 1 ]; then
            # shellcheck disable=SC2086
            DEBIAN_FRONTEND=noninteractive dpkg --purge $installed >/dev/null 2>&1 || fail "some packages could not be removed (see 'dpkg -l | grep -E \"mender|vsftpd\"')"
        fi
    fi
    [ "$CHANGES" = "$before" ] && say "  nothing to do"
fi

# ---------- Indagate's own services and folders ----------

say ""
say "Indagate:"
before=$CHANGES
for folder in /opt/indagate/releases /etc/indagate /var/lib/indagate; do
    if [ ! -d "$ROOT$folder" ]; then
        plan "create $folder"
        [ "$APPLY" = 1 ] && mkdir -p "$ROOT$folder"
    fi
done
if [ "$APPLY" = 1 ]; then
    chmod 700 "$ROOT/var/lib/indagate" "$ROOT/opt/indagate/releases" 2>/dev/null
fi
RELOAD=0
for unit in indagate-board-power.service indagate-controller.service; do
    source_file="$HERE/systemd/$unit"
    target="$ROOT/etc/systemd/system/$unit"
    [ -f "$source_file" ] || { fail "missing $source_file (run this script from the firmware's deploy folder)"; continue; }
    if ! cmp -s "$source_file" "$target"; then
        plan "install $unit"
        if [ "$APPLY" = 1 ]; then
            mkdir -p "$ROOT/etc/systemd/system"
            install -m 644 "$source_file" "$target" || fail "could not install $unit"
            RELOAD=1
        fi
    fi
done
if system; then
    [ "$RELOAD" = 1 ] && systemctl daemon-reload
    for unit in indagate-board-power.service indagate-controller.service; do
        if [ "$(systemctl is-enabled "$unit" 2>/dev/null)" != enabled ]; then
            plan "enable $unit to start at boot"
            [ "$APPLY" = 1 ] && { systemctl enable "$unit" >/dev/null 2>&1 || fail "could not enable $unit"; }
        fi
    done
    if [ ! -e /opt/indagate/current ]; then
        say "  note: no release is installed yet (/opt/indagate/current is missing); see README.md"
    fi
    if ! ls /etc/systemd/system/indagate-controller.service.d/*.conf >/dev/null 2>&1; then
        say "  note: no server address is set yet (indagate-controller.service.d/*.conf); see README.md"
    fi
fi
[ "$CHANGES" = "$before" ] && say "  nothing to do"

# ---------- what is left ----------

if system; then
    say ""
    say "Still accepting connections from the network (for you to judge):"
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sort -u | sed 's/^/  /'
fi

say ""
if [ "$PROBLEMS" -gt 0 ]; then
    say "Finished with $PROBLEMS problem(s). Read them above before going on."
    exit 1
fi
if [ "$APPLY" = 1 ]; then
    say "Done: $CHANGES change(s) made. Now reboot, then remove the power and restore it, and check a card each time."
else
    say "$CHANGES change(s) would be made. Run again with --apply to make them."
fi
