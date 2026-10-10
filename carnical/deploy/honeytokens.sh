#!/bin/sh
# Create the honeytoken files that deploy/auditd/carnical.rules watches. Run once, as root, after the directories exist
# (systemd-tmpfiles --create) and before the audit rules are loaded.
#
# A honeytoken is a file that looks worth stealing and that nothing legitimate ever reads. An attacker who has a foothold looks
# for exactly this kind of file (a backup of the customer database, an old copy of a key, an .env backup), so a read of one is an
# incident with no false positives. They hold nothing real: the contents are random bytes with a plausible header, and the
# values in the .env copy are marked so that the owner who finds one in a log knows what it is.
set -eu

umask 077
failed=0 # a token that could not be made does not stop the others; the script fails at the end

# Each file is written by the user who owns its directory, never by root. The directory is that user's, so after a takeover it
# may already hold a link to somewhere else (/etc/ld.so.preload, a disk device): written as root, the file would land there.
# Written as the owner, such a link leads only where the owner could write anyway. The contents go to a new file with a random
# name first (mktemp creates it exclusively), which is then hard-linked into place: link(2) fails if anything has the name,
# a link or a pipe included, and never follows one, so even a link planted after the checks below is not written through.
make() { # owner path
	owner=$1
	path=$2
	if [ -L "$path" ]; then
		echo "a symbolic link is in its place, which nothing here makes: look into it: $path" >&2
		return 1
	fi
	if [ -e "$path" ]; then
		echo "exists, left alone: $path"
		return
	fi
	if setpriv --reuid="$owner" --regid="$owner" --clear-groups --no-new-privs -- sh -c \
		'umask 077; tmp=$(mktemp "$1.XXXXXXXX") || exit 1; cat >"$tmp" && ln -T -- "$tmp" "$1"; status=$?; rm -f -- "$tmp"; exit $status' \
		sh "$path"; then
		echo "created: $path"
	else
		echo "could not be created as $owner (is something in its place?): $path" >&2
		return 1
	fi
}

# A "backup" of the customer database: the SQLite header followed by random bytes, about the size of a small one.
{
	printf 'SQLite format 3\000'
	head -c 262144 /dev/urandom
} | make carnical-ctl /var/lib/carnical/ctl/customers-backup.sqlite || failed=1

# An old environment file with keys in it, every value marked as a honeytoken.
make carnical-portal /var/lib/carnical/portal/.env.bak <<'EOF' || failed=1
# copied before the last upgrade
DATABASE_URL=postgres://portal:CARNICAL-HONEY-DO-NOT-USE@127.0.0.1:5432/portal
SESSION_SECRET=CARNICAL-HONEY-0000000000000000000000000000
PAYMENT_API_KEY=CARNICAL-HONEY-sk_live_0000000000000000
EOF

# The "previous" signing key, which was never a key.
{
	printf -- '-----BEGIN PRIVATE KEY-----\n'
	head -c 96 /dev/urandom | base64
	printf -- '-----END PRIVATE KEY-----\n'
} | make carnical-signer /var/lib/carnical/signer/signing-key.old || failed=1

if [ "$failed" != 0 ]; then
	echo "not every honeytoken was created: see above" >&2
	exit 1
fi
echo
echo "Load the audit rules next:   augenrules --load"
echo "A read of any of these shows up as:   ausearch -k carnical_honey -i"
