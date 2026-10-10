# Linux host deployment

This recipe places edge, portal, control and signer services on one Linux host with separate users,
systemd sandboxes, network policy and process confinement. Follow the installation order below and
test on the target host. The [hardening guide](../docs/hardening.md) explains the layers.

Tested on Linux 6.18 with systemd 259 (Ubuntu 26.04 under WSL2). Not yet on Ubuntu 22.04, Ubuntu
24.04 or Debian 12; see "Differences between systems" below.

For the edge in front of one website, start with the [site configuration and client handover
guide](../docs/website-onboarding.md). The service now validates its effective settings before
startup; local checks do not replace confined live forwarding tests.

For standalone binaries, containers, private health checks and multi-replica contracts, see
[availability and portable deployment](../docs/availability-and-deployment.md). Linux kernel
controls below are additional platform-specific layers; the health listener needs the narrow systemd
bind allowance described in that guide.

## What is here

| File | What it does |
|---|---|
| `sysusers.d/carnical.conf` | One user per part. None can log in. |
| `tmpfiles.d/carnical.conf` | Each part's directory, owned by it and mode 0700, and root's own for the host audit. |
| `systemd/carnical-edge.service`, `.socket` | The edge: no capabilities, a read-only machine, other services' data not visible, nothing but the system calls a service needs, port 443 from systemd. |
| `systemd/carnical-audit.*` | The segmentation checks, as an unprivileged user, four times a day. |
| `systemd/carnical-host-audit.*` | The checks of the machine itself, as root with five capabilities and no network sockets, four times a day. |
| `nftables/carnical.nft` | Early SYN and malformed-packet filtering, bounded echo/log budgets, and network policy by user. The edge: public addresses on 80 and 443 only. Everything else: this machine only. The metadata service: root only. See [L3/L4 protection](../docs/network-protection.md). |
| `nftables/render_policy.py` | Render small, standard or large packet budgets and verified proxy-peer ranges. Prints a policy for review; loading it is an explicit administrator action. |
| `sysctl/90-carnical.conf` | Kernel settings against ptrace, kernel address leaks, BPF, io_uring, user namespaces and link tricks, and TCP Fast Open (which connects without the call Landlock's port rules check). |
| `modprobe/carnical.conf` | Kernel modules a web server does not need and attackers use. |
| `auditd/carnical.rules` | What to record, chosen so that each record is an incident. |
| `honeytokens.sh` | Files that look worth stealing and that nothing reads. |

## Order

Run the build commands from `carnical/`. Installation paths below are relative to `carnical/deploy/`
unless absolute.

1. Build with the right Go and without cgo, so that the self-confinement reaches every thread.

   ```sh
   CGO_ENABLED=0 go build -trimpath -o carnical ./cmd/carnical
   CGO_ENABLED=0 go build -trimpath -o carnical-audit ./cmd/carnical-audit
   CGO_ENABLED=0 go build -trimpath -o carnical-confine ./cmd/carnical-confine
   govulncheck ./...        # must say "No vulnerabilities found"; the module requires go1.26.9 or later
   ```

2. Install the programs as root, owned by root and not writable by anyone else: `install -o root -g root -m 0755 carnical carnical-audit carnical-confine /usr/local/bin/`.
3. `install -m 0644 sysusers.d/carnical.conf /etc/sysusers.d/ && systemd-sysusers`, then the same for `tmpfiles.d` and `systemd-tmpfiles --create`.
4. Put `zones.json` in `/etc/carnical/` (see [segmentation](../docs/segmentation.md); with everything on one machine each part is a zone, each listener names its `user`, and a socket that systemd opened is owned by root, so list `root,carnical-edge`). Install the reviewed site file as `/etc/carnical/site.json` (root-owned, edge-group-readable, mode 0640) and put `CARNICAL_ARGS="-config /etc/carnical/site.json"` in `/etc/carnical/edge.env`. Direct flag lists remain supported. See the [site examples](../docs/website-onboarding.md) for certificates, origin addresses and checks.
5. `install -m 0644 sysctl/90-carnical.conf /etc/sysctl.d/ && sysctl --system`. `install -m 0644 modprobe/carnical.conf /etc/modprobe.d/`.
6. Edit the management addresses and resolver at the top of `nftables/carnical.nft`. Keep the resolver a local stub such as systemd-resolved's 127.0.0.53: the host audit expects the internal services to resolve names through this machine only, and on Azure the stub forwards to 168.63.129.16, which the edge itself may not reach. [Render a deployment profile](../docs/network-protection.md#choosing-a-budget) with budgets matching the measured edge capacity and verified CDN/load-balancer peers, review the output, check it, then load it: `nft -c -f /etc/carnical/network.nft && nft -f /etc/carnical/network.nft`. Rendered profiles require nftables 1.0.9 or later and kernel support for `destroy`; `nft -c` verifies support. Load the complete file in one transaction. It resets this table's counters/meters so changed limits and revoked peer ranges take effect. Load it from a unit that runs before the services, and keep the file where no service user can write it.
7. `./honeytokens.sh`, then `install -m 0640 auditd/carnical.rules /etc/audit/rules.d/ && augenrules --load`. The last line of the rules locks them until the next boot.
8. Install the units, then `systemctl daemon-reload && systemctl enable --now carnical-edge.socket carnical-audit.timer carnical-host-audit.timer`.
9. Mount `/tmp`, `/var/tmp` and `/dev/shm` with `nosuid,nodev,noexec` (a `tmp.mount` unit or `/etc/fstab`) and `/proc` with `hidepid=invisible`. The host audit reports each one that is not.
10. **When the machine is known to be good**, record the baseline as root: `carnical-audit -write-baseline`. It goes in `/var/lib/carnical/host-audit`, which only root owns and can write; the host audit refuses a baseline that anyone else could have changed. Copy `integrity.json` and `suid.json` from there to somewhere an attacker on this machine cannot reach, and compare them from there now and then. A baseline kept only on the machine proves nothing against someone who can write to it. (Baselines recorded in `/var/lib/carnical/audit` by earlier versions are not read: that directory belongs to the segmentation audit's user. Record them again.)

## Check that it works

```sh
systemd-analyze security carnical-edge.service            # exposure 1.4 on the tested system; the host audit fails it above 2.0
sudo carnical-audit -zones /etc/carnical/zones.json -host # every host check, as root; a check that could not run is a failure, not a pass
sudo -u carnical-edge carnical-confine check              # the confinement, from inside: every forbidden action must be refused
carnical-confine check -unconfined                        # the control: the same actions with no confinement must all go through
ausearch -m SECCOMP -i                                    # the record the kernel writes when the filter ends a process
```

If `-unconfined` does not pass, the probe is broken and the confined run proves nothing.

For flood latency, check the origin as well as the edge: persistent responses, accept-queue capacity
and upstream concurrency must fit the measured workload. The [controlled latency
investigation](../docs/network-protection.md#investigating-the-one-second-tail) reproduced the
earlier one-second delay in an undersized test origin even without a flood. Compare
matched-concurrency runs and connection/TCP counters before increasing protection budgets.

## What to do when something fails

* A `host-processes`, `host-listeners` or `host-edge-confined` finding on a machine that was fine yesterday is an incident until shown otherwise. Do not restart the service first: the process and its open files are the evidence. `ausearch -k carnical_svc_exec -i` and `-m SECCOMP -i` show what it tried.
* A `host-integrity` or `host-suid` finding is either an update you made (record the baseline again, from a machine you trust) or someone else's change. `host-suid` also names a network file system (NFS, CIFS, sshfs) mounted without `nosuid`: setuid files would work there and the scan does not walk it, so mount it `nosuid`.
* A `host-nft` finding names the rule. Where the policy lets traffic through, the check knows only the forms `carnical.nft` uses (named ports, the listed ICMP types, the resolver by address; for the edge after its blocks, named ports to any public address or to named ones), so a rule you added on purpose, such as an accept for a private origin, is reported until it is one of those forms: the finding is then a record of the exception, not a fault. The check reads `nft list ruleset`, which prints names and strings without escaping them, so it also reads `nft -j list ruleset` and reports any name with a space, quote, brace, comma, semicolon, `#` or control character and any string with a quote or control character: with one of those, a rule can be listed as something it is not. nft must support `-j`. The listing format was tested with nftables 1.1.3; another version that prints a rule differently shows up as a finding naming a rule the file really has.
* A `host-sysctl`, `host-mounts` or `host-unit-*` finding is drift: something was set back. Find out what did it.

## Differences between systems

* **Landlock** needs Linux 5.13. ABI 4 (Linux 6.7) adds the TCP port rules and ABI 6 (Linux 6.12) the abstract-socket and signal scoping. Ubuntu 22.04 (5.15) has ABI 1 and Debian 12 (6.1) has ABI 2, so there strict `-confine` refuses to start because its configured port restrictions require ABI 4. Explicit `-confine-best-effort` can apply file rules while skipping unsupported port rules; the startup report states the missing layer. ABI 4/5 still lack ABI 6 scoping, which is separately reported. The nftables policy and the unit's `IPAddressDeny` carry the network side there.
* **systemd 249** (Ubuntu 22.04) has no `systemd-analyze security --offline`, and `ProtectProc`, `SocketBindDeny` and the others used here are present from 247 and 249; check `systemd-analyze security` on the host.
* **User namespaces:** Debian uses `kernel.unprivileged_userns_clone`, Ubuntu 24.04 `kernel.apparmor_restrict_unprivileged_userns`; `user.max_user_namespaces=0` covers both and is what the host audit demands.
* **io_uring:** `kernel.io_uring_disabled` exists from Linux 6.6; older kernels rely on the seccomp filter and the unit's system call filter, which both refuse it by name.
