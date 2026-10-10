# Linux host confinement

These controls limit what a compromised service account can do on a shared Linux host. The recipe
separates edge, portal, control and signer users, restricts process/filesystem/network access, and
audits drift. It assumes code may already be running as the edge user.

Start with the [deployment order](../deploy/README.md), then compare the installed host with the
layers below. [Validation scope](#what-was-verified-and-how) records the tested kernel and remaining
target-host checks. Source: [sandbox](../sandbox/), [host auditor](../audit/host/), [deployment
files](../deploy/).

## The layers

| # | Layer | What it does | Where |
|---|---|---|---|
| 1 | **The process confines itself** | After start-up it can no longer start a program, ptrace, mount, load kernel code, create a namespace, open a raw or kernel-crypto socket, use io_uring or BPF; it can read and write only its own files; its internet sockets are TCP and UDP only, and TCP connects and listens only on named ports (UDP, which name lookups need, is left to the network policy), with TCP Fast Open, which would connect without the port check, refused; it is not dumpable, so another process of the same user cannot read its memory. Applied to every thread. A filtered call ends the process and leaves an audit record that names it. | `sandbox/`, `carnical -confine` |
| 2 | **systemd sandboxes the unit from outside** | No capabilities, the whole machine read-only except its own directory, other services' data not present, no other users' processes visible, no memory that is both writable and executable, a system call allow list, no metadata-service access. | `deploy/systemd/` |
| 3 | **Network policy by user** | The edge may connect only to public addresses on 80 and 443 (and DNS to the local resolver): not to private ranges, this machine's own address, the metadata service, or Azure's platform address (168.63.129.16). Everything else on the machine may connect nowhere but this machine. The kernel decides by the user that owns the socket. | `deploy/nftables/` |
| 4 | **The kernel is set so the usual steps fail** | No ptrace between same-user processes, no kernel address leaks, no BPF or io_uring, no user namespaces, no link tricks in sticky directories, no setuid core dumps; modules attackers use cannot be loaded. | `deploy/sysctl/`, `deploy/modprobe/` |
| 5 | **Separate users and directories** | One user per part, none can log in, each directory 0700 to its own user; programs are root-owned. | `deploy/sysusers.d/`, `tmpfiles.d/` |
| 6 | **Things are recorded** | An exec by a service, a use of the calls an attacker needs, a change to what runs at boot, a new setuid file, and any read of a honeytoken. | `deploy/auditd/`, `deploy/honeytokens.sh` |
| 7 | **The checks look for what was undone or added** | Four times a day: the settings above are still in force; no listener, process or setuid file has appeared; nothing that should not change has changed; the running edge really is confined, on every thread. | `audit/host`, `carnical-audit -host` |

Layers 1 and 2 overlap on purpose (the proxy forbids `execve` in-process, and the unit forbids the
same system calls from outside). The in-process layer survives a mistake in the unit file, and the
unit survives a bug in the in-process code.

## What it does to the usual steps

The techniques are the ones real intrusions through a web service account use. "Stopped" means
stopped for an attacker who is **only** the edge user.

| Technique | Stopped by | Detected by | Result |
|---|---|---|---|
| Run a shell or any program | seccomp (`execve`, `execveat` end the process), Landlock (no execute right), unit system call filter, `NoExecPaths` not needed | `carnical_svc_exec`, a SECCOMP record, `host-processes` | Stopped |
| Setuid or capability abuse, `sudo` | `no_new_privs`, `CapabilityBoundingSet=` empty, no sudoers entry | `carnical_setuid`, `host-suid` | Stopped |
| Kernel privilege escalation (netfilter, AF_ALG, overlayfs, io_uring, userfaultfd) | seccomp refuses namespaces, `AF_ALG`, `AF_PACKET`, io_uring, BPF, userfaultfd by name; `user.max_user_namespaces=0`; modules blacklisted; patching | `carnical_abuse`, a SECCOMP record | Blocks the listed operations; flaws in allowed syscalls/kernel paths remain possible |
| Read another service's files (the signer key, other customers) | Landlock, `InaccessiblePaths`, mode 0700 per user | the honeytokens; `carnical_honey` | Stopped |
| Read another process's environment or memory | `ProtectProc=invisible`, `ptrace_scope=2`, non-dumpable, Landlock | `carnical_abuse` | Stopped (**Measured**: a non-dumpable process hides its own program path from an unprivileged process of the same user) |
| Reach other services over loopback | nftables (no loopback for the edge), Landlock port rules, no shared sockets | `carnical-edge-private` log lines | Blocked by the supplied policy; required local services need a reviewed UNIX socket or narrow policy exception |
| Reach the cloud metadata service, or Azure's platform address (168.63.129.16) | nftables, `IPAddressDeny=link-local 168.63.129.16`, the proxy's origin guard | `carnical-imds` and `carnical-edge-private` log lines | Stopped |
| Reverse shell, tunnel out, download tools | no exec; egress limited to public 80 and 443 | `carnical-edge-egress` log lines | A shell: stopped. Traffic over 443 to a public address from inside the process: **not**, until the egress list is the registered origins (below) |
| Write to boot, cron, systemd or library-loading files | read-only machine, Landlock, `RestrictSUIDSGID` | `carnical_persist`, `host-integrity` | Stopped |
| Plant an SSH key | `ProtectHome`, no shell, Landlock | `carnical_ssh`, `host-integrity` | Stopped |
| Fileless code (`memfd_create`, a deleted binary) | seccomp, `MemoryDenyWriteExecute=yes`, `noexec` mounts | `host-processes`, SECCOMP | Stopped |
| Run a miner or hog the CPU | no exec; `CPUQuota`, `MemoryMax`, `TasksMax` | cgroup CPU | **Capped, not stopped** |
| Wipe logs | read-only machine; logs shipped off the machine | an off-machine copy | Needs the off-machine copy (not built) |
| Load a rootkit or module | seccomp, `kernel.modules_disabled=1` after boot, module blacklist | `carnical_abuse` | Stopped |

## What was verified, and how

**On a real kernel (Linux 6.18, Landlock ABI 7, Ubuntu 26.04 under WSL2), measured:**

* `carnical-confine` runs 34 actions from inside the confinement, each in its own process: **33 behave as expected**, and the 34th was
  a wrong expectation that is now corrected (a child that tries to exec is killed, so its parent sees a failed command, not a kill).
  Allowed: read and write its own directories, connect and listen on allowed ports, resolve a name, serve HTTP, read the machine's
  addresses, start forty threads. Refused: everything outside its files, a symlink or named pipe in its directory, reading another
  process's environment or maps, a port that is not allowed (connect and listen), an abstract socket of another process, a signal to
  a process outside, and ended by the filter: exec, exec from a child, ptrace, mount, a user namespace, BPF, io_uring, perf, userfaultfd,
  memfd_create, a kernel module, packet, kernel-crypto and vsock sockets. It also checks that every thread has `no_new_privs` and the filter.
* **The control:** the same 34 actions with no confinement all go through, so the confined run is telling something. Runs with
  Landlock or seccomp switched off are reported as failing for the actions each layer owns.
* The seccomp filter is also evaluated by a small BPF interpreter against 34 made-up system calls and arguments, including the
  architecture check and the x32 ABI bit.
* The real proxy binary with `-confine` serves requests, blocks an attack, handles an upload into its own directory, serves on a
  socket systemd hands it, and shuts down cleanly; the kernel shows `Seccomp: 2` and `NoNewPrivs: 1` on every thread of it, and `0` and `0` for the same
  binary without `-confine`.
* `nft -f deploy/nftables/carnical.nft` loads in a private network namespace; with the edge chain applied to that namespace's own
  user, a connection to a loopback address is blocked and the counter on the private-address rule records it, and the same connection
  with no rules succeeds.
* `systemd-analyze security --offline` gives the edge unit **1.4 (OK)**, the audit unit 2.2 and the root host-audit unit 2.4.
* The host checks were tested against fixtures (every pass and every failure), with the single sources of truth tied together (the Go
  baseline against `90-carnical.conf`, the unit file against the check, the nft and audit tokens against their files), and against this
  machine: a running process with a deleted executable was detected, a listener nobody declared was found, and a baseline made from
  the machine's own settings passed while one asking for something else failed. Nine deliberate breaks of the checks were each caught.
* Run on this unhardened machine, `carnical-audit -host` reports its real sysctl values, the missing units and files, and the undeclared DNS
  listeners, and says plainly where it needs root.

**Not verified, because it needs root on the target machine:**

* The units, sysctls, modprobe entries, nftables policy for real users (`meta skuid`), and audit rules have not been installed on any machine.
  In particular, how the unit's system call filter, `SocketBindDeny=any` and `IPAddressDeny=link-local 168.63.129.16` behave with the proxy running under them
  has not been seen; the first start should be watched, with `SystemCallErrorNumber=EPERM` set temporarily so that a filtered call is an error and not a kill.
* Landlock ABIs 1 to 6 and kernels older than 6.18, and Ubuntu 22.04, Ubuntu 24.04 and Debian 12 (see `deploy/README.md`).
* The audit rules have not been loaded (`augenrules`), so their syntax is checked only by reading.
* `host-processes` and `host-edge-confined` need root: a process that is not dumpable hides its program from other processes of the same user
  (**measured**), so the unprivileged audit sees nothing. They run in the root host-audit unit and report "needs root" otherwise.

## What an attacker in the edge still has

* **The edge's own memory.** Every TLS private key the edge serves is in it. An attacker who reads the process's memory (a bug in
  the proxy, not another process) has those keys. Mitigations: per-customer certificates that are short-lived; the configuration-signing
  key is never in the edge (it is in the signer, a different user the edge cannot see).
* **Connections to the public internet on 80 and 443.** The proxy can still be used to attack other sites, and to exfiltrate over 443.
  Tightening it: when the registry exists, load the registered origins' addresses into an nftables set and let the edge connect only to
  those. That is the single largest remaining step.
* **The control plane's interface.** If the edge fetches configuration or pushes events over a UNIX socket,
  it can reach the service listening on that socket. Keep the interface small and parse its input strictly.
* **`clone3` with a namespace flag.** seccomp cannot inspect `clone3`'s arguments (they are in memory). Namespaces are refused instead by `RestrictNamespaces=yes`
  and `user.max_user_namespaces=0`.
* **A kernel flaw in a system call the proxy needs.** Patching and rebooting stay the first control. The hardening shrinks the surface; it does not remove it.
* **CPU and memory.** Capped by the unit, not prevented.
* **Logs on the same machine.** An attacker with root can edit them. Ship them off the machine (not built).

## Next, in order

1. When the registry exists: the edge's egress is the set of registered origins, enforced by nftables and by the proxy.
2. Services talk over UNIX sockets with peer-credential checks; no TCP on loopback between parts.
3. Install on a real machine and run `carnical-audit -host` and `carnical-confine check` on it, on each of the three distributions.
4. Ship the audit log and the baselines off the machine, and compare them from there.
5. Per-tenant certificate keys held outside the edge (a small signing service) so that compromising the edge does not hand over every key.
