package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/YurilLAB/coraza/carnical/audit"
)

// Setting is one kernel setting and the value it must have.
type Setting struct {
	Key  string
	Want int64
	// AtLeast accepts any value from Want up: for these a larger number is stricter.
	AtLeast bool
	// Optional means that a kernel without the setting is fine (the switch is newer than some kernels, or specific to one
	// distribution).
	Optional bool
}

// Sysctls is what the kernel must be set to. deploy/sysctl/90-carnical.conf is the file that sets them, and a test keeps
// the two the same.
var Sysctls = []Setting{
	{"kernel.yama.ptrace_scope", 2, true, false},
	{"kernel.kptr_restrict", 2, true, false},
	{"kernel.dmesg_restrict", 1, true, false},
	{"kernel.unprivileged_bpf_disabled", 1, true, false},
	{"net.core.bpf_jit_harden", 2, true, false},
	{"kernel.perf_event_paranoid", 2, true, false}, // 3 on Debian and Ubuntu kernels; mainline stops at 2
	{"kernel.io_uring_disabled", 2, true, true},
	{"kernel.kexec_load_disabled", 1, true, false},
	{"kernel.sysrq", 0, false, false},
	{"kernel.randomize_va_space", 2, false, false},
	{"user.max_user_namespaces", 0, false, false},
	{"kernel.unprivileged_userns_clone", 0, false, true},
	{"kernel.apparmor_restrict_unprivileged_userns", 1, true, true},
	{"fs.protected_symlinks", 1, true, false},
	{"fs.protected_hardlinks", 1, true, false},
	{"fs.protected_fifos", 2, true, false},
	{"fs.protected_regular", 2, true, false},
	{"fs.suid_dumpable", 0, false, false},
	{"vm.mmap_min_addr", 65536, true, false},
	{"vm.unprivileged_userfaultfd", 0, false, true},
	{"net.ipv4.conf.all.rp_filter", 1, false, false}, // 2 is not stricter: it is the loose mode
	{"net.ipv4.conf.default.rp_filter", 1, false, false},
	{"net.ipv4.conf.all.accept_redirects", 0, false, false},
	{"net.ipv4.conf.default.accept_redirects", 0, false, false},
	{"net.ipv4.conf.all.send_redirects", 0, false, false},
	{"net.ipv4.conf.default.send_redirects", 0, false, false},
	{"net.ipv4.conf.all.accept_source_route", 0, false, false},
	{"net.ipv6.conf.all.accept_redirects", 0, false, true},
	{"net.ipv6.conf.default.accept_redirects", 0, false, true},
	{"net.ipv6.conf.all.accept_source_route", 0, false, true},
	{"net.ipv4.conf.all.log_martians", 1, true, false},
	{"net.ipv4.tcp_syncookies", 1, true, false},
	{"net.ipv4.icmp_echo_ignore_broadcasts", 1, true, false},
	{"net.ipv4.tcp_fastopen", 0, false, false}, // a bit mask (1 client, 2 server): any bit set is not stricter
}

// Satisfied reports whether a value meets the setting.
func (s Setting) Satisfied(got int64) bool {
	if s.AtLeast {
		return got >= s.Want
	}
	return got == s.Want
}

// ifaceRule is how a net.*.conf.all setting combines with each interface's own copy (Documentation/networking/ip-sysctl.rst).
type ifaceRule int

const (
	// ifaceEither: the setting is on for an interface if it is on in "all" or in the interface, so each must be off.
	ifaceEither ifaceRule = iota + 1
	// ifaceMax: the interface uses the larger of the two values.
	ifaceMax
)

// PerInterface are the settings whose per-interface copies count too. A network card that existed before the settings file
// was applied keeps its own value, and a distribution's own file may set every interface (systemd sets rp_filter to 2,
// the loose mode), so "all" alone does not say what the kernel does. The settings file sets them with a glob.
var PerInterface = map[string]ifaceRule{
	"net.ipv4.conf.all.rp_filter":        ifaceMax,
	"net.ipv4.conf.all.accept_redirects": ifaceEither,
	"net.ipv4.conf.all.send_redirects":   ifaceEither,
	"net.ipv6.conf.all.accept_redirects": ifaceEither,
}

// interfaceProblems reads each interface's copy of a per-interface setting whose "all" value is all.
func interfaceProblems(src Source, s Setting, rule ifaceRule, all int64) (problems []string, checked int) {
	base, leaf, _ := strings.Cut(s.Key, ".all.")
	paths, err := src.Glob("/proc/sys/" + strings.ReplaceAll(base, ".", "/") + "/*/" + leaf)
	if err != nil {
		return []string{fmt.Sprintf("the interfaces' %s cannot be listed: %v", leaf, err)}, 1
	}
	for _, p := range paths {
		iface := filepath.Base(filepath.Dir(p))
		if iface == "all" || iface == "default" {
			continue
		}
		key := base + "." + iface + "." + leaf
		checked++
		data, err := src.ReadFile(p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s cannot be read: %v", key, err))
			continue
		}
		got, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		switch {
		case err != nil:
			problems = append(problems, key+" is not a number")
		case rule == ifaceEither && !s.Satisfied(got):
			problems = append(problems, fmt.Sprintf("%s is %d, should be %d (the interface's own value counts as well as all)", key, got, s.Want))
		case rule == ifaceMax && !s.Satisfied(max(all, got)):
			problems = append(problems, fmt.Sprintf("%s is %d, so the interface uses %d, should be %d", key, got, max(all, got), s.Want))
		}
	}
	return problems, checked
}

// Sysctl checks the running kernel's settings against the baseline.
func Sysctl(src Source, baseline []Setting) audit.Check {
	return audit.Check{
		Name: "host-sysctl", Zone: "",
		What: "The kernel is set so that a service user cannot ptrace, read kernel addresses, use BPF or io_uring, make user namespaces or abuse links.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			var out audit.Outcome
			for _, s := range baseline {
				data, err := src.ReadFile("/proc/sys/" + strings.ReplaceAll(s.Key, ".", "/"))
				if err != nil {
					if s.Optional {
						continue // this kernel does not have the switch
					}
					out.Problems = append(out.Problems, fmt.Sprintf("%s cannot be read: %v", s.Key, err))
					out.Checked++
					continue
				}
				got, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
				out.Checked++
				switch {
				case err != nil:
					out.Problems = append(out.Problems, fmt.Sprintf("%s is not a number", s.Key))
				case !s.Satisfied(got):
					rel := "should be"
					if s.AtLeast {
						rel = "should be at least"
					}
					out.Problems = append(out.Problems, fmt.Sprintf("%s is %d, %s %d", s.Key, got, rel, s.Want))
				}
				if rule, ok := PerInterface[s.Key]; ok && err == nil {
					problems, n := interfaceProblems(src, s, rule, got)
					out.Problems, out.Checked = append(out.Problems, problems...), out.Checked+n
				}
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}

// MountRule is what a mount must look like.
type MountRule struct {
	Path string
	// Need are options that must be set.
	Need []string
}

// Mounts are the directories an attacker writes a program to and then runs it from.
var Mounts = []MountRule{
	{"/tmp", []string{"nosuid", "nodev", "noexec"}},
	{"/var/tmp", []string{"nosuid", "nodev", "noexec"}},
	{"/dev/shm", []string{"nosuid", "nodev", "noexec"}},
}

// ParseMounts reads /proc/self/mounts: mount point to its options.
func ParseMounts(data []byte) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		opts := map[string]bool{}
		for _, o := range strings.Split(f[3], ",") {
			opts[o] = true
		}
		out[f[1]] = opts // a later line for the same mount point is the one in force
	}
	return out
}

// Mount checks that the directories a program could be written to and run from do not allow running it.
func Mount(src Source, rules []MountRule) audit.Check {
	return audit.Check{
		Name: "host-mounts", Zone: "",
		What: "Directories that anyone can write to cannot be used to run a program from, and /proc hides other users' processes.",
		Run: func(ctx context.Context) audit.Outcome {
			if why := linux(); why != "" {
				return audit.Outcome{SkipReason: why}
			}
			data, err := src.ReadFile("/proc/self/mounts")
			if err != nil {
				return audit.Outcome{SkipReason: "cannot read the mount table: " + err.Error()}
			}
			mounts := ParseMounts(data)
			var out audit.Outcome
			for _, r := range rules {
				out.Checked++
				opts, ok := mounts[r.Path]
				if !ok {
					out.Problems = append(out.Problems, r.Path+" is not a mount of its own, so it cannot be mounted noexec")
					continue
				}
				for _, need := range r.Need {
					if !opts[need] {
						out.Problems = append(out.Problems, fmt.Sprintf("%s is mounted without %s", r.Path, need))
					}
				}
			}
			out.Checked++
			proc := mounts["/proc"]
			if !(proc["hidepid=2"] || proc["hidepid=invisible"] || proc["hidepid=4"]) {
				out.Problems = append(out.Problems, "/proc shows every user's processes (mount it with hidepid=invisible)")
			}
			sort.Strings(out.Problems)
			return out
		},
	}
}
