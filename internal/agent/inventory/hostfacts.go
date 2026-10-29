// SPDX-License-Identifier: Apache-2.0

// Package inventory collects what the agent reports about its host and its
// containers (INV-1). It only reads: host files and the nux-sockguard socket.
package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// ifaceAddr is one address of one network interface.
type ifaceAddr struct {
	Name string
	IP   net.IP
}

// realFilesystems are the types worth reporting as disks; pseudo and network filesystems are not.
var realFilesystems = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
}

// skippedInterfaces are container-networking interfaces whose addresses say nothing about the host.
var skippedInterfaces = []string{"docker", "br-", "veth", "cni", "flannel", "cali", "podman", "virbr"}

type disk struct {
	Mount      string `json:"mount"`
	FSType     string `json:"fstype"`
	TotalBytes uint64 `json:"total_bytes"`
}

// hostSources are the host's inputs; tests replace them.
type hostSources struct {
	root       string
	hostname   func() (string, error)
	interfaces func() ([]ifaceAddr, error)
	statfs     func(path string) (uint64, error)
}

func defaultSources(root string) hostSources {
	return hostSources{root: root, hostname: os.Hostname, interfaces: systemInterfaces, statfs: statfsTotal}
}

func systemInterfaces() ([]ifaceAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ifaceAddr
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, ifaceAddr{Name: i.Name, IP: n.IP})
			}
		}
	}
	return out, nil
}

func statfsTotal(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Blocks * uint64(st.Bsize), nil //nolint:gosec // block size is positive
}

// collectHost gathers the host facts. A source that cannot be read leaves its field
// empty and is reported in the returned error; the facts that could be read are still returned.
func (s hostSources) collectHost() (*agentv1.HostFacts, error) {
	var problems []error
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(s.root, rel)) //nolint:gosec // fixed host paths under a configurable root
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", rel, errors.Unwrap(err)))
			return ""
		}
		return string(b)
	}

	h := &agentv1.HostFacts{Os: runtime.GOOS, Arch: runtime.GOARCH, Facts: map[string]string{}}
	var err error
	if h.Hostname, err = s.hostname(); err != nil {
		problems = append(problems, fmt.Errorf("hostname: %w", err))
	}
	h.Distro = distroName(read("etc/os-release"))
	h.Kernel = strings.TrimSpace(read("proc/sys/kernel/osrelease"))
	h.MemoryBytes = memTotal(read("proc/meminfo"))
	cpus, model := cpuInfo(read("proc/cpuinfo"))
	h.CpuCount = cpus
	if model != "" {
		h.Facts["cpu_model"] = model
	}
	if boot := bootTime(read("proc/stat")); boot > 0 {
		h.Facts["boot_time_unix"] = strconv.FormatInt(boot, 10) // fixed per boot, unlike uptime, so it does not look like a change every poll
	}
	if ips, err := s.interfaces(); err != nil {
		problems = append(problems, fmt.Errorf("interfaces: %w", err))
	} else if list := hostIPs(ips); list != "" {
		h.Facts["ips"] = list
	}
	if disks := s.disks(read("proc/self/mountinfo")); len(disks) > 0 {
		b, _ := json.Marshal(disks)
		h.Facts["disks"] = string(b)
	}
	return h, errors.Join(problems...)
}

func distroName(osRelease string) string {
	vals := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(osRelease))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			vals[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	if vals["PRETTY_NAME"] != "" {
		return vals["PRETTY_NAME"]
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION_ID"])
}

func memTotal(meminfo string) uint64 {
	for _, line := range strings.Split(meminfo, "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				kb, _ := strconv.ParseUint(f[0], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func cpuInfo(cpuinfo string) (count uint32, model string) {
	for _, line := range strings.Split(cpuinfo, "\n") {
		switch {
		case strings.HasPrefix(line, "processor"):
			count++
		case model == "" && strings.HasPrefix(line, "model name"):
			_, v, _ := strings.Cut(line, ":")
			model = strings.TrimSpace(v)
		}
	}
	if count == 0 && cpuinfo == "" {
		count = uint32(runtime.NumCPU()) //nolint:gosec // a small positive count
	}
	return count, model
}

func bootTime(stat string) int64 {
	for _, line := range strings.Split(stat, "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			return n
		}
	}
	return 0
}

// hostIPs lists global addresses, sorted, skipping loopback, link-local and container networking.
func hostIPs(addrs []ifaceAddr) string {
	seen := map[string]bool{}
	for _, a := range addrs {
		if a.IP == nil || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() || a.IP.IsLinkLocalMulticast() || a.IP.IsMulticast() || a.IP.IsUnspecified() {
			continue
		}
		skip := false
		for _, p := range skippedInterfaces {
			if strings.HasPrefix(a.Name, p) {
				skip = true
			}
		}
		if !skip {
			seen[a.IP.String()] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// disks reads the mount table and reports each real filesystem once (btrfs subvolumes share a device).
func (s hostSources) disks(mountinfo string) []disk {
	var out []disk
	seenDev := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(mountinfo))
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		fields, rest := strings.Fields(pre), strings.Fields(post)
		if len(fields) < 5 || len(rest) < 2 || !realFilesystems[rest[0]] {
			continue
		}
		dev := fields[2] + "/" + rest[1] // major:minor plus source
		if seenDev[dev] {
			continue
		}
		mount := unescapeMount(fields[4])
		total, err := s.statfs(mount)
		if err != nil {
			continue // not reachable from the agent's sandbox
		}
		seenDev[dev] = true
		out = append(out, disk{Mount: mount, FSType: rest[0], TotalBytes: total})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

// unescapeMount decodes the octal escapes the kernel uses in mountinfo (\040 for a space).
func unescapeMount(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
