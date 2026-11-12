// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	userHZ        = 100 // /proc/stat ticks; fixed by the kernel ABI
	sectorBytes   = 512 // /proc/diskstats sectors are always 512 bytes
	maxMounts     = 64
	maxDisks      = 64
	maxInterfaces = 64
)

var cpuModes = [...]string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

// realFS lists file systems that hold data; pseudo file systems are skipped.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "jfs": true, "reiserfs": true, "fuseblk": true,
}

type statfsFunc func(path string) (size, free, avail uint64, err error)

func osStatfs(path string) (size, free, avail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return st.Blocks * bs, st.Bfree * bs, st.Bavail * bs, nil
}

// hostCollector reads /proc and statfs below root.
type hostCollector struct {
	root   string
	statfs statfsFunc

	prevBusy, prevTotal float64
	havePrev            bool
}

func newHostCollector(root string, sf statfsFunc) *hostCollector {
	if sf == nil {
		sf = osStatfs
	}
	return &hostCollector{root: root, statfs: sf}
}

// collect gathers what it can; the error lists every part that failed.
func (h *hostCollector) collect() ([]reading, error) {
	var out []reading
	var errs []error
	for _, part := range []struct {
		name string
		fn   func() ([]reading, error)
	}{
		{"stat", h.cpu},
		{"loadavg", h.load},
		{"meminfo", h.mem},
		{"mounts", h.filesystems},
		{"diskstats", h.disks},
		{"net/dev", h.net},
	} {
		r, err := part.fn()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", part.name, err))
		}
		out = append(out, r...)
	}
	return out, errors.Join(errs...)
}

func (h *hostCollector) proc(name string) ([]byte, error) {
	return readFile(filepath.Join(h.root, "proc", name))
}

func (h *hostCollector) cpu() ([]reading, error) {
	b, err := h.proc("stat")
	if err != nil {
		return nil, err
	}
	rs, busy, total, err := parseStat(b)
	if err != nil {
		return nil, err
	}
	if h.havePrev && total > h.prevTotal && busy >= h.prevBusy {
		rs = append(rs, reading{
			target: agentv1.TargetKind_TARGET_KIND_HOST, metric: "nux_host_cpu_usage_ratio",
			labels: lbl("cpu", "all"), value: (busy - h.prevBusy) / (total - h.prevTotal),
		})
	}
	h.prevBusy, h.prevTotal, h.havePrev = busy, total, true
	return rs, nil
}

// parseStat returns the per-mode counters and the aggregate busy and total seconds.
func parseStat(b []byte) (rs []reading, busy, total float64, err error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	seen := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		cpu := "all"
		if f[0] != "cpu" {
			cpu = strings.TrimPrefix(f[0], "cpu")
			if _, err := strconv.Atoi(cpu); err != nil {
				continue
			}
		}
		var sum, idle float64
		for i, mode := range cpuModes {
			v, perr := parseU(f[i+1])
			if perr != nil {
				return nil, 0, 0, fmt.Errorf("cpu %s %s: %w", cpu, mode, perr)
			}
			sum += v
			if mode == "idle" || mode == "iowait" {
				idle += v
			}
			rs = append(rs, reading{
				target: agentv1.TargetKind_TARGET_KIND_HOST, metric: "nux_host_cpu_seconds_total",
				labels: lbl("cpu", cpu, "mode", mode), value: v / userHZ, counter: true,
			})
		}
		if cpu == "all" {
			busy, total = (sum-idle)/userHZ, sum/userHZ
		}
		seen = true
	}
	if !seen {
		return nil, 0, 0, errors.New("no cpu lines")
	}
	return rs, busy, total, nil
}

func (h *hostCollector) load() ([]reading, error) {
	b, err := h.proc("loadavg")
	if err != nil {
		return nil, err
	}
	return parseLoad(b)
}

func parseLoad(b []byte) ([]reading, error) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return nil, errors.New("short loadavg")
	}
	var rs []reading
	for i, w := range []string{"1m", "5m", "15m"} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return nil, err
		}
		rs = append(rs, reading{target: agentv1.TargetKind_TARGET_KIND_HOST, metric: "nux_host_load_average", labels: lbl("window", w), value: v})
	}
	return rs, nil
}

func (h *hostCollector) mem() ([]reading, error) {
	b, err := h.proc("meminfo")
	if err != nil {
		return nil, err
	}
	return parseMeminfo(b)
}

func parseMeminfo(b []byte) ([]reading, error) {
	kb := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := parseU(f[0])
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		kb[name] = v
	}
	total, ok := kb["MemTotal"]
	if !ok {
		return nil, errors.New("MemTotal missing")
	}
	avail, ok := kb["MemAvailable"]
	if !ok { // kernels before 3.14
		avail = kb["MemFree"] + kb["Buffers"] + kb["Cached"]
	}
	g := func(m, typ string, v float64) reading {
		return reading{target: agentv1.TargetKind_TARGET_KIND_HOST, metric: m, labels: lbl("type", typ), value: v}
	}
	rs := []reading{
		g("nux_host_memory_bytes", "total", total), g("nux_host_memory_bytes", "available", avail),
		g("nux_host_memory_bytes", "free", kb["MemFree"]), g("nux_host_memory_bytes", "buffers", kb["Buffers"]),
		g("nux_host_memory_bytes", "cached", kb["Cached"]), g("nux_host_memory_bytes", "used", max(total-avail, 0)),
	}
	if st, ok := kb["SwapTotal"]; ok {
		sf := kb["SwapFree"]
		rs = append(rs, g("nux_host_swap_bytes", "total", st), g("nux_host_swap_bytes", "free", sf), g("nux_host_swap_bytes", "used", max(st-sf, 0)))
	}
	return rs, nil
}

type mount struct{ device, point, fstype string }

func parseMounts(b []byte) []mount {
	var out []mount
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		out = append(out, mount{device: unescapeMount(f[0]), point: unescapeMount(f[1]), fstype: f[2]})
		if len(out) == maxMounts {
			break
		}
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for a space) /proc/mounts uses.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func (h *hostCollector) filesystems() ([]reading, error) {
	b, err := h.proc("mounts")
	if err != nil {
		return nil, err
	}
	var rs []reading
	var errs []error
	for _, m := range parseMounts(b) {
		size, free, avail, err := h.statfs(filepath.Join(h.root, m.point))
		if err != nil {
			errs = append(errs, fmt.Errorf("statfs %s: %w", m.point, err))
			continue
		}
		for typ, v := range map[string]uint64{"size": size, "used": size - min(free, size), "avail": avail} {
			rs = append(rs, reading{
				target: agentv1.TargetKind_TARGET_KIND_HOST, metric: "nux_host_filesystem_bytes",
				labels: lbl("mount", m.point, "device", m.device, "fstype", m.fstype, "type", typ), value: float64(v),
			})
		}
	}
	return rs, errors.Join(errs...)
}

func (h *hostCollector) disks() ([]reading, error) {
	b, err := h.proc("diskstats")
	if err != nil {
		return nil, err
	}
	return parseDiskstats(b), nil
}

func parseDiskstats(b []byte) []reading {
	var rs []reading
	devices := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 14 {
			continue
		}
		dev := f[2]
		if strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "ram") {
			continue
		}
		v := make([]float64, 14)
		ok := true
		for _, i := range []int{3, 5, 7, 9, 12} {
			x, err := parseU(f[i])
			if err != nil {
				ok = false
				break
			}
			v[i] = x
		}
		if !ok || v[3]+v[7] == 0 { // never used: no signal
			continue
		}
		if devices++; devices > maxDisks {
			break
		}
		add := func(metric string, val float64, kv ...string) {
			rs = append(rs, reading{target: agentv1.TargetKind_TARGET_KIND_HOST, metric: metric, labels: lbl(kv...), value: val, counter: true})
		}
		add("nux_host_disk_io_bytes_total", v[5]*sectorBytes, "device", dev, "direction", "read")
		add("nux_host_disk_io_bytes_total", v[9]*sectorBytes, "device", dev, "direction", "write")
		add("nux_host_disk_io_ops_total", v[3], "device", dev, "direction", "read")
		add("nux_host_disk_io_ops_total", v[7], "device", dev, "direction", "write")
		add("nux_host_disk_io_seconds_total", v[12]/1000, "device", dev)
	}
	return rs
}

func (h *hostCollector) net() ([]reading, error) {
	b, err := h.proc("net/dev")
	if err != nil {
		return nil, err
	}
	nets := parseNetDev(b, maxInterfaces)
	return netReadings(nets, agentv1.TargetKind_TARGET_KIND_HOST, "", "nux_host_network", "interface"), nil
}

type netCounters struct {
	name                                  string
	rxBytes, rxPackets, rxErrors, rxDrops float64
	txBytes, txPackets, txErrors, txDrops float64
}

// parseNetDev skips lo and caps the interface count.
func parseNetDev(b []byte, limit int) []netCounters {
	var out []netCounters
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		name = strings.TrimSpace(name)
		if !ok || name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		var v [12]float64
		bad := false
		for i := range v {
			x, err := parseU(f[i])
			if err != nil {
				bad = true
				break
			}
			v[i] = x
		}
		if bad {
			continue
		}
		out = append(out, netCounters{name, v[0], v[1], v[2], v[3], v[8], v[9], v[10], v[11]})
		if len(out) == limit {
			break
		}
	}
	return out
}

// netReadings emits one set per interface; with iface == "" the label is omitted (containers sum interfaces).
func netReadings(nets []netCounters, kind agentv1.TargetKind, id, prefix, ifaceLabel string) []reading {
	var rs []reading
	for _, n := range nets {
		for _, m := range []struct {
			metric string
			rx, tx float64
		}{
			{prefix + "_bytes_total", n.rxBytes, n.txBytes},
			{prefix + "_packets_total", n.rxPackets, n.txPackets},
			{prefix + "_errors_total", n.rxErrors, n.txErrors},
			{prefix + "_drops_total", n.rxDrops, n.txDrops},
		} {
			if kind == agentv1.TargetKind_TARGET_KIND_CONTAINER && strings.HasSuffix(m.metric, "drops_total") {
				continue
			}
			for dir, v := range map[string]float64{"rx": m.rx, "tx": m.tx} {
				l := lbl("direction", dir)
				if ifaceLabel != "" && n.name != "" {
					l[ifaceLabel] = n.name
				}
				rs = append(rs, reading{target: kind, id: id, metric: m.metric, labels: l, value: v, counter: true})
			}
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].metric < rs[j].metric })
	return rs
}
