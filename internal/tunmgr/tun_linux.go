//go:build linux

package tunmgr

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *Device) configure(addr string, dns []string, routes []string, defaultRoute bool, preserveHost string) error {
	ip, prefix, err := addrParts(addr)
	if err != nil {
		return err
	}
	steps := [][]string{
		{"ip", "link", "set", "dev", d.name, "mtu", fmt.Sprint(d.mtu)},
		{"ip", "addr", "add", fmt.Sprintf("%s/%d", ip, prefix), "dev", d.name},
		{"ip", "link", "set", "dev", d.name, "up"},
	}
	for _, s := range steps {
		if err := run(s...); err != nil {
			return fmt.Errorf("tunmgr: %w", err)
		}
	}
	d.cleanup = append(d.cleanup, func() {
		run("ip", "link", "set", "dev", d.name, "down")
		run("ip", "addr", "del", fmt.Sprintf("%s/%d", ip, prefix), "dev", d.name)
	})

	for _, cidr := range routes {
		if err := run("ip", "route", "add", cidr, "dev", d.name); err != nil {
			return fmt.Errorf("tunmgr: route %s: %w", cidr, err)
		}
		c := cidr
		d.cleanup = append(d.cleanup, func() { run("ip", "route", "del", c, "dev", d.name) })
	}

	if defaultRoute {
		if preserveHost == "" {
			return fmt.Errorf("tunmgr: default_route needs the server host to preserve a direct route")
		}
		gw, dev, err := defaultGateway()
		if err != nil {
			return fmt.Errorf("tunmgr: %w", err)
		}
		if err := run("ip", "route", "add", preserveHost, "via", gw, "dev", dev); err != nil {
			return fmt.Errorf("tunmgr: preserve route: %w", err)
		}
		if err := run("ip", "route", "replace", "default", "dev", d.name, "metric", "50"); err != nil {
			return fmt.Errorf("tunmgr: default route: %w", err)
		}
		d.cleanup = append(d.cleanup, func() {
			run("ip", "route", "del", "default", "dev", d.name, "metric", "50")
			run("ip", "route", "del", preserveHost, "via", gw, "dev", dev)
		})
	}

	if len(dns) > 0 {
		// Best effort: prepend a resolv.conf entry. Real deployments should use
		// systemd-resolved or a local resolver.
		if err := prependResolvConf(dns); err == nil {
			d.cleanup = append(d.cleanup, restoreResolvConf)
		}
	}
	return nil
}

// defaultGateway parses `ip route show default` -> ("192.168.1.1", "eth0").
func defaultGateway() (string, string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("cannot read default route: %w", err)
	}
	fs := strings.Fields(strings.TrimSpace(string(out)))
	// "default via 192.168.1.1 dev eth0"
	for i, f := range fs {
		if f == "via" && i+1 < len(fs) {
			gw := fs[i+1]
			dev := ""
			if i+3 < len(fs) && fs[i+2] == "dev" {
				dev = fs[i+3]
			}
			return gw, dev, nil
		}
	}
	return "", "", fmt.Errorf("no default route found")
}

const resolvBackup = "/tmp/mirage-resolv.conf.bak"

func prependResolvConf(dns []string) error {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	if err := exec.Command("cp", "/etc/resolv.conf", resolvBackup).Run(); err != nil {
		return err
	}
	var b strings.Builder
	for _, ns := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	b.Write(data)
	return os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644)
}

func restoreResolvConf() {
	_ = exec.Command("cp", resolvBackup, "/etc/resolv.conf").Run()
}
