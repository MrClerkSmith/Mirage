//go:build darwin

package tunmgr

import (
	"fmt"
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
	gw, err := tunnelGateway(addr)
	if err != nil {
		return err
	}
	if err := run("ifconfig", d.name, "mtu", fmt.Sprint(d.mtu)); err != nil {
		return fmt.Errorf("tunmgr: mtu: %w", err)
	}
	// macOS utun is point to point: <local> <peer>
	if err := run("ifconfig", d.name, "inet", ip, gw, "up"); err != nil {
		return fmt.Errorf("tunmgr: address: %w", err)
	}
	d.cleanup = append(d.cleanup, func() {
		run("ifconfig", d.name, "inet", ip, gw, "down")
	})

	for _, cidr := range routes {
		if err := run("route", "-q", "add", "-net", cidr, "-interface", d.name); err != nil {
			return fmt.Errorf("tunmgr: route %s: %w", cidr, err)
		}
		c := cidr
		d.cleanup = append(d.cleanup, func() { run("route", "-q", "delete", "-net", c, "-interface", d.name) })
	}

	if defaultRoute {
		if preserveHost == "" {
			return fmt.Errorf("tunmgr: default_route needs the server host to preserve a direct route")
		}
		if err := run("route", "-q", "change", "default", "-interface", d.name); err != nil {
			return fmt.Errorf("tunmgr: default route: %w", err)
		}
		d.cleanup = append(d.cleanup, func() {
			run("route", "-q", "change", "default", "-interface", "en0")
		})
	}
	return nil
}
