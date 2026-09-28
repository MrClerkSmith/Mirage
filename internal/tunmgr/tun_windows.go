//go:build windows

package tunmgr

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
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

	if defaultRoute {
		if preserveHost == "" {
			return fmt.Errorf("tunmgr: default_route needs the server host to preserve a direct route")
		}
		if err := run("netsh", "interface", "ip", "set", "address",
			"name="+d.name, "source=static", "addr="+ip, "mask="+maskFor(prefix),
			"gateway="+gw, "gwmetric=1"); err != nil {
			return fmt.Errorf("tunmgr: set address: %w", err)
		}
		// Make sure the tunnel interface wins over the LAN default route.
		_ = run("netsh", "interface", "ipv4", "set", "interface", "name="+d.name, "metric=1")

		curGW, err := defaultGatewayWindows()
		if err != nil {
			return fmt.Errorf("tunmgr: %w", err)
		}
		if err := run("route", "add", preserveHost, "mask", "255.255.255.255", curGW, "metric", "1"); err != nil {
			return fmt.Errorf("tunmgr: preserve route: %w", err)
		}
		host := preserveHost
		d.cleanup = append(d.cleanup, func() {
			run("route", "delete", host, "mask", "255.255.255.255", curGW)
		})
	} else {
		if err := run("netsh", "interface", "ip", "set", "address",
			"name="+d.name, "source=static", "addr="+ip, "mask="+maskFor(prefix),
			"gateway=none"); err != nil {
			return fmt.Errorf("tunmgr: set address: %w", err)
		}
	}

	for i, ns := range dns {
		if i == 0 {
			_ = run("netsh", "interface", "ip", "set", "dns", "name="+d.name, "static", ns, "validate=no")
		} else {
			_ = run("netsh", "interface", "ip", "add", "dns", "name="+d.name, ns, fmt.Sprintf("index=%d", i+1), "validate=no")
		}
	}

	for _, cidr := range routes {
		net, prefix, err := addrParts(cidr)
		if err != nil {
			return fmt.Errorf("tunmgr: bad route %s: %w", cidr, err)
		}
		if err := run("route", "add", net, "mask", maskFor(prefix), gw, "metric", "1"); err != nil {
			return fmt.Errorf("tunmgr: route %s: %w", cidr, err)
		}
		c := net
		p := prefix
		d.cleanup = append(d.cleanup, func() {
			run("route", "delete", c, "mask", maskFor(p), gw)
		})
	}
	return nil
}

// defaultGatewayWindows parses `route print` and returns the IPv4 default
// gateway with the lowest metric.
func defaultGatewayWindows() (string, error) {
	out, err := exec.Command("route", "print", "-4").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cannot read routing table: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	started := false
	best := -1
	bestGW := ""
	for _, ln := range lines {
		if strings.Contains(ln, "Network Destination") {
			started = true
			continue
		}
		if !started {
			continue
		}
		fs := strings.Fields(ln)
		if len(fs) < 5 || fs[0] != "0.0.0.0" || fs[1] != "0.0.0.0" {
			continue
		}
		m, err := strconv.Atoi(fs[4])
		if err != nil {
			continue
		}
		if best == -1 || m < best {
			best = m
			bestGW = fs[2]
		}
	}
	if bestGW == "" {
		return "", fmt.Errorf("no IPv4 default gateway found")
	}
	return bestGW, nil
}
