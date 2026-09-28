//go:build linux || windows || darwin

// Package tunmgr creates and configures the virtual interface used in IP mode.
// It wraps golang.zx2c4.com/wireguard/tun (Wintun on Windows, /dev/net/tun on
// Linux, utun on macOS) and assigns addresses, DNS and routes through the
// system tools, cleaning everything up on Close.
package tunmgr

import (
	"fmt"
	"net"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device is a configured TUN interface.
type Device struct {
	dev     wgtun.Device
	name    string
	mtu     int
	writeMu sync.Mutex // guards WritePacket against concurrent writers
	cleanup []func()
}

// Create brings the interface up with the given address. Routes is the list of
// CIDRs routed into the tunnel; when defaultRoute is set, 0.0.0.0/0 (and ::/0)
// is routed through the tunnel while preserveHost keeps a direct route to the
// decoy endpoint so the tunnel itself does not recurse.
func Create(name string, mtu int, addr string, dns []string, routes []string, defaultRoute bool, preserveHost string) (*Device, error) {
	if mtu <= 0 {
		mtu = 1400
	}
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunmgr: create %s: %w", name, err)
	}
	realName, err := dev.Name()
	if err != nil || strings.TrimSpace(realName) == "" {
		realName = name
	}
	d := &Device{dev: dev, name: realName, mtu: mtu}
	if err := d.configure(addr, dns, routes, defaultRoute, preserveHost); err != nil {
		dev.Close()
		return nil, err
	}
	return d, nil
}

// Name is the interface name the OS actually created.
func (d *Device) Name() string { return d.name }

// MTU is the interface MTU.
func (d *Device) MTU() int { return d.mtu }

// ReadPacket reads one IP packet into buf, returning its length.
func (d *Device) ReadPacket(buf []byte) (int, error) {
	sizes := make([]int, 1)
	n, err := d.dev.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

// WritePacket writes one IP packet to the interface. Safe for concurrent use.
func (d *Device) WritePacket(p []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.dev.Write([][]byte{p}, 0)
	return err
}

// Close removes routes, addresses and the interface itself.
func (d *Device) Close() error {
	for _, fn := range d.cleanup {
		fn()
	}
	return d.dev.Close()
}

// addrParts splits "10.7.0.2/24" into ("10.7.0.2", 24).
func addrParts(addr string) (string, int, error) {
	ip, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", 0, err
	}
	ones, _ := ipnet.Mask.Size()
	return ip.String(), ones, nil
}

// maskFor renders an IPv4 netmask for a prefix length.
func maskFor(prefix int) string {
	return net.IP(net.CIDRMask(prefix, 32)).String()
}

// tunnelGateway returns the first host inside the given CIDR, which by
// convention is the server's address on the virtual link (e.g. 10.7.0.1 for
// 10.7.0.0/24). Windows needs it to install routes.
func tunnelGateway(addr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", err
	}
	gw := make(net.IP, len(ipnet.IP))
	copy(gw, ipnet.IP)
	for i := len(gw) - 1; i >= 0; i-- {
		gw[i]++
		if gw[i] != 0 {
			break
		}
	}
	return gw.String(), nil
}
