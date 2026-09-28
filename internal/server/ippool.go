package server

import (
	"bytes"
	"fmt"
	"net"
	"sync"
)

// ipPool hands out virtual addresses to clients inside the tunnel subnet.
type ipPool struct {
	mu    sync.Mutex
	start net.IP
	end   net.IP
	used  map[string]bool
}

func newPool(start, end string) (*ipPool, error) {
	s, e := net.ParseIP(start), net.ParseIP(end)
	if s == nil || e == nil {
		return nil, fmt.Errorf("server: bad pool range %s-%s", start, end)
	}
	if bytes.Compare(s, e) > 0 {
		return nil, fmt.Errorf("server: pool start %s is after end %s", start, end)
	}
	return &ipPool{start: s, end: e, used: make(map[string]bool)}, nil
}

// Acquire returns a free address or an error when the pool is exhausted.
func (p *ipPool) Acquire() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip := append(net.IP(nil), p.start...); bytes.Compare(ip, p.end) <= 0; inc(ip) {
		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip, nil
		}
	}
	return nil, fmt.Errorf("server: no free addresses")
}

// Release returns an address to the pool.
func (p *ipPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
