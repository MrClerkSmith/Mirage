// Package dns is a tiny UDP DNS relay. On the server it answers queries that
// arrive from the tunnel on the TUN address, so clients can resolve names
// through the VPN without leaking to the local resolver.
package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	queryTimeout = 5 * time.Second
	maxDNSPacket = 4096
)

// Serve relays UDP DNS traffic arriving at listenAddr to upstream until the
// context is cancelled.
func Serve(ctx context.Context, listenAddr, upstream string) error {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("dns: listen %s: %w", listenAddr, err)
	}
	defer pc.Close()

	log.Printf("dns: relaying %s -> %s", listenAddr, upstream)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, maxDNSPacket)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n < 2 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go relay(pc, addr, query, upstream)
	}
}

func relay(pc net.PacketConn, client net.Addr, query []byte, upstream string) {
	up, err := net.Dial("udp", upstream)
	if err != nil {
		return
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(queryTimeout))
	if _, err := up.Write(query); err != nil {
		return
	}
	resp := make([]byte, maxDNSPacket)
	n, err := up.Read(resp)
	if err != nil {
		return
	}
	pc.WriteTo(resp[:n], client)
}
