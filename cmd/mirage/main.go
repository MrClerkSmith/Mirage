// Command mirage runs the three roles of the protocol: keygen, client, server
// and decoy.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"mirage/internal/client"
	"mirage/internal/conf"
	"mirage/internal/keygen"
	"mirage/internal/relay"
	"mirage/internal/server"
)

func usage() {
	fmt.Fprintf(os.Stderr, `mirage - DPI-resistant VPN with a decoy front

usage:
  mirage keygen  -domain decoy.example.com [-dir keys] [-decoy-addr host:443]
                  [-server-addr 10.0.0.2:8443]
  mirage client  -c client.json
  mirage server  -c server.json
  mirage decoy   -c decoy.json
`)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "keygen":
		cmdKeygen(ctx)
	case "client":
		cmdClient(ctx)
	case "server":
		cmdServer(ctx)
	case "decoy":
		cmdDecoy(ctx)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdKeygen(ctx context.Context) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", "keys", "output directory")
	domain := fs.String("domain", "", "decoy domain (the tunnel SNI)")
	decoyAddr := fs.String("decoy-addr", "", "client-facing endpoint, host:443")
	serverAddr := fs.String("server-addr", "", "the hidden server the decoy relays to")
	serverListen := fs.String("server-listen", "", "where the hidden server listens")
	tunnelCIDR := fs.String("tunnel-cidr", "10.7.0.0/24", "virtual subnet for clients")
	dnsUpstream := fs.String("dns-upstream", "1.1.1.1:53", "resolver the server forwards DNS to")
	fs.Parse(os.Args[2:])
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "keygen: -domain is required")
		os.Exit(2)
	}
	must(keygen.Generate(keygen.Options{
		Dir:          *dir,
		Domain:       *domain,
		DecoyAddr:    *decoyAddr,
		ServerAddr:   *serverAddr,
		ServerListen: *serverListen,
		TunnelCIDR:   *tunnelCIDR,
		DNSUpstream:  *dnsUpstream,
	}))
}

func cmdClient(ctx context.Context) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	config := fs.String("c", "client.json", "client config")
	fs.Parse(os.Args[2:])

	cfg := &conf.ClientConfig{}
	must(conf.Load(*config, cfg))
	mustSignal(client.New(cfg).Run(ctx))
}

func cmdServer(ctx context.Context) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	config := fs.String("c", "server.json", "server config")
	fs.Parse(os.Args[2:])

	cfg := &conf.ServerConfig{}
	must(conf.Load(*config, cfg))
	srv, err := server.New(cfg)
	must(err)
	mustSignal(srv.ListenAndServe(ctx))
}

func cmdDecoy(ctx context.Context) {
	fs := flag.NewFlagSet("decoy", flag.ExitOnError)
	config := fs.String("c", "decoy.json", "decoy config")
	fs.Parse(os.Args[2:])

	cfg := &conf.DecoyConfig{}
	must(conf.Load(*config, cfg))
	r, err := relay.New(cfg)
	must(err)
	mustSignal(r.ListenAndServe())
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func mustSignal(err error) {
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
