// Command mirage-admin manages a Mirage server: the terminal UI creates
// clients (PSK entries) and inbound listeners and exports ready client configs.
// The "export" subcommand does the same without a terminal, for scripts.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"mirage/internal/admin"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  mirage-admin -c server.json                       # terminal UI
  mirage-admin -c server.json export <client> [inbound]
                                                     # print a client config
  mirage-admin -c server.json export <client> [inbound] -b64
                                                     # ... as one base64 line`)
}

func main() {
	fs := flag.NewFlagSet("mirage-admin", flag.ExitOnError)
	config := fs.String("c", "server.json", "server config (created on first run)")
	asBase64 := fs.Bool("b64", false, "print the exported config as one base64 line")
	fs.Usage = usage
	fs.Parse(os.Args[1:])

	args := fs.Args()
	if len(args) == 0 {
		if err := admin.Run(*config); err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
		return
	}

	switch args[0] {
	case "export":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		inbound := ""
		if len(args) >= 3 {
			inbound = args[2]
		}
		store, err := admin.Load(*config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
		out, err := store.ExportClient(args[1], inbound)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
		if *asBase64 {
			fmt.Println(base64.StdEncoding.EncodeToString(data))
			return
		}
		fmt.Print(string(data))
	default:
		usage()
		os.Exit(2)
	}
}
