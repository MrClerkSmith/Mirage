// Command mirage-admin is the terminal UI that manages a Mirage server: it
// creates clients (PSK entries), adds inbound listeners and exports ready
// client configs.
package main

import (
	"flag"
	"fmt"
	"os"

	"mirage/internal/admin"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mirage-admin -c server.json")
}

func main() {
	fs := flag.NewFlagSet("mirage-admin", flag.ExitOnError)
	config := fs.String("c", "server.json", "server config (created on first run)")
	fs.Usage = usage
	fs.Parse(os.Args[1:])

	if err := admin.Run(*config); err != nil {
		fmt.Fprintln(os.Stderr, "admin:", err)
		os.Exit(1)
	}
}
