package admin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mirage/internal/conf"
	"mirage/internal/keygen"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	must2(t, keygen.Generate(keygen.Options{
		Dir:        dir,
		Domain:     "mirage.test",
		ServerAddr: "203.0.113.10:443",
	}))
	path := filepath.Join(dir, "server.json")
	s, err := Load(path)
	must2(t, err)
	return s, dir
}

func must2(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestLoadMigratesLegacyLayout checks that a config written in the old
// single-inbound shape still loads.
func TestLoadMigratesLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	legacy := `{
		"listen": ":443",
		"tls_cert": "server.pem",
		"tls_key": "server-key.pem",
		"tunnel_cidr": "10.7.0.0/24",
		"ip_start": "10.7.0.2",
		"ip_end": "10.7.0.254",
		"psks": {"a": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"x25519_priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	}`
	path := filepath.Join(dir, "server.json")
	must2(t, os.WriteFile(path, []byte(legacy), 0o600))
	s, err := Load(path)
	must2(t, err)
	in := s.Inbounds()
	if len(in) != 1 || in[0].Listen != ":443" {
		t.Fatalf("migrated inbounds: %+v", in)
	}
}

func TestClients(t *testing.T) {
	s, _ := newStore(t)
	if len(s.ClientIDs()) != 1 {
		t.Fatalf("initial clients: %d", len(s.ClientIDs()))
	}
	must2(t, s.AddClient("alice"))
	if err := s.AddClient("alice"); err == nil {
		t.Fatal("duplicate client must be rejected")
	}
	if len(s.ClientIDs()) != 2 {
		t.Fatalf("after add: %d", len(s.ClientIDs()))
	}
	if !s.RemoveClient("alice") {
		t.Fatal("remove failed")
	}
	if s.RemoveClient("nope") {
		t.Fatal("removing an unknown client must fail")
	}
}

func TestInboundAndExport(t *testing.T) {
	s, dir := newStore(t)

	must2(t, s.AddInbound("second", "cdn.mirage.test", ":8443", "ws"))
	in := s.Inbounds()
	if len(in) != 2 || in[1].Domain != "cdn.mirage.test" {
		t.Fatalf("inbounds: %+v", in)
	}
	if _, err := os.Stat(filepath.Join(dir, "second.pem")); err != nil {
		t.Fatalf("cert not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "second-key.pem")); err != nil {
		t.Fatalf("key not written: %v", err)
	}

	must2(t, s.AddClient("alice"))
	out, err := s.ExportClient("alice", "second")
	must2(t, err)

	data, err := os.ReadFile(out)
	must2(t, err)
	c := &conf.ClientConfig{}
	must2(t, json.Unmarshal(data, c))
	if c.ServerAddr != "203.0.113.10:8443" {
		t.Fatalf("server_addr: got %q", c.ServerAddr)
	}
	if c.ServerDomain != "cdn.mirage.test" {
		t.Fatalf("server_domain: got %q", c.ServerDomain)
	}
	if c.Transport != "ws" {
		t.Fatalf("transport: got %q", c.Transport)
	}
	if c.PSKID != "alice" || c.PSK == "" || c.ServerCertSHA256 == "" {
		t.Fatalf("client config incomplete: %+v", c)
	}
	must2(t, c.Validate())

	if _, err := s.ExportClient("alice", "nope"); err == nil {
		t.Fatal("export via unknown inbound must fail")
	}
}

func TestSavePersists(t *testing.T) {
	s, _ := newStore(t)
	must2(t, s.AddClient("bob"))
	must2(t, s.Save())

	again, err := Load(s.Path())
	must2(t, err)
	if _, ok := again.PSK("bob"); !ok {
		t.Fatal("saved client not found after reload")
	}
}
